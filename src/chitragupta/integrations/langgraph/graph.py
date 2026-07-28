"""LangGraph integration: pause a graph run for human authorization, then
resume through the core engine's commit/verify.

Framework-specific code lives entirely in this module -- ``ChitraguptaEngine``
has no import-time or runtime dependency on LangGraph. The signing key is
captured in a closure, never placed in graph state, so nothing an agent
node produces (and nothing that gets checkpointed) can ever contain it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict

try:
    from langgraph.checkpoint.base import BaseCheckpointSaver
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, START, StateGraph
    from langgraph.graph.state import CompiledStateGraph
    from langgraph.types import interrupt
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "the 'langgraph' and 'langchain-core' packages are required for "
        "chitragupta.integrations.langgraph; install with "
        "`pip install chitragupta-protocol[langgraph]`"
    ) from exc

from chitragupta.adapters.base import EffectAdapter
from chitragupta.crypto.keys import SigningKey
from chitragupta.domain.common import Principal
from chitragupta.engine.core import ChitraguptaEngine
from chitragupta.errors import ChitraguptaError
from chitragupta.grants.model import ScopeConstraints


class ChitraguptaGraphState(TypedDict, total=False):
    request: Any
    context: Any
    manifest_dict: dict[str, Any]
    manifest_hash: str
    grant_dict: dict[str, Any] | None
    commit_result: dict[str, Any] | None
    outcome_proof: dict[str, Any] | None
    status: str
    denial_reason: str | None


def build_chitragupta_graph(
    *,
    engine: ChitraguptaEngine,
    adapter: EffectAdapter,
    signing_key: SigningKey,
    checkpointer: BaseCheckpointSaver[Any] | None = None,
) -> CompiledStateGraph[Any, Any, Any]:
    """Build a compiled LangGraph app implementing prepare -> seal -> pause
    for authorization -> commit -> verify.

    Resume a paused run with ``Command(resume={"approved": True, "issuer":
    {...}, "subject": {...}})`` (or ``{"approved": False, "reason": "..."}``
    to deny). ``issuer``/``subject`` are plain dicts matching
    :class:`~chitragupta.domain.common.Principal` fields; the issuer must be
    human or service (invariant #30 is enforced by the engine regardless of
    what the graph does).
    """
    sealed_registry: dict[str, Any] = {}
    manifest_registry: dict[str, Any] = {}
    grant_registry: dict[str, Any] = {}

    def prepare_node(state: ChitraguptaGraphState) -> dict[str, Any]:
        manifest = engine.prepare(adapter, state["request"], state.get("context"))
        manifest_registry[manifest.manifest_id] = manifest
        return {"manifest_dict": manifest.model_dump(mode="json"), "status": "prepared"}

    def seal_node(state: ChitraguptaGraphState) -> dict[str, Any]:
        manifest = manifest_registry[state["manifest_dict"]["manifest_id"]]
        sealed = engine.seal(manifest, signing_key)
        sealed_registry[manifest.manifest_id] = sealed
        return {"manifest_hash": sealed.seal.manifest_hash, "status": "sealed"}

    def authorize_node(state: ChitraguptaGraphState) -> dict[str, Any]:
        manifest_id = state["manifest_dict"]["manifest_id"]
        sealed = sealed_registry[manifest_id]

        decision = interrupt(
            {
                "action": "authorize_effect",
                "manifest": state["manifest_dict"],
                "manifest_hash": state["manifest_hash"],
            }
        )

        if not decision.get("approved"):
            return {
                "status": "denied",
                "denial_reason": decision.get("reason", "denied by authorizer"),
            }

        now = datetime.now(timezone.utc)
        not_before = decision.get("not_before", now)
        expires_at = decision.get("expires_at", now + timedelta(minutes=5))
        try:
            grant = engine.authorize(
                sealed,
                issuer=Principal(**decision["issuer"]),
                subject=Principal(**decision["subject"]),
                audience=(adapter.adapter_id,),
                allowed_effect_types=(sealed.manifest.effect_type,),
                scope=decision.get("scope") or ScopeConstraints(),
                not_before=not_before,
                expires_at=expires_at,
                signing_key=signing_key,
            )
        except ChitraguptaError as exc:
            return {"status": "authorization_failed", "denial_reason": str(exc)}

        grant_registry[grant.grant_id] = grant
        return {"grant_dict": grant.model_dump(mode="json"), "status": "authorized"}

    def commit_node(state: ChitraguptaGraphState) -> dict[str, Any]:
        if state.get("status") != "authorized":
            return {}
        manifest_id = state["manifest_dict"]["manifest_id"]
        sealed = sealed_registry[manifest_id]
        grant_dict = state["grant_dict"]
        assert grant_dict is not None  # nosec B101 - guaranteed by the status=="authorized" check above
        grant = grant_registry[grant_dict["grant_id"]]

        try:
            result = engine.commit(sealed, grant, adapter, state.get("context"))
        except ChitraguptaError as exc:
            return {"status": "commit_failed", "denial_reason": str(exc)}

        if not result.success:
            return {
                "commit_result": {
                    "success": False,
                    "provider_reference": result.provider_reference,
                    "detail": result.detail,
                },
                "status": "commit_failed",
            }

        proof = engine.verify(sealed.manifest, result, adapter, state.get("context"))
        return {
            "commit_result": {
                "success": True,
                "provider_reference": result.provider_reference,
                "detail": result.detail,
            },
            "outcome_proof": {
                "matched_expected": proof.matched_expected,
                "detail": proof.detail,
            },
            "status": "verified" if proof.matched_expected else "verification_mismatch",
        }

    graph: StateGraph[ChitraguptaGraphState, Any, Any, Any] = StateGraph(ChitraguptaGraphState)
    graph.add_node("prepare", prepare_node)
    graph.add_node("seal", seal_node)
    graph.add_node("authorize", authorize_node)
    graph.add_node("commit", commit_node)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "seal")
    graph.add_edge("seal", "authorize")
    graph.add_edge("authorize", "commit")
    graph.add_edge("commit", END)

    return graph.compile(checkpointer=checkpointer or MemorySaver())


__all__ = ["ChitraguptaGraphState", "build_chitragupta_graph"]
