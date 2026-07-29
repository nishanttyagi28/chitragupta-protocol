"""Grant issuance.

Issuance is the one place invariant #30 ("the model or agent must never make
the final authorization decision") is enforced structurally: an issuer whose
``principal_type`` is ``agent`` can never mint a grant, full stop.
"""

from __future__ import annotations

from datetime import datetime

from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.crypto.keys import SigningKey
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.errors import GrantIssuerNotAuthorizedError
from karmasakshi.grants.model import ExecutionGrant, ScopeConstraints


def issue_grant(
    *,
    grant_id: str,
    issuer: Principal,
    subject: Principal,
    audience: tuple[str, ...],
    allowed_effect_types: tuple[str, ...],
    scope: ScopeConstraints,
    not_before: datetime,
    expires_at: datetime,
    nonce: str,
    signing_key: SigningKey,
    manifest_hash: str | None = None,
    policy_bundle_hash: str | None = None,
    approval_set_hash: str | None = None,
    decision_envelope_hash: str | None = None,
    causal_graph_hash: str | None = None,
    authority_budget_id: str | None = None,
    max_uses: int = 1,
    parent_grant_id: str | None = None,
    clock: Clock = SYSTEM_CLOCK,
) -> ExecutionGrant:
    """Mint and sign a new :class:`ExecutionGrant`.

    Raises :class:`GrantIssuerNotAuthorizedError` if ``issuer`` is an agent
    principal -- agents may request grants but may never issue them.

    ``decision_envelope_hash`` and ``causal_graph_hash`` are mutually
    exclusive plan-level bindings (Phase 6); passing both raises
    ``ValueError`` from ``ExecutionGrant`` validation.
    """
    if issuer.principal_type == PrincipalType.AGENT:
        raise GrantIssuerNotAuthorizedError(
            "an agent principal cannot issue an execution grant; authorization "
            "must come from a human or service principal (invariant #30)"
        )

    unsigned = ExecutionGrant(
        grant_id=grant_id,
        manifest_hash=manifest_hash,
        policy_bundle_hash=policy_bundle_hash,
        approval_set_hash=approval_set_hash,
        decision_envelope_hash=decision_envelope_hash,
        causal_graph_hash=causal_graph_hash,
        authority_budget_id=authority_budget_id,
        issuer=issuer,
        subject=subject,
        audience=audience,
        allowed_effect_types=allowed_effect_types,
        scope=scope,
        issued_at=clock.now(),
        not_before=not_before,
        expires_at=expires_at,
        max_uses=max_uses,
        nonce=nonce,
        parent_grant_id=parent_grant_id,
        key_id=signing_key.key_id,
        algorithm=signing_key.algorithm,
        signature=None,
    )
    signature = signing_key.sign(unsigned.canonical_hash().encode("utf-8"))
    return unsigned.model_copy(update={"signature": signature})


__all__ = ["issue_grant"]
