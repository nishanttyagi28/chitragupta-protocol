"""In-process control-plane state.

Principals, manifests, and grants held here are process-local caches.
Durable protocol state uses SQLite under ``data_dir``: grant store,
audit journal, and (Phase 13) lifecycle store. Suitable for a single
control-plane instance; horizontal scaling would need shared backends
(see docs/storage-semantics.md). The audit journal remains the
tamper-evident record of what happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from karmasakshi.adapters.base import CommitResult, CompensationResult, EffectAdapter, OutcomeProof
from karmasakshi.adapters.email_sandbox import EmailSandboxAdapter, SandboxOutbox
from karmasakshi.adapters.payment_simulator import PaymentSimulator, PaymentSimulatorAdapter
from karmasakshi.adapters.registry import TrustedAdapterRegistry, build_reference_registry
from karmasakshi.adapters.sqlite_db import SQLiteRowAdapter
from karmasakshi.approval.model import ApprovalStatement
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.audit.sqlite_backend import SQLiteAuditBackend
from karmasakshi.causal.graph import CausalEffectGraph
from karmasakshi.compensation.passport import CompensationPassport
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.engine.context import EngineContext
from karmasakshi.engine.core import KarmaSakshiEngine
from karmasakshi.envelope.model import DecisionEnvelope
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.integrations.agenteval import FailureMemoryStore
from karmasakshi.intelligence.model import EffectAssessment
from karmasakshi.outbox.sqlite import SQLiteOutboxStore
from karmasakshi.policy.bundle import SealedPolicyBundle
from karmasakshi.stores.lifecycle_sqlite import SQLiteLifecycleStore
from karmasakshi.stores.sqlite import SQLiteGrantStore
from karmasakshi.witness.model import WitnessStatement


@dataclass
class ApiState:
    engine: KarmaSakshiEngine
    signing_key: SigningKey
    keyring: Keyring
    adapters: dict[str, EffectAdapter]
    adapter_registry: TrustedAdapterRegistry
    agenteval_memory: FailureMemoryStore
    principals: dict[str, Principal] = field(default_factory=dict)
    sealed_manifests: dict[str, SealedManifest] = field(default_factory=dict)
    grants: dict[str, ExecutionGrant] = field(default_factory=dict)
    grants_by_manifest: dict[str, list[str]] = field(default_factory=dict)
    commit_results: dict[str, CommitResult] = field(default_factory=dict)
    outcome_proofs: dict[str, OutcomeProof] = field(default_factory=dict)
    compensation_results: dict[str, CompensationResult] = field(default_factory=dict)
    assessments: dict[str, EffectAssessment] = field(default_factory=dict)
    policy_bundles: dict[str, SealedPolicyBundle] = field(default_factory=dict)
    approval_statements: dict[str, list[ApprovalStatement]] = field(default_factory=dict)
    witness_statements: dict[str, list[WitnessStatement]] = field(default_factory=dict)
    causal_graphs: dict[str, CausalEffectGraph] = field(default_factory=dict)
    decision_envelopes: dict[str, DecisionEnvelope] = field(default_factory=dict)
    compensation_passports: dict[str, CompensationPassport] = field(default_factory=dict)
    kill_switch_engaged: bool = False
    #: Gateway refund vertical slice (Milestone A): which entry of
    #: `policy_bundles` is currently "active" for this organization, bound
    #: into new refund grants at approval time unless a caller explicitly
    #: overrides it. `None` means no organization policy has been
    #: activated yet -- refunds are still approvable, just unbound.
    active_policy_bundle_id: str | None = None

    def register_grant(self, manifest_id: str, grant: ExecutionGrant) -> None:
        self.grants[grant.grant_id] = grant
        self.grants_by_manifest.setdefault(manifest_id, []).append(grant.grant_id)


def build_default_state(data_dir: Path | None = None) -> ApiState:
    """Build a ready-to-use state with the three reference adapters wired up
    against a fresh signing key -- suitable for local development and demos.
    Production embedding should construct ``ApiState`` directly with real
    keys/adapters instead of calling this.
    """
    data_dir = data_dir or Path.cwd() / ".karmasakshi-api"
    data_dir.mkdir(parents=True, exist_ok=True)

    signing_key = generate_signing_key("api-dev-issuer")
    keyring = Keyring([signing_key.verification_key()])
    adapter_registry = build_reference_registry()
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=keyring,
            grant_store=SQLiteGrantStore(data_dir / "grants.db"),
            audit=AuditJournal(backend=SQLiteAuditBackend(data_dir / "audit.db")),
            lifecycle_store=SQLiteLifecycleStore(data_dir / "lifecycle.db"),
            outbox_store=SQLiteOutboxStore(data_dir / "outbox.db"),
            adapter_registry=adapter_registry,
        )
    )

    payment_simulator = PaymentSimulator()
    payment_simulator.fund_account("acct-src", 10_000_000)

    adapters: dict[str, EffectAdapter] = {
        "sqlite.row": SQLiteRowAdapter(str(data_dir / "ledger.db")),
        "email.sandbox": EmailSandboxAdapter(SandboxOutbox()),
        "payment.simulator": PaymentSimulatorAdapter(payment_simulator),
    }

    return ApiState(
        engine=engine,
        signing_key=signing_key,
        keyring=keyring,
        adapters=adapters,
        adapter_registry=adapter_registry,
        agenteval_memory=FailureMemoryStore(data_dir / "agenteval-memory.jsonl"),
    )


__all__ = ["ApiState", "build_default_state"]
