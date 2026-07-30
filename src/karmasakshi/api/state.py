"""In-process control-plane state.

Principals, manifests, and grants held here are process-local caches.
Durable protocol state uses SQLite under ``data_dir``: grant store,
audit journal, and (Phase 13) lifecycle store. Suitable for a single
control-plane instance; horizontal scaling would need shared backends
(see docs/storage-semantics.md). The audit journal remains the
tamper-evident record of what happened.
"""

from __future__ import annotations

import contextlib
import os
import stat
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
from karmasakshi.crypto.keys import (
    SigningKey,
    generate_signing_key,
    load_signing_key_from_file,
    save_signing_key_to_file,
)
from karmasakshi.domain.common import Principal
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.engine.context import EngineContext
from karmasakshi.engine.core import KarmaSakshiEngine
from karmasakshi.envelope.model import DecisionEnvelope
from karmasakshi.errors import KeyLoadError
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.integrations.agenteval import FailureMemoryStore
from karmasakshi.intelligence.model import EffectAssessment
from karmasakshi.outbox.sqlite import SQLiteOutboxStore
from karmasakshi.policy.bundle import SealedPolicyBundle
from karmasakshi.stores.lifecycle_sqlite import SQLiteLifecycleStore
from karmasakshi.stores.sqlite import SQLiteGrantStore
from karmasakshi.witness.model import WitnessStatement

_SIGNING_KEY_FILENAME = "signing-key.bin"
_SIGNING_PUB_FILENAME = "signing-key.pub"
# Files that indicate this data_dir already held a signing identity or
# signed protocol state. If the private key is missing while any of these
# exist, fail closed rather than mint a replacement identity that would
# invalidate prior seals/grants/policy signatures.
_PRIOR_IDENTITY_MARKERS = (
    _SIGNING_PUB_FILENAME,
    "grants.db",
    "audit.db",
    "lifecycle.db",
    "outbox.db",
    "ledger.db",
    "agenteval-memory.jsonl",
)


def _write_public_key_sidecar(signing_key: SigningKey, pub_path: Path) -> None:
    pub_path.write_bytes(signing_key.public_bytes())
    with contextlib.suppress(OSError):
        os.chmod(pub_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600; best-effort on Windows


def _has_prior_signing_identity(data_dir: Path) -> bool:
    return any((data_dir / name).exists() for name in _PRIOR_IDENTITY_MARKERS)


def _load_or_create_durable_signing_key(data_dir: Path, *, key_id: str) -> SigningKey:
    """Load the durable dev signing key, or create one only on clean first start.

    Fail closed when:
    - the private key file is corrupt / unreadable;
    - the private key is missing but this directory already has durable
      protocol artifacts or a public-key sidecar (would otherwise silently
      mint a new identity for existing signed records);
    - the private key's public material does not match the recorded
      ``signing-key.pub`` sidecar (mismatched identity).
    """
    key_path = data_dir / _SIGNING_KEY_FILENAME
    pub_path = data_dir / _SIGNING_PUB_FILENAME

    if key_path.exists():
        signing_key = load_signing_key_from_file(key_path, key_id=key_id)
        if pub_path.exists():
            try:
                expected_public = pub_path.read_bytes()
            except OSError as exc:
                raise KeyLoadError(
                    "could not read signing-key.pub public identity sidecar (fail closed)"
                ) from exc
            if len(expected_public) != 32:
                raise KeyLoadError(
                    "signing-key.pub is corrupt (expected 32 raw Ed25519 public key bytes)"
                )
            if signing_key.public_bytes() != expected_public:
                raise KeyLoadError(
                    "signing key does not match recorded public identity (fail closed)"
                )
        else:
            # Upgrade path from the first durable-key fix (private key only):
            # record the public identity so later mismatch detection works.
            _write_public_key_sidecar(signing_key, pub_path)
        return signing_key

    if _has_prior_signing_identity(data_dir):
        raise KeyLoadError(
            "signing key missing for existing tenant data directory (fail closed); "
            "refusing to generate a replacement identity that would invalidate "
            "prior signatures"
        )

    signing_key = generate_signing_key(key_id)
    save_signing_key_to_file(signing_key, key_path)
    _write_public_key_sidecar(signing_key, pub_path)
    return signing_key


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
    #: The exact policy bundle that actually produced a manifest's risk
    #: assessment at proposal time (see `karmasakshi.gateway.refunds`).
    #: Approval binds to this, not to whatever policy is active *now* --
    #: an org switching policies between propose and approve must not
    #: silently rebind an already-shown assessment to a policy that never
    #: scored it.
    assessment_policy_bundles: dict[str, SealedPolicyBundle] = field(default_factory=dict)
    approval_policy_bundles: dict[str, SealedPolicyBundle] = field(default_factory=dict)
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
    against a durable dev signing key -- suitable for local development and
    demos. Production embedding should construct ``ApiState`` directly with
    real keys/adapters instead of calling this.

    RA-002 follow-up: the signing key is persisted to (and reloaded from)
    ``data_dir`` rather than regenerated every call, using the same
    ``save_signing_key_to_file``/``load_signing_key_from_file`` helpers
    already used elsewhere for dev-mode key storage (best-effort
    owner-only file permissions -- see docs/limitations.md). Without this,
    every process restart minted a new key, and the keyring only ever
    trusted the newest one -- so any content signed before a restart
    (grants, policy bundles, approval statements) failed signature
    verification against the post-restart keyring. That silently broke
    two things once refund-journey state became durable: any org with an
    active policy could no longer propose new refunds after a restart
    (the activated bundle's signature no longer verified), and every
    already-completed refund's Action Passport permanently reported
    ``grant_verified: False`` afterward.

    Missing, corrupt, or mismatched key material fails closed when the
    data directory already holds durable protocol artifacts: a new
    identity is never silently minted for existing signed records.
    Clean first-start (empty data directory) still generates a fresh key.
    """
    data_dir = data_dir or Path.cwd() / ".karmasakshi-api"
    data_dir.mkdir(parents=True, exist_ok=True)

    signing_key = _load_or_create_durable_signing_key(data_dir, key_id="api-dev-issuer")
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
