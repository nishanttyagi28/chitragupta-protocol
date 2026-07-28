"""In-process control-plane state.

This is intentionally process-local (no external database) -- the durable
record of what happened is always the audit journal (SQLite-backed by
default), same as the CLI. Suitable for a single control-plane instance;
horizontal scaling would need a shared GrantStore (Redis) and a shared
audit backend, which the engine already supports (see docs/storage-semantics.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from karmasakshi.adapters.base import CommitResult, CompensationResult, EffectAdapter, OutcomeProof
from karmasakshi.adapters.email_sandbox import EmailSandboxAdapter, SandboxOutbox
from karmasakshi.adapters.payment_simulator import PaymentSimulator, PaymentSimulatorAdapter
from karmasakshi.adapters.sqlite_db import SQLiteRowAdapter
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.audit.sqlite_backend import SQLiteAuditBackend
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.engine.context import EngineContext
from karmasakshi.engine.core import KarmaSakshiEngine
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.stores.sqlite import SQLiteGrantStore


@dataclass
class ApiState:
    engine: KarmaSakshiEngine
    signing_key: SigningKey
    keyring: Keyring
    adapters: dict[str, EffectAdapter]
    principals: dict[str, Principal] = field(default_factory=dict)
    sealed_manifests: dict[str, SealedManifest] = field(default_factory=dict)
    grants: dict[str, ExecutionGrant] = field(default_factory=dict)
    grants_by_manifest: dict[str, list[str]] = field(default_factory=dict)
    commit_results: dict[str, CommitResult] = field(default_factory=dict)
    outcome_proofs: dict[str, OutcomeProof] = field(default_factory=dict)
    compensation_results: dict[str, CompensationResult] = field(default_factory=dict)
    kill_switch_engaged: bool = False

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
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=keyring,
            grant_store=SQLiteGrantStore(data_dir / "grants.db"),
            audit=AuditJournal(backend=SQLiteAuditBackend(data_dir / "audit.db")),
        )
    )

    payment_simulator = PaymentSimulator()
    payment_simulator.fund_account("acct-src", 10_000_000)

    adapters: dict[str, EffectAdapter] = {
        "sqlite.row": SQLiteRowAdapter(str(data_dir / "ledger.db")),
        "email.sandbox": EmailSandboxAdapter(SandboxOutbox()),
        "payment.simulator": PaymentSimulatorAdapter(payment_simulator),
    }

    return ApiState(engine=engine, signing_key=signing_key, keyring=keyring, adapters=adapters)


__all__ = ["ApiState", "build_default_state"]
