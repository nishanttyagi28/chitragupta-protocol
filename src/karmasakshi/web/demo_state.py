"""Isolated, auto-resetting sandbox state for the public interactive demo.

Deliberately separate from :class:`~karmasakshi.api.state.ApiState` (the real
control-plane state): the public demo never touches durable storage, never
shares data with an authenticated deployment, and rebuilds itself from
scratch on a timer so no one visitor's actions persist indefinitely. Only
the three reference simulators (SQLite, email sandbox, payment simulator)
are used here -- see docs/deployment.md for the full public-demo safety
model.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from karmasakshi.adapters.base import EffectAdapter
from karmasakshi.adapters.email_sandbox import EmailSandboxAdapter, SandboxOutbox
from karmasakshi.adapters.payment_simulator import PaymentSimulator, PaymentSimulatorAdapter
from karmasakshi.adapters.registry import TrustedAdapterRegistry, build_reference_registry
from karmasakshi.audit.journal import AuditJournal
from karmasakshi.config.clock import FixedClock
from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import SigningKey, generate_signing_key
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.domain.seal import SealedManifest
from karmasakshi.engine.context import EngineContext
from karmasakshi.engine.core import KarmaSakshiEngine
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.stores.memory import InMemoryGrantStore

DEMO_TTL_ENV = "KARMASAKSHI_DEMO_TTL_SECONDS"
DEFAULT_TTL_SECONDS = 900  # 15 minutes -- see docs/deployment.md#public-demo-safety

TREASURY_ACCOUNT = "demo-treasury"
TREASURY_OPENING_BALANCE_MINOR_UNITS = 100_000_00  # INR 100,000.00

AGENT = Principal(principal_id="refund-agent", principal_type=PrincipalType.AGENT)
APPROVER = Principal(principal_id="finance-approver", principal_type=PrincipalType.HUMAN)


@dataclass
class ScenarioStep:
    label: str
    status: Literal["info", "ok", "blocked", "error"]
    detail: str
    data: dict[str, Any] | None = None


@dataclass
class ScenarioRun:
    key: str
    title: str
    passed: bool
    steps: list[ScenarioStep] = field(default_factory=list)
    ran_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DemoSession:
    session_id: str
    created_at: datetime
    clock: FixedClock
    engine: KarmaSakshiEngine
    signing_key: SigningKey
    other_signing_key: SigningKey
    keyring: Keyring
    payment_simulator: PaymentSimulator
    email_outbox: SandboxOutbox
    adapters: dict[str, EffectAdapter]
    adapter_registry: TrustedAdapterRegistry
    tmp_dir: Path
    pending_manifests: dict[str, SealedManifest] = field(default_factory=dict)
    grants: dict[str, ExecutionGrant] = field(default_factory=dict)
    grants_by_manifest: dict[str, list[str]] = field(default_factory=dict)
    commit_results: dict[str, Any] = field(default_factory=dict)
    outcome_proofs: dict[str, Any] = field(default_factory=dict)
    scenario_runs: dict[str, ScenarioRun] = field(default_factory=dict)

    def register_grant(self, manifest_id: str, grant: ExecutionGrant) -> None:
        self.grants[grant.grant_id] = grant
        self.grants_by_manifest.setdefault(manifest_id, []).append(grant.grant_id)

    def new_sqlite_adapter(self, table: str = "demo_ledger") -> Any:
        from karmasakshi.adapters.sqlite_db import SQLiteRowAdapter

        db_path = str(self.tmp_dir / f"{table}-{uuid.uuid4().hex[:8]}.db")
        return SQLiteRowAdapter(db_path, table=table)


def _demo_ttl_seconds() -> int:
    raw = os.environ.get(DEMO_TTL_ENV)
    if not raw:
        return DEFAULT_TTL_SECONDS
    try:
        return max(60, int(raw))
    except ValueError:
        return DEFAULT_TTL_SECONDS


def build_session() -> DemoSession:
    now = datetime.now(timezone.utc)
    clock = FixedClock(now)
    signing_key = generate_signing_key("public-demo-issuer")
    other_signing_key = generate_signing_key("public-demo-untrusted")
    keyring = Keyring([signing_key.verification_key()])
    adapter_registry = build_reference_registry()
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=keyring,
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=clock),
            clock=clock,
            adapter_registry=adapter_registry,
        )
    )

    payment_simulator = PaymentSimulator()
    payment_simulator.fund_account(TREASURY_ACCOUNT, TREASURY_OPENING_BALANCE_MINOR_UNITS)
    email_outbox = SandboxOutbox()

    tmp_dir = Path(tempfile.mkdtemp(prefix="karmasakshi-public-demo-"))
    adapters: dict[str, EffectAdapter] = {
        "payment.simulator": PaymentSimulatorAdapter(payment_simulator),
        "email.sandbox": EmailSandboxAdapter(email_outbox),
    }

    return DemoSession(
        session_id=str(uuid.uuid4()),
        created_at=now,
        clock=clock,
        engine=engine,
        signing_key=signing_key,
        other_signing_key=other_signing_key,
        keyring=keyring,
        payment_simulator=payment_simulator,
        email_outbox=email_outbox,
        adapters=adapters,
        adapter_registry=adapter_registry,
        tmp_dir=tmp_dir,
    )


_lock = threading.Lock()
_current: DemoSession | None = None


def _is_expired(session: DemoSession) -> bool:
    age = (datetime.now(timezone.utc) - session.created_at).total_seconds()
    return age > _demo_ttl_seconds()


def get_session() -> DemoSession:
    """Return the shared public-demo sandbox, lazily rebuilding it if it has
    aged past ``KARMASAKSHI_DEMO_TTL_SECONDS`` (default 15 minutes)."""
    global _current
    with _lock:
        if _current is None or _is_expired(_current):
            old = _current
            _current = build_session()
            if old is not None:
                shutil.rmtree(old.tmp_dir, ignore_errors=True)
        return _current


def reset_session() -> DemoSession:
    """Force an immediate reset, e.g. from the "Reset demo" button."""
    global _current
    with _lock:
        old = _current
        _current = build_session()
        if old is not None:
            shutil.rmtree(old.tmp_dir, ignore_errors=True)
        return _current


def session_age_seconds() -> float:
    session = get_session()
    return (datetime.now(timezone.utc) - session.created_at).total_seconds()


def session_ttl_seconds() -> int:
    return _demo_ttl_seconds()


__all__ = [
    "AGENT",
    "APPROVER",
    "TREASURY_ACCOUNT",
    "TREASURY_OPENING_BALANCE_MINOR_UNITS",
    "DemoSession",
    "ScenarioRun",
    "ScenarioStep",
    "build_session",
    "get_session",
    "reset_session",
    "session_age_seconds",
    "session_ttl_seconds",
]
