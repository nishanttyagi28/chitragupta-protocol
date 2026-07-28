"""End-to-end tests for the LangGraph integration: pause for authorization,
resume, commit, verify -- and the denied/expired/tampered-adjacent cases.

Skipped entirely if langgraph/langchain-core are not installed (optional
extra) -- see BUILD_STATUS.md for whether this ran in a given verification
pass.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

langgraph = pytest.importorskip("langgraph")

from langgraph.types import Command  # noqa: E402

from karmasakshi.adapters.payment_simulator import (  # noqa: E402
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from karmasakshi.audit.journal import AuditJournal  # noqa: E402
from karmasakshi.crypto import Keyring, generate_signing_key  # noqa: E402
from karmasakshi.domain.common import Principal  # noqa: E402
from karmasakshi.domain.enums import PrincipalType  # noqa: E402
from karmasakshi.engine import EngineContext, KarmaSakshiEngine  # noqa: E402
from karmasakshi.integrations.langgraph import build_karmasakshi_graph  # noqa: E402
from karmasakshi.stores.memory import InMemoryGrantStore  # noqa: E402


@pytest.fixture
def signing_key():
    return generate_signing_key("langgraph-issuer")


@pytest.fixture
def engine(signing_key):
    keyring = Keyring([signing_key.verification_key()])
    ctx = EngineContext(
        keyring=keyring,
        grant_store=InMemoryGrantStore(),
        audit=AuditJournal(),
    )
    return KarmaSakshiEngine(ctx)


@pytest.fixture
def simulator():
    sim = PaymentSimulator()
    sim.fund_account("acct-src", 1_000_000)
    return sim


@pytest.fixture
def adapter(simulator):
    return PaymentSimulatorAdapter(simulator)


@pytest.fixture
def app(engine, adapter, signing_key):
    return build_karmasakshi_graph(engine=engine, adapter=adapter, signing_key=signing_key)


AGENT = Principal(principal_id="agent-1", principal_type=PrincipalType.AGENT)
HUMAN = Principal(principal_id="user-1", principal_type=PrincipalType.HUMAN)


def _request(**overrides):
    kwargs = {
        "actor": AGENT,
        "principal": HUMAN,
        "source_account": "acct-src",
        "beneficiary": "merchant-A",
        "amount_minor_units": 1000,
        "currency": "INR",
        "reference": "ref-1",
        "idempotency_key": "idem-lg-default",
    }
    kwargs.update(overrides)
    return PaymentRequest(**kwargs)


def _issuer_subject_payload():
    return {
        "issuer": {"principal_id": HUMAN.principal_id, "principal_type": "human"},
        "subject": {"principal_id": AGENT.principal_id, "principal_type": "agent"},
    }


def test_graph_pauses_before_authorization(app):
    config = {"configurable": {"thread_id": "pause-1"}}
    result = app.invoke({"request": _request(idempotency_key="idem-lg-1")}, config=config)
    assert result["status"] == "sealed"
    snapshot = app.get_state(config)
    assert snapshot.next == ("authorize",)


def test_approved_manifest_commits_and_verifies(app, simulator):
    config = {"configurable": {"thread_id": "approve-1"}}
    app.invoke({"request": _request(idempotency_key="idem-lg-2")}, config=config)
    result = app.invoke(
        Command(resume={"approved": True, **_issuer_subject_payload()}), config=config
    )
    assert result["status"] == "verified"
    assert result["commit_result"]["success"] is True
    assert result["outcome_proof"]["matched_expected"] is True
    assert simulator.get_balance("acct-src") == 1_000_000 - 1000


def test_denied_authorization_never_commits(app, simulator):
    config = {"configurable": {"thread_id": "deny-1"}}
    app.invoke({"request": _request(idempotency_key="idem-lg-3")}, config=config)
    result = app.invoke(
        Command(resume={"approved": False, "reason": "policy denied"}), config=config
    )
    assert result["status"] == "denied"
    assert result["denial_reason"] == "policy denied"
    assert simulator.get_balance("acct-src") == 1_000_000


def test_agent_cannot_be_the_authorizing_issuer(app):
    config = {"configurable": {"thread_id": "agent-issuer-1"}}
    app.invoke({"request": _request(idempotency_key="idem-lg-4")}, config=config)
    result = app.invoke(
        Command(
            resume={
                "approved": True,
                "issuer": {"principal_id": "agent-1", "principal_type": "agent"},
                "subject": {"principal_id": "agent-1", "principal_type": "agent"},
            }
        ),
        config=config,
    )
    assert result["status"] == "authorization_failed"


def test_already_expired_authorization_window_fails_at_commit(app):
    config = {"configurable": {"thread_id": "expired-1"}}
    app.invoke({"request": _request(idempotency_key="idem-lg-5")}, config=config)
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    result = app.invoke(
        Command(
            resume={
                "approved": True,
                **_issuer_subject_payload(),
                "not_before": past - timedelta(minutes=10),
                "expires_at": past,
            }
        ),
        config=config,
    )
    assert result["status"] == "commit_failed"


def test_interrupt_payload_never_contains_signing_material(app):
    config = {"configurable": {"thread_id": "no-secrets-1"}}
    app.invoke({"request": _request(idempotency_key="idem-lg-6")}, config=config)
    snapshot = app.get_state(config)
    interrupt_value = snapshot.tasks[0].interrupts[0].value
    serialized = str(interrupt_value)
    assert "private" not in serialized.lower()
    assert "signature" not in serialized.lower()
    assert "BEGIN" not in serialized  # no PEM-looking key material
