from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from karmasakshi.crypto import Keyring
from karmasakshi.errors import (
    GrantExpiredError,
    GrantIssuerNotAuthorizedError,
    GrantNotYetValidError,
    InvalidSignatureError,
    UnknownKeyError,
)
from karmasakshi.grants import ExecutionGrant, ScopeConstraints, issue_grant, verify_grant
from karmasakshi.grants.verifier import verify_grant_signature, verify_grant_time_window


def _issue(now, issuer, subject, signing_key, **overrides):
    kwargs = {
        "grant_id": "grant-1",
        "issuer": issuer,
        "subject": subject,
        "audience": ("payment.simulator",),
        "allowed_effect_types": ("payment.transfer",),
        "scope": ScopeConstraints(),
        "not_before": now,
        "expires_at": now + timedelta(minutes=5),
        "nonce": "grant-nonce-1",
        "signing_key": signing_key,
        "manifest_hash": "sha256:" + "a" * 64,
    }
    kwargs.update(overrides)
    return issue_grant(**kwargs)


def test_issue_and_verify_grant(
    now, service_principal, agent_principal, issuer_signing_key, keyring
):
    grant = _issue(now, service_principal, agent_principal, issuer_signing_key)
    verify_grant(grant, keyring, now=now)


def test_agent_cannot_issue_grant(now, agent_principal, issuer_signing_key):
    with pytest.raises(GrantIssuerNotAuthorizedError):
        _issue(now, agent_principal, agent_principal, issuer_signing_key)


def test_human_can_issue_grant(now, human_principal, agent_principal, issuer_signing_key, keyring):
    grant = _issue(now, human_principal, agent_principal, issuer_signing_key)
    verify_grant(grant, keyring, now=now)


def test_tampering_any_field_invalidates_signature(
    now, service_principal, agent_principal, issuer_signing_key, keyring
):
    grant = _issue(now, service_principal, agent_principal, issuer_signing_key)
    tampered = grant.model_copy(update={"max_uses": grant.max_uses + 10})
    with pytest.raises(InvalidSignatureError):
        verify_grant_signature(tampered, keyring)


def test_tampering_manifest_hash_invalidates_signature(
    now, service_principal, agent_principal, issuer_signing_key, keyring
):
    grant = _issue(now, service_principal, agent_principal, issuer_signing_key)
    tampered = grant.model_copy(update={"manifest_hash": "sha256:" + "b" * 64})
    with pytest.raises(InvalidSignatureError):
        verify_grant_signature(tampered, keyring)


def test_unknown_key_fails_closed(now, service_principal, agent_principal, issuer_signing_key):
    grant = _issue(now, service_principal, agent_principal, issuer_signing_key)
    with pytest.raises(UnknownKeyError):
        verify_grant_signature(grant, Keyring([]))


def test_unsigned_grant_rejected(
    now, service_principal, agent_principal, issuer_signing_key, keyring
):
    grant = _issue(now, service_principal, agent_principal, issuer_signing_key)
    unsigned = grant.model_copy(update={"signature": None})
    with pytest.raises(InvalidSignatureError):
        verify_grant_signature(unsigned, keyring)


@pytest.mark.parametrize(
    "offset,expect_error",
    [
        (timedelta(seconds=1), None),
        (timedelta(seconds=0), None),
        (timedelta(minutes=5), None),
        (timedelta(minutes=5, seconds=1), GrantExpiredError),
        (timedelta(seconds=-1), GrantNotYetValidError),
    ],
)
def test_time_window_boundaries(now, offset, expect_error):
    grant = ExecutionGrant(
        grant_id="g1",
        manifest_hash="sha256:" + "a" * 64,
        issuer={"principal_id": "svc", "principal_type": "service"},
        subject={"principal_id": "agent-1", "principal_type": "agent"},
        audience=("payment.simulator",),
        allowed_effect_types=("payment.transfer",),
        scope=ScopeConstraints(),
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        nonce="n1",
        key_id="k1",
        signature="unused-for-time-check",
    )
    check_time = now + offset
    if expect_error is None:
        verify_grant_time_window(grant, check_time)
    else:
        with pytest.raises(expect_error):
            verify_grant_time_window(grant, check_time)


def test_clock_skew_leeway_extends_boundaries(now):
    grant = ExecutionGrant(
        grant_id="g1",
        manifest_hash="sha256:" + "a" * 64,
        issuer={"principal_id": "svc", "principal_type": "service"},
        subject={"principal_id": "agent-1", "principal_type": "agent"},
        audience=("payment.simulator",),
        allowed_effect_types=("payment.transfer",),
        scope=ScopeConstraints(),
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=5),
        nonce="n1",
        key_id="k1",
        signature="unused-for-time-check",
    )
    just_after_expiry = now + timedelta(minutes=5, seconds=3)
    with pytest.raises(GrantExpiredError):
        verify_grant_time_window(grant, just_after_expiry, leeway=timedelta(seconds=0))
    verify_grant_time_window(grant, just_after_expiry, leeway=timedelta(seconds=5))


def test_grant_rejects_invalid_time_window(now):
    with pytest.raises(ValidationError):
        ExecutionGrant(
            grant_id="g1",
            issuer={"principal_id": "svc", "principal_type": "service"},
            subject={"principal_id": "agent-1", "principal_type": "agent"},
            audience=("payment.simulator",),
            allowed_effect_types=("payment.transfer",),
            scope=ScopeConstraints(),
            issued_at=now,
            not_before=now,
            expires_at=now,  # not strictly after not_before
            nonce="n1",
            key_id="k1",
        )


def test_grant_rejects_zero_max_uses(now):
    with pytest.raises(ValidationError):
        ExecutionGrant(
            grant_id="g1",
            issuer={"principal_id": "svc", "principal_type": "service"},
            subject={"principal_id": "agent-1", "principal_type": "agent"},
            audience=("payment.simulator",),
            allowed_effect_types=("payment.transfer",),
            scope=ScopeConstraints(),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(minutes=1),
            max_uses=0,
            nonce="n1",
            key_id="k1",
        )


def test_scope_rejects_empty_allow_list(now):
    with pytest.raises(ValidationError):
        ScopeConstraints(target_resources=())


def test_grant_rejects_unknown_fields(now):
    with pytest.raises(ValidationError):
        ExecutionGrant(
            grant_id="g1",
            issuer={"principal_id": "svc", "principal_type": "service"},
            subject={"principal_id": "agent-1", "principal_type": "agent"},
            audience=("payment.simulator",),
            allowed_effect_types=("payment.transfer",),
            scope=ScopeConstraints(),
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(minutes=1),
            nonce="n1",
            key_id="k1",
            unknown_field="nope",
        )
