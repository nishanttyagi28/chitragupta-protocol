"""Adversarial tests for separation of duties (extreme-v2 Phase 4):
attempts to bind a role assignment to the wrong manifest, tamper with a
separation policy bundle, or slip a role conflict past the default
matrix via a custom protocol role.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from karmasakshi.config.clock import FixedClock
from karmasakshi.domain.common import Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.duty import ProtocolRole, RoleAssignment, SeparationOfDutyPolicy
from karmasakshi.duty.policy import build_separation_of_duty_policy_bundle
from karmasakshi.errors import (
    PolicyBundleTamperedError,
    RoleAssignmentError,
    SeparationOfDutyViolationError,
)
from karmasakshi.grants.model import ScopeConstraints
from karmasakshi.policy import seal_policy_bundle


def _sealed_separation_bundle(signing_key, now, *, forbidden_role_pairs=None):
    policy = (
        SeparationOfDutyPolicy(forbidden_role_pairs=forbidden_role_pairs)
        if forbidden_role_pairs is not None
        else SeparationOfDutyPolicy()
    )
    bundle = build_separation_of_duty_policy_bundle(
        policy,
        bundle_id="sod-gaming-1",
        bundle_version="1.0",
        issuer=Principal(principal_id="policy-admin", principal_type=PrincipalType.HUMAN),
        created_at=now,
        effective_from=now,
    )
    return seal_policy_bundle(bundle, signing_key, clock=FixedClock(now))


def _authorize_kwargs(sealed, *, issuer, subject, signing_key, now, **overrides):
    kwargs = {
        "issuer": issuer,
        "subject": subject,
        "audience": ("payment.simulator",),
        "allowed_effect_types": (sealed.manifest.effect_type,),
        "scope": ScopeConstraints(),
        "not_before": now,
        "expires_at": now + timedelta(minutes=5),
        "signing_key": signing_key,
    }
    kwargs.update(overrides)
    return kwargs


def test_role_assignment_bound_to_a_different_manifest_is_rejected(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    """An attacker (or a buggy caller) supplying a role_assignment whose
    manifest_hash does not match the manifest actually being authorized
    must be rejected outright -- silently ignoring the mismatch or
    applying it anyway could smuggle a role fact from one manifest's
    authorization into another's."""
    engine = engine_factory()
    manifest = manifest_factory()
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    wrong_hash_assignment = RoleAssignment.of(
        "sha256:" + "9" * 64, ProtocolRole.SEALER, service_principal.principal_id
    )

    with pytest.raises(RoleAssignmentError):
        engine.authorize(
            sealed,
            **_authorize_kwargs(
                sealed,
                issuer=service_principal,
                subject=agent_principal,
                signing_key=issuer_signing_key,
                now=now,
                role_assignment=wrong_hash_assignment,
            ),
        )


def test_tampered_separation_policy_bundle_is_rejected(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    engine = engine_factory()
    manifest = manifest_factory()
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    sod_bundle = _sealed_separation_bundle(issuer_signing_key, now)
    tampered_bundle = sod_bundle.bundle.model_copy(
        update={"payload": {**sod_bundle.bundle.payload, "policy_id": "tampered"}}
    )
    tampered_sealed_bundle = sod_bundle.model_copy(update={"bundle": tampered_bundle})

    with pytest.raises(PolicyBundleTamperedError):
        engine.authorize(
            sealed,
            **_authorize_kwargs(
                sealed,
                issuer=service_principal,
                subject=agent_principal,
                signing_key=issuer_signing_key,
                now=now,
                separation_policy_bundle=tampered_sealed_bundle,
            ),
        )


def test_custom_matrix_catches_a_non_default_role_collision(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    """The default matrix does not mention witness/verifier at all -- a
    deployment that cares about that pair must be able to add it, and
    the check must actually catch it (not silently no-op on unfamiliar
    role names it has never seen paired before)."""
    engine = engine_factory()
    manifest = manifest_factory()
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    sod_bundle = _sealed_separation_bundle(
        issuer_signing_key, now, forbidden_role_pairs=(("witness", "verifier"),)
    )
    same_principal = "user:overloaded"
    role_assignment = RoleAssignment(
        manifest_hash=sealed.seal.manifest_hash,
        assignments=(
            (ProtocolRole.WITNESS.value, same_principal),
            (ProtocolRole.VERIFIER.value, same_principal),
        ),
    )

    with pytest.raises(SeparationOfDutyViolationError):
        engine.authorize(
            sealed,
            **_authorize_kwargs(
                sealed,
                issuer=service_principal,
                subject=agent_principal,
                signing_key=issuer_signing_key,
                now=now,
                separation_policy_bundle=sod_bundle,
                role_assignment=role_assignment,
            ),
        )


def test_violation_leaves_no_grant_reservation_or_lifecycle_advance(
    engine_factory,
    manifest_factory,
    service_principal,
    agent_principal,
    issuer_signing_key,
    now,
    fake_adapter,
):
    """A blocked authorize() call must have zero side effects on the
    grant store or lifecycle state -- fail closed means fail
    *completely*, not partially."""
    from karmasakshi.state_machine import LifecycleState

    engine = engine_factory()
    manifest = manifest_factory()
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)
    sod_bundle = _sealed_separation_bundle(issuer_signing_key, now)

    with pytest.raises(SeparationOfDutyViolationError):
        engine.authorize(
            sealed,
            **_authorize_kwargs(
                sealed,
                issuer=manifest.actor,
                subject=agent_principal,
                signing_key=issuer_signing_key,
                now=now,
                separation_policy_bundle=sod_bundle,
            ),
        )
    assert engine.get_lifecycle_state(manifest.manifest_id) == LifecycleState.SEALED


def test_one_conflicting_approver_among_several_still_blocks(
    manifest_factory, agent_principal, issuer_signing_key, fixed_clock, now, fake_adapter
):
    """Under quorum, a majority of clean approvers cannot outvote or
    dilute a single approver who also holds a forbidden role -- the
    violation is structural, not a tally to be overwhelmed."""
    from karmasakshi.approval import (
        ApprovalPolicy,
        build_approval_policy_bundle,
        sign_approval_statement,
    )
    from karmasakshi.audit.journal import AuditJournal
    from karmasakshi.crypto import Keyring, generate_signing_key
    from karmasakshi.engine.context import EngineContext
    from karmasakshi.engine.core import KarmaSakshiEngine
    from karmasakshi.stores.memory import InMemoryGrantStore

    conflicted_key = generate_signing_key("key-conflicted")
    clean_keys = [generate_signing_key(f"key-clean-{i}") for i in range(3)]
    all_keys = [issuer_signing_key, conflicted_key, *clean_keys]
    engine = KarmaSakshiEngine(
        EngineContext(
            keyring=Keyring([k.verification_key() for k in all_keys]),
            grant_store=InMemoryGrantStore(),
            audit=AuditJournal(clock=fixed_clock),
            clock=fixed_clock,
        )
    )
    manifest = manifest_factory()
    prepared = engine.prepare(fake_adapter, manifest, context=None)
    sealed = engine.seal(prepared, issuer_signing_key)

    approval_bundle_unsigned = build_approval_policy_bundle(
        ApprovalPolicy(required_approvals=4),
        bundle_id="approval-gaming-1",
        bundle_version="1.0",
        issuer=Principal(principal_id="policy-admin", principal_type=PrincipalType.HUMAN),
        created_at=now,
        effective_from=now,
    )
    approval_bundle = seal_policy_bundle(
        approval_bundle_unsigned, issuer_signing_key, clock=FixedClock(now)
    )
    sod_bundle = _sealed_separation_bundle(issuer_signing_key, now)

    def _approve(key, name):
        return sign_approval_statement(
            statement_id=f"stmt-{name}",
            manifest_hash=sealed.seal.manifest_hash,
            approval_policy_bundle_hash=approval_bundle.seal.bundle_hash,
            approver=Principal(principal_id=name, principal_type=PrincipalType.HUMAN),
            decision="approve",
            signing_key=key,
            expires_at=now + timedelta(minutes=30),
            nonce=f"nonce-{name}",
            clock=FixedClock(now),
        )

    statements = (
        _approve(conflicted_key, "conflicted"),
        _approve(clean_keys[0], "clean-0"),
        _approve(clean_keys[1], "clean-1"),
        _approve(clean_keys[2], "clean-2"),
    )
    role_assignment = RoleAssignment.of(
        sealed.seal.manifest_hash, ProtocolRole.SEALER, "conflicted"
    )

    with pytest.raises(SeparationOfDutyViolationError):
        engine.authorize_with_quorum(
            sealed,
            statements=statements,
            approval_policy_bundle=approval_bundle,
            proposer=manifest.actor,
            subject=agent_principal,
            grant_issuer=Principal(
                principal_id="quorum-service", principal_type=PrincipalType.SERVICE
            ),
            audience=("payment.simulator",),
            allowed_effect_types=(manifest.effect_type,),
            scope=ScopeConstraints(),
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            signing_key=issuer_signing_key,
            separation_policy_bundle=sod_bundle,
            role_assignment=role_assignment,
        )
