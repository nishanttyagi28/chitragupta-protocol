"""Gateway refund vertical slice tests (Milestone A). Skipped entirely if
fastapi is not installed (the optional ``api`` extra)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("jinja2")

from fastapi.testclient import TestClient

from karmasakshi.api.app import create_app
from karmasakshi.api.auth import DEV_MODE_ENV


@pytest.fixture
def dev_client(monkeypatch, tmp_path):
    monkeypatch.setenv(DEV_MODE_ENV, "1")
    app = create_app(data_dir=tmp_path / "api-data")
    return TestClient(app), app


def _bootstrap_and_login(client, org_id="acme", email="alice@acme.com", password="hunter2"):
    client.post(
        "/gateway/organizations",
        json={
            "org_id": org_id,
            "name": "Acme Corp",
            "owner_email": email,
            "owner_display_name": "Alice",
            "owner_password": password,
        },
    )
    login = client.post(
        "/gateway/auth/login", json={"org_id": org_id, "email": email, "password": password}
    )
    token = login.json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}
    agent = client.post(
        f"/gateway/organizations/{org_id}/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers,
    )
    assert agent.status_code == 200
    adapter = client.post(
        f"/gateway/organizations/{org_id}/adapters",
        json={"adapter_id": "payment.simulator", "adapter_version": "1.0.0"},
        headers=headers,
    )
    assert adapter.status_code == 200
    return headers


def _propose(client, headers, *, org_id="acme", idempotency_key="idem-1", amount=50000):
    return client.post(
        f"/gateway/organizations/{org_id}/refunds/propose",
        json={
            "agent_id": "refund-agent-1",
            "requested_by": "customer-1",
            "beneficiary": "customer-acct-1",
            "amount_minor_units": amount,
            "reference": idempotency_key,
            "idempotency_key": idempotency_key,
        },
        headers=headers,
    )


def _approve_to_quorum(client, headers, manifest_id, *, org_id="acme", body=None):
    response = client.post(
        f"/gateway/organizations/{org_id}/refunds/{manifest_id}/approve",
        json=body or {},
        headers=headers,
    )
    assert response.status_code == 200
    return _approve_to_quorum_from_partial(
        client,
        headers,
        manifest_id,
        response,
        org_id=org_id,
        body=body,
    )


def _approve_to_quorum_from_partial(
    client,
    headers,
    manifest_id,
    response,
    *,
    org_id="acme",
    body=None,
):
    index = 1
    while not response.json()["authorized"]:
        email = f"approver-{index}-{manifest_id[:8]}@example.com"
        created = client.post(
            f"/gateway/organizations/{org_id}/users",
            json={
                "user_id": f"{org_id}-approver-{index}-{manifest_id[:8]}",
                "email": email,
                "display_name": f"Approver {index}",
                "password": "approval-password",
                "role": "member",
            },
            headers=headers,
        )
        assert created.status_code == 200
        token = client.post(
            "/gateway/auth/login",
            json={
                "org_id": org_id,
                "email": email,
                "password": "approval-password",
            },
        ).json()["session_token"]
        response = client.post(
            f"/gateway/organizations/{org_id}/refunds/{manifest_id}/approve",
            json=body or {},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        index += 1
    return response


def test_proposal_fails_closed_until_agent_and_adapter_are_registered(dev_client):
    client, _app = dev_client
    client.post(
        "/gateway/organizations",
        json={
            "org_id": "unregistered",
            "name": "Unregistered Corp",
            "owner_email": "owner@unregistered.example",
            "owner_display_name": "Owner",
            "owner_password": "hunter2",
        },
    )
    token = client.post(
        "/gateway/auth/login",
        json={
            "org_id": "unregistered",
            "email": "owner@unregistered.example",
            "password": "hunter2",
        },
    ).json()["session_token"]
    headers = {"Authorization": f"Bearer {token}"}

    missing_agent = _propose(client, headers, org_id="unregistered")
    assert missing_agent.status_code == 409
    assert "agent" in missing_agent.json()["detail"]

    client.post(
        "/gateway/organizations/unregistered/agents",
        json={"agent_id": "refund-agent-1", "display_name": "Refund Agent"},
        headers=headers,
    )
    missing_adapter = _propose(client, headers, org_id="unregistered")
    assert missing_adapter.status_code == 409
    assert "adapter" in missing_adapter.json()["detail"]


def test_distinct_authenticated_users_are_required_to_complete_quorum(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-quorum").json()["manifest_id"]

    first = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/approve",
        json={},
        headers=headers,
    )
    assert first.status_code == 200
    assert first.json()["authorized"] is False
    assert first.json()["grant_id"] is None
    assert first.json()["completed_human_approvals"] == 1
    assert first.json()["required_human_approvals"] > 1

    duplicate = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/approve",
        json={},
        headers=headers,
    )
    assert duplicate.status_code == 409
    assert "already approved" in duplicate.json()["detail"]

    final = _approve_to_quorum_from_partial(client, headers, manifest_id, first)
    assert final.json()["authorized"] is True
    assert final.json()["grant_id"]

    detail = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}",
        headers=headers,
    ).json()
    assert (
        detail["policy_decision"]["completed_human_approvals"]
        == detail["policy_decision"]["required_human_approvals"]
    )


def test_ambiguous_timeout_injection_uses_real_simulator_and_recovers(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-ambiguous").json()["manifest_id"]
    grant_id = _approve_to_quorum(client, headers, manifest_id).json()["grant_id"]

    armed = client.post(
        "/gateway/organizations/acme/evaluation/payment-simulator/ambiguous-next",
        headers=headers,
    )
    assert armed.status_code == 200
    assert armed.json() == {"armed": True}

    execute = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is False
    assert "ambiguous" in execute.json()["detail"]

    recover = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/recover",
        headers=headers,
    )
    assert recover.status_code == 200
    assert recover.json()["matched_expected"] is True


def test_full_refund_journey_happy_path(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)

    propose = _propose(client, headers)
    assert propose.status_code == 200
    manifest_id = propose.json()["manifest_id"]
    assert propose.json()["assessment"]["score"] >= 0

    approve = _approve_to_quorum(client, headers, manifest_id)
    assert approve.status_code == 200
    grant_id = approve.json()["grant_id"]

    execute = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is True

    verify = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/verify", headers=headers
    )
    assert verify.status_code == 200
    assert verify.json()["matched_expected"] is True

    passport_v1 = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport", headers=headers
    )
    assert passport_v1.status_code == 200
    assert passport_v1.json()["lifecycle_state"] == "verified"

    passport_v2 = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"version": "v2"},
        headers=headers,
    )
    assert passport_v2.status_code == 200
    assert passport_v2.json()["outcome_status"] == "verified_match"

    audit = client.get("/gateway/organizations/acme/audit", headers=headers)
    assert audit.status_code == 200
    assert len(audit.json()["events"]) > 0

    audit_scoped = client.get(
        "/gateway/organizations/acme/audit",
        params={"manifest_id": manifest_id},
        headers=headers,
    )
    assert all(e["manifest_id"] == manifest_id for e in audit_scoped.json()["events"])

    audit_verify = client.get("/gateway/organizations/acme/audit/verify", headers=headers)
    assert audit_verify.status_code == 200
    assert audit_verify.json()["verified"] is True


def test_evidence_pack_offline_verification(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-evpack").json()["manifest_id"]
    grant_id = _approve_to_quorum(client, headers, manifest_id).json()["grant_id"]
    client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )
    client.post(f"/gateway/organizations/acme/refunds/{manifest_id}/verify", headers=headers)

    pack_response = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/evidence-pack", headers=headers
    )
    assert pack_response.status_code == 200
    pack = pack_response.json()
    assert pack["manifest_id"] == manifest_id

    # Fully offline, deliberately unauthenticated: no headers passed here.
    verify_response = client.post("/evidence-pack/verify", json=pack)
    assert verify_response.status_code == 200
    result = verify_response.json()
    assert result["all_verified"] is True
    assert result["reasons"] == []


def test_policy_activation_binds_grant(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)

    policy = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "default-policy"},
        headers=headers,
    )
    assert policy.status_code == 200
    bundle_hash = policy.json()["bundle_hash"]

    manifest_id = _propose(client, headers, idempotency_key="idem-policy").json()["manifest_id"]
    approve = _approve_to_quorum(client, headers, manifest_id)
    assert approve.json()["policy_bundle_hash"] == bundle_hash

    execute = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": approve.json()["grant_id"]},
        headers=headers,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is True


def test_member_cannot_activate_policy(dev_client):
    """RA-005: since RA-003 made the active policy actually govern
    assessment, a non-owner member activating a lenient policy would let
    them weaken risk scoring for their own refund proposals. Only the
    owner may activate a policy."""
    client, _app = dev_client
    owner_headers = _bootstrap_and_login(client)
    created = client.post(
        "/gateway/organizations/acme/users",
        json={
            "user_id": "bob",
            "email": "bob@acme.com",
            "display_name": "Bob",
            "password": "password123",
            "role": "member",
        },
        headers=owner_headers,
    )
    assert created.status_code == 200
    member_token = client.post(
        "/gateway/auth/login",
        json={"org_id": "acme", "email": "bob@acme.com", "password": "password123"},
    ).json()["session_token"]
    member_headers = {"Authorization": f"Bearer {member_token}"}

    resp = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "member-lenient", "block_threshold": 100, "review_threshold": 99},
        headers=member_headers,
    )
    assert resp.status_code == 403

    owner_resp = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "owner-policy"},
        headers=owner_headers,
    )
    assert owner_resp.status_code == 200


def test_approval_binds_to_the_policy_active_at_proposal_time_not_approval_time(dev_client):
    """Policy-binding timing regression (found by the independent
    post-remediation audit): approving a refund must bind the grant to
    whatever policy actually produced its risk assessment at proposal
    time, not whatever policy happens to be active when it is approved.
    Otherwise approvers approve against one assessment while the grant
    silently binds to a different policy that never scored this
    manifest."""
    client, _app = dev_client
    headers = _bootstrap_and_login(client)

    policy_a = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "policy-a", "block_threshold": 95, "review_threshold": 90},
        headers=headers,
    )
    assert policy_a.status_code == 200
    bundle_hash_a = policy_a.json()["bundle_hash"]

    propose = _propose(client, headers, idempotency_key="idem-policy-timing")
    assert propose.status_code == 200
    assert propose.json()["assessment"]["policy_id"] == "policy-a"

    # Switch the org's active policy *after* proposal, *before* approval.
    policy_b = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "policy-b", "block_threshold": 10, "review_threshold": 5},
        headers=headers,
    )
    assert policy_b.status_code == 200
    bundle_hash_b = policy_b.json()["bundle_hash"]
    assert bundle_hash_b != bundle_hash_a

    manifest_id = propose.json()["manifest_id"]
    approve = _approve_to_quorum(client, headers, manifest_id)
    assert approve.json()["authorized"] is True
    # Must bind to policy-a (the one that scored the assessment shown to
    # approvers), never policy-b (merely active now).
    assert approve.json()["policy_bundle_hash"] == bundle_hash_a
    assert approve.json()["policy_bundle_hash"] != bundle_hash_b

    # Switching the active policy again before execute must not break a
    # grant that is legitimately bound to a bundle still on file.
    client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "policy-c"},
        headers=headers,
    )
    execute = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": approve.json()["grant_id"]},
        headers=headers,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is True


def test_explicit_policy_bundle_override_at_approval_still_works(dev_client):
    """The explicit `policy_bundle_id` override on approve must still take
    priority over the proposal-time snapshot -- this is an intentional,
    caller-requested exception, not the buggy default."""
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "policy-a"},
        headers=headers,
    )
    propose = _propose(client, headers, idempotency_key="idem-policy-override")
    manifest_id = propose.json()["manifest_id"]
    policy_b = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "policy-b"},
        headers=headers,
    )
    bundle_hash_b = policy_b.json()["bundle_hash"]

    approve = _approve_to_quorum(
        client, headers, manifest_id, body={"policy_bundle_id": "policy-b"}
    )
    assert approve.json()["policy_bundle_hash"] == bundle_hash_b


def test_duplicate_execute_retry_is_prevented(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-dup").json()["manifest_id"]
    grant_id = _approve_to_quorum(client, headers, manifest_id).json()["grant_id"]

    first = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )
    assert first.status_code == 200

    second = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )
    assert second.status_code == 409


def test_grant_for_one_refund_cannot_execute_a_different_refund(dev_client):
    """The essence of 'modified amount or recipient blocked': a grant is
    only ever valid for the one exact sealed manifest it was issued
    against (invariant #2)."""
    client, _app = dev_client
    headers = _bootstrap_and_login(client)

    manifest_a = _propose(client, headers, idempotency_key="idem-a", amount=50000).json()[
        "manifest_id"
    ]
    manifest_b = _propose(client, headers, idempotency_key="idem-b", amount=999999).json()[
        "manifest_id"
    ]
    grant_a = _approve_to_quorum(client, headers, manifest_a).json()["grant_id"]

    # Attempt to execute refund B (a different amount) using refund A's grant.
    cross = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_b}/execute",
        json={"grant_id": grant_a},
        headers=headers,
    )
    assert cross.status_code == 409


def test_compensation_is_a_separate_authorized_effect(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-comp").json()["manifest_id"]
    grant_id = _approve_to_quorum(client, headers, manifest_id).json()["grant_id"]
    client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )

    compensate = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/compensate", json={}, headers=headers
    )
    assert compensate.status_code == 200
    body = compensate.json()
    assert body["compensation_manifest_id"] != manifest_id
    assert body["attempted"] is True
    # The payment simulator honestly refuses to reverse a settled transfer --
    # never silently upgraded to "succeeded".
    assert body["succeeded"] is False


def test_compensation_requires_the_caller_to_have_approved_the_original_refund(dev_client):
    """RA-008 regression: before this fix, any authenticated org member --
    not just someone who had any part in authorizing the original refund
    -- could single-handedly compensate (reverse) a committed refund."""
    client, _app = dev_client
    owner_headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers=owner_headers, idempotency_key="idem-comp-auth").json()[
        "manifest_id"
    ]
    grant_id = _approve_to_quorum(client, owner_headers, manifest_id).json()["grant_id"]
    client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=owner_headers,
    )

    created = client.post(
        "/gateway/organizations/acme/users",
        json={
            "user_id": "outsider",
            "email": "outsider@acme.com",
            "display_name": "Outsider",
            "password": "password123",
            "role": "member",
        },
        headers=owner_headers,
    )
    assert created.status_code == 200
    outsider_token = client.post(
        "/gateway/auth/login",
        json={"org_id": "acme", "email": "outsider@acme.com", "password": "password123"},
    ).json()["session_token"]
    outsider_headers = {"Authorization": f"Bearer {outsider_token}"}

    denied = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/compensate",
        json={},
        headers=outsider_headers,
    )
    assert denied.status_code == 403

    allowed = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/compensate",
        json={},
        headers=owner_headers,
    )
    assert allowed.status_code == 200


def test_ambiguous_outcome_recovered_honestly(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-ambiguous").json()["manifest_id"]
    grant_id = _approve_to_quorum(client, headers, manifest_id).json()["grant_id"]

    org_state = _app.state.karmasakshi_gateway.control_plane.get_state("acme")
    org_state.adapters["payment.simulator"].simulator.inject_ambiguous_timeout()

    execute = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is False
    assert "ambiguous" in execute.json()["detail"].lower()

    recover = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/recover", headers=headers
    )
    assert recover.status_code == 200
    # The simulator did settle the payment internally despite the raised
    # TimeoutError; recovery re-observes and finds it, rather than blindly
    # retrying or blindly declaring failure.
    assert recover.json()["matched_expected"] is True

    # RA-004 cross-surface regression: lifecycle, the Gateway read model,
    # and Action Passport V2 must all agree on what actually happened --
    # none of them may still say "failed" now that recovery has
    # independently confirmed the effect succeeded.
    detail = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}", headers=headers
    ).json()
    assert detail["lifecycle_state"] == "recovered_committed"
    assert detail["verification_status"] == "verified_match"
    assert detail["verification_matched_expected"] is True
    assert detail["ambiguous"] is False

    passport_v2 = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"version": "v2"},
        headers=headers,
    ).json()
    assert passport_v2["outcome_status"] == "verified_match"
    assert passport_v2["lifecycle_state"] == "recovered_committed"


def test_ambiguous_outcome_with_no_evidence_stays_honestly_failed(dev_client):
    """The other half of RA-004: when recovery finds *no* evidence, the
    lifecycle must correctly stay FAILED (never silently upgraded), and
    every surface must agree on that too."""
    client, app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-ambiguous-no-evidence").json()[
        "manifest_id"
    ]
    grant_id = _approve_to_quorum(client, headers, manifest_id).json()["grant_id"]

    org_state = app.state.karmasakshi_gateway.control_plane.get_state("acme")
    org_state.adapters["payment.simulator"].simulator.inject_ambiguous_timeout()

    execute = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )
    assert execute.status_code == 200
    assert execute.json()["success"] is False

    # Wipe the simulator's internal record before recovering, so
    # re-observation genuinely finds no evidence either way.
    payment_record_store = org_state.adapters["payment.simulator"].simulator._payments
    payment_record_store.clear()

    recover = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/recover", headers=headers
    )
    assert recover.status_code == 200
    assert recover.json()["matched_expected"] is False

    detail = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}", headers=headers
    ).json()
    assert detail["lifecycle_state"] == "failed"
    assert detail["verification_status"] == "verified_mismatch"

    passport_v2 = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"version": "v2"},
        headers=headers,
    ).json()
    assert passport_v2["outcome_status"] == "verified_mismatch"
    assert passport_v2["lifecycle_state"] == "failed"


def test_cross_tenant_access_rejected_on_every_org_scoped_endpoint(dev_client):
    client, _app = dev_client
    headers_a = _bootstrap_and_login(client, org_id="acme", email="alice@acme.com")
    headers_b = _bootstrap_and_login(
        client, org_id="beta", email="bob@beta.com", password="password123"
    )

    manifest_id = _propose(client, headers_a, idempotency_key="idem-cross").json()["manifest_id"]

    assert (
        client.get(
            f"/gateway/organizations/acme/refunds/{manifest_id}/passport", headers=headers_b
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/gateway/organizations/acme/refunds/{manifest_id}/approve",
            json={},
            headers=headers_b,
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/gateway/organizations/acme/refunds/{manifest_id}/evidence-pack", headers=headers_b
        ).status_code
        == 403
    )
    assert client.get("/gateway/organizations/acme/audit", headers=headers_b).status_code == 403
    assert (
        client.get("/gateway/organizations/acme/audit/verify", headers=headers_b).status_code == 403
    )
    assert (
        client.post(
            "/gateway/organizations/acme/policy",
            json={"bundle_id": "sneaky"},
            headers=headers_b,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
            json={"grant_id": "whatever"},
            headers=headers_b,
        ).status_code
        == 403
    )


def test_propose_unknown_manifest_lookups_404(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    assert (
        client.get(
            "/gateway/organizations/acme/refunds/does-not-exist/passport", headers=headers
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/gateway/organizations/acme/refunds/does-not-exist/approve",
            json={},
            headers=headers,
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/gateway/organizations/acme/refunds/does-not-exist/execute",
            json={"grant_id": "x"},
            headers=headers,
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/gateway/organizations/acme/refunds/does-not-exist/verify", headers=headers
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/gateway/organizations/acme/refunds/does-not-exist/recover", headers=headers
        ).status_code
        == 404
    )


def test_approve_with_unknown_policy_bundle_404s(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-badpolicy").json()["manifest_id"]
    resp = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/approve",
        json={"policy_bundle_id": "no-such-bundle"},
        headers=headers,
    )
    assert resp.status_code == 404


def test_propose_rejects_unsafe_principal_ids(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    resp = client.post(
        "/gateway/organizations/acme/refunds/propose",
        json={
            "agent_id": "not a safe id!",
            "requested_by": "customer-1",
            "beneficiary": "customer-acct-1",
            "amount_minor_units": 1000,
            "reference": "r1",
            "idempotency_key": "idem-unsafe",
        },
        headers=headers,
    )
    assert resp.status_code == 422


def test_all_endpoints_require_a_gateway_session(dev_client):
    client, _app = dev_client
    _bootstrap_and_login(client)
    resp = client.get("/gateway/organizations/acme/audit")
    assert resp.status_code == 401


def test_passport_markdown_and_html_formats(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-fmt").json()["manifest_id"]
    grant_id = _approve_to_quorum(client, headers, manifest_id).json()["grant_id"]
    client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/execute",
        json={"grant_id": grant_id},
        headers=headers,
    )

    md = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"fmt": "markdown"},
        headers=headers,
    )
    assert md.status_code == 200
    assert manifest_id in md.text

    html = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"fmt": "html"},
        headers=headers,
    )
    assert html.status_code == 200
    assert "<pre>" in html.text or "<html" in html.text.lower() or manifest_id in html.text

    md_v2 = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"fmt": "markdown", "version": "v2"},
        headers=headers,
    )
    assert md_v2.status_code == 200

    html_v2 = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"fmt": "html", "version": "v2"},
        headers=headers,
    )
    assert html_v2.status_code == 200

    bad_version = client.get(
        f"/gateway/organizations/acme/refunds/{manifest_id}/passport",
        params={"version": "v9"},
        headers=headers,
    )
    assert bad_version.status_code == 400


def test_evidence_pack_unknown_manifest_404s(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    resp = client.get(
        "/gateway/organizations/acme/refunds/does-not-exist/evidence-pack", headers=headers
    )
    assert resp.status_code == 404


def test_compensate_without_prior_execute_404s(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-comp-404").json()["manifest_id"]
    resp = client.post(
        f"/gateway/organizations/acme/refunds/{manifest_id}/compensate", json={}, headers=headers
    )
    assert resp.status_code == 404


def test_verify_without_prior_execute_404s(dev_client):
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    manifest_id = _propose(client, headers, idempotency_key="idem-verify-404").json()["manifest_id"]
    resp = client.post(f"/gateway/organizations/acme/refunds/{manifest_id}/verify", headers=headers)
    assert resp.status_code == 404


# --- RA-003: activated policy must actually govern assessment -------------------


def test_activated_policy_changes_the_assessment_not_just_the_grant_binding(dev_client):
    """RA-003 exact regression: before this fix, `propose` always scored
    against the engine's default policy and only looked the active bundle
    up later, for grant binding. A caller could activate a much stricter
    (or laxer) policy and see zero effect on the assessment/recommendation
    a refund actually receives at proposal time."""
    client, _app = dev_client
    headers = _bootstrap_and_login(client)

    # Exact reproduction from RELEASE_AUDIT.md RA-003: this shape of refund
    # scores 87 under the default policy (block_threshold=85), so the
    # default (unactivated) baseline recommends BLOCK.
    baseline = _propose(client, headers, idempotency_key="idem-ra003-baseline")
    assert baseline.status_code == 200
    baseline_assessment = baseline.json()["assessment"]
    assert baseline_assessment["policy_id"] == "default"
    assert baseline_assessment["score"] == 87
    assert baseline_assessment["recommendation"] == "block"

    # Activating a *lenient* policy (thresholds above 87) must change the
    # very next proposal's assessment, not just later grant binding.
    activate = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "lenient-policy", "block_threshold": 95, "review_threshold": 90},
        headers=headers,
    )
    assert activate.status_code == 200

    lenient = _propose(client, headers, idempotency_key="idem-ra003-lenient")
    assert lenient.status_code == 200
    lenient_assessment = lenient.json()["assessment"]
    # The exact same shape of refund, scored under the newly activated
    # policy, must reflect that policy's identity and its (much higher)
    # thresholds -- not silently reuse the engine default that would have
    # blocked it.
    assert lenient_assessment["policy_id"] == "lenient-policy"
    assert lenient_assessment["score"] == 87
    assert lenient_assessment["recommendation"] == "allow"


def test_no_activated_policy_still_uses_the_engine_default(dev_client):
    """Backward compatibility: an organization that never calls
    POST .../policy must keep getting the previous (default-policy)
    assessment behavior unchanged."""
    client, _app = dev_client
    headers = _bootstrap_and_login(client)
    resp = _propose(client, headers, idempotency_key="idem-ra003-no-policy")
    assert resp.status_code == 200
    assert resp.json()["assessment"]["policy_id"] == "default"


def test_propose_fails_closed_if_active_policy_bundle_is_tampered(dev_client):
    """A tampered/corrupted active bundle must never be silently ignored
    in favor of the default policy -- that would defeat the point of
    fixing RA-003. It must fail closed instead."""
    client, app = dev_client
    headers = _bootstrap_and_login(client)
    activate = client.post(
        "/gateway/organizations/acme/policy",
        json={"bundle_id": "tamper-me"},
        headers=headers,
    )
    assert activate.status_code == 200

    gateway_state = app.state.karmasakshi_gateway
    runtime = gateway_state.control_plane.get_state("acme")
    sealed_bundle = runtime.policy_bundles["tamper-me"]
    tampered_bundle = sealed_bundle.bundle.model_copy(update={"bundle_version": "2.0"})
    runtime.policy_bundles["tamper-me"] = sealed_bundle.model_copy(
        update={"bundle": tampered_bundle}
    )

    resp = _propose(client, headers, idempotency_key="idem-ra003-tampered")
    assert resp.status_code == 409
