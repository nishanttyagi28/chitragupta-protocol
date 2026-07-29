# KarmaSakshi Gateway SDK

`karmasakshi.sdk` is a typed synchronous and asynchronous Python client
for the [Gateway HTTP API](gateway.md) (commercial Milestone A). Optional
-- requires the `sdk` extra:

```bash
pip install "karmasakshi-protocol[sdk]"
```

(adds `httpx`; everything else in this package has no new dependency.)

## Honest scope statement

This is a client for **the Gateway HTTP API described in
docs/gateway.md** -- organization bootstrap/auth and the refund vertical
slice. It is not a general client for every protocol feature (decision
envelopes, causal graphs, witness quorum, ...); those remain
library-level `karmasakshi.engine`/`karmasakshi.api` surfaces without an
SDK wrapper yet.

## Synchronous usage

```python
from karmasakshi.sdk import GatewayClient

with GatewayClient("http://localhost:8000", platform_token="dev-token") as client:
    client.bootstrap_organization(
        org_id="acme",
        name="Acme Corp",
        owner_email="alice@acme.com",
        owner_display_name="Alice",
        owner_password="a-real-password",
    )
    client.login(org_id="acme", email="alice@acme.com", password="a-real-password")

    proposal = client.propose_refund(
        "acme",
        agent_id="refund-agent-1",
        requested_by="customer-1",
        beneficiary="customer-acct-1",
        amount_minor_units=50_000,
        reference="order-123",
        idempotency_key="idem-order-123",
    )
    pending = client.list_refunds("acme", decision_status="pending")
    exact_effect = client.get_refund("acme", proposal.manifest_id)
    approval = client.approve_refund("acme", proposal.manifest_id)
    execution = client.execute_refund("acme", proposal.manifest_id, grant_id=approval.grant_id)
    verification = client.verify_refund("acme", proposal.manifest_id)

    passport = client.get_passport("acme", proposal.manifest_id, version="v2")
    pack = client.get_evidence_pack("acme", proposal.manifest_id)
    assert client.verify_evidence_pack(pack).all_verified
    client.logout()
```

## Asynchronous usage

Identical surface, `async`/`await` throughout:

```python
from karmasakshi.sdk import AsyncGatewayClient

async with AsyncGatewayClient("http://localhost:8000") as client:
    await client.login(org_id="acme", email="alice@acme.com", password="...")
    proposal = await client.propose_refund("acme", ...)
    ...
```

## Typed responses, reused from the real server-side models

Wherever the Gateway response body already *is* a real, tested pydantic
model (`ActionPassport`, `ActionPassportV2`, `EvidencePack`,
`EvidencePackVerificationResult`, `AuditEvent`, and the org/user models
in `karmasakshi.gateway.schemas`), the SDK parses responses directly into
that same class -- not a hand-maintained duplicate that could drift out
of sync. The Control Center refund read models are shared directly from
`karmasakshi.gateway.refund_schemas`: `RefundSummaryOut`,
`RefundDetailOut`, its exact-effect/risk/policy submodels, and
`RefundDenyResult`. Small action responses remain in
`karmasakshi.sdk.models`: `RefundProposalResult`, `ApprovalResult`,
`ExecutionResult`, `VerificationResult`, `CompensationResult`, and
`PolicyActivationResult`.

## Errors

- `KarmaSakshiApiError(status_code, detail)` -- the Gateway responded
  with a non-2xx status. `detail` is FastAPI's `{"detail": "..."}` body
  when present, otherwise the raw response text.
- `KarmaSakshiConnectionError` -- the Gateway could not be reached at all
  (DNS, connection refused, timeout before any response).
- `KarmaSakshiSdkError` -- a client-side usage error, e.g. calling an
  org-scoped method before `login()` with no `session_token` supplied.

None of these are `karmasakshi.errors.KarmaSakshiError` subclasses: a
non-2xx HTTP response is a fact about a remote call, not a protocol
security decision made in this process.

## Sessions

`login()` stores the returned session token on the client instance
(`client.session_token`) and every subsequent org-scoped call sends it
automatically. Construct a client with `session_token=` directly to
reuse a token obtained elsewhere (e.g. restored from secure storage)
without calling `login()` again. There is no automatic token refresh --
Gateway sessions expire after 12 hours by default (see docs/gateway.md);
call `login()` again once a call fails with `KarmaSakshiApiError(401, ...)`.
`logout()` revokes the active server session and clears
`client.session_token`.

`get_audit()` supports `manifest_id=`, `query=`, `event_type=`, and
`decision=` filters. Filtering is performed by the Gateway after
organization scope is enforced, not by mixing events client-side.

## Known limitations

- One client instance holds at most one session token -- construct a
  separate client per concurrent user/session, the same way you would
  not share one `httpx.Client` across unrelated credentials.
- No automatic retry, backoff, or rate-limit handling. Callers get the
  raw `KarmaSakshiApiError`/`KarmaSakshiConnectionError` and decide.
- No streaming/webhook support -- every call is a single request/response
  round trip.
