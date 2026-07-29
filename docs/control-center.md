# KarmaSakshi Control Center

The Control Center is the authenticated, server-rendered Milestone A UI
for the AI-operated refund journey. It is mounted at
`/control-center/` in the existing FastAPI application.

It is not a mock dashboard. Every page and action calls the typed
`AsyncGatewayClient`, through an in-process ASGI transport, and therefore
traverses the same Gateway HTTP endpoints, session authentication,
organization isolation, protocol engine, payment simulator, lifecycle
store, and audit journal as a remote SDK client.

## Product surface

- Overview dashboard with pending, verified, ambiguous-outcome, and audit
  integrity counts.
- Approval inbox containing only the authenticated organization's
  pending sealed refunds.
- Exact manifest-bound before and expected-after source balance and
  beneficiary credit.
- Structured risk score, level, signals, deterministic explanation,
  policy recommendation, and approval/verification requirements.
- Approve and deny actions. The acting identity always comes from the
  server-side Gateway session, never a hidden form field.
- Assessment-required human quorum: distinct authenticated organization
  users create signed approval statements; a partial set remains pending,
  and only a satisfied set issues a quorum-bound execution grant.
- Commit, independent verify, and ambiguous-outcome recovery actions
  against the real payment simulator lifecycle.
- Per-effect audit timeline.
- Action Passport V2 viewer with seal, grant, audit-chain, outcome, and
  full JSON record.
- Organization-scoped searchable audit explorer.

## Run locally

Install the API extra and start the existing application:

```bash
pip install -e ".[api]"
KARMASAKSHI_API_DEV_MODE=1 uvicorn karmasakshi.api.app:create_app --factory
```

Bootstrap an organization through the platform-authenticated Gateway API,
then visit `http://127.0.0.1:8000/control-center/login` and sign in with
that organization's owner credentials. Organization bootstrap remains a
platform operation; the Control Center never creates organizations or
silently supplies development credentials.

## Browser security

- The Gateway bearer session is stored in an `HttpOnly`,
  `SameSite=Strict` cookie scoped to `/control-center`. It is never
  written to HTML, browser storage, or page JavaScript.
- HTTPS requests receive a `Secure` session cookie. Local HTTP evaluation
  remains usable without weakening the setting for HTTPS deployments.
- Every state-changing form requires an HMAC-derived CSRF token bound to
  the live session. Missing or modified tokens fail with `403` before any
  Gateway action.
- Logout revokes the exact server session and clears the browser cookie.
- Authenticated HTML responses are `Cache-Control: no-store` and include
  a restrictive CSP, frame denial, content-type protection, and a
  no-referrer policy.
- The UI does not accept an organization identifier on authenticated
  routes. It derives `org_id` from `/gateway/auth/me`, and every SDK call
  is still checked by `resolve_org_runtime`.
- A session for organization A receives a generic not-found response for
  organization B's refund identifier and cannot search B's audit events.
- Gateway errors are mapped to bounded, buyer-readable UI errors. Raw
  exceptions, credentials, and cross-tenant details are not rendered.

## Authorization boundary

Milestone A permits any authenticated team member in the same
organization to approve or deny a refund. Authorization is server-side:
the session must be live, must belong to the URL organization, and
supplies the immutable approval principal. One user cannot count twice.
The risk assessment's required human count is sealed into an approval
policy; only distinct signed statements satisfying that count produce a
grant whose `approval_set_hash` binds the counted set.

Role-based decision permissions and named approval groups remain
Milestone B work. The Control Center does not infer those features from
the existing `owner`/`member` role metadata. Approval statements are
signed by the Gateway's organization service key on behalf of the
session-authenticated human; per-user cryptographic keys are not shipped.

## Tests

`tests/integration/test_control_center.py` drives the real browser routes,
Gateway API, async SDK, protocol state, and templates. It covers:

- safe login/session/logout behavior and security headers;
- real overview, approval inbox, before/after, risk, and policy output;
- partial and completed quorum -> execute -> verify -> Action Passport;
- denial and prevention of later approval;
- CSRF rejection without lifecycle mutation;
- audit search and hash-chain status;
- ambiguous timeout visibility and recovery by observation;
- cross-tenant refund and audit non-disclosure.
