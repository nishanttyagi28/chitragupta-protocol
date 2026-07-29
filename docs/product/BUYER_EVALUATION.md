# Buyer Evaluation Package

Milestone A is a local evaluation product for one named use case:
an AI-operated customer refund through the payment simulator. It is not
a production payment integration.

## Ten-minute Docker evaluation

Prerequisite: Docker Engine with Compose v2.

```bash
git clone https://github.com/nishanttyagi28/karmasakshi-protocol.git
cd karmasakshi-protocol
docker compose up --detach --build --wait api
docker compose --profile acceptance run --rm acceptance
```

The `acceptance` container waits for the API health check, then drives
the real Gateway HTTP API, typed SDK, and authenticated Control Center.
It prints 25 `PASS` checks and writes a machine-readable report to the
`karmasakshi-data` volume at
`/data/acceptance/milestone-a.json`.

Open `http://127.0.0.1:8000/control-center/login`. The acceptance command
prints its generated organization, owner email, and one-time local
evaluation password; the API remains running for UI review. The API port
is bound to loopback because Compose uses unauthenticated platform
bootstrap mode. When finished, run `docker compose down --volumes`.

## Run against an existing Gateway

```bash
karmasakshi-acceptance \
  --base-url http://127.0.0.1:8000 \
  --report artifacts/milestone-a-acceptance.json
```

For a token-protected platform bootstrap endpoint, also pass
`--platform-token` or set `KARMASAKSHI_API_TOKEN`. Use a fresh `--org-id`
for each run; organization bootstrap is intentionally not destructive.

## What the acceptance command proves

The command creates two isolated organizations and checks:

- explicit durable refund-agent and payment-adapter registration;
- a signed organization policy and exact manifest-bound before/after;
- structured risk output and a distinct-session 3-of-3 human quorum;
- modified-recipient rejection and exactly-once execution;
- independent observation, Action Passport V2, and searchable audit;
- real settle-then-timeout ambiguity followed by observation recovery;
- a separately authorized compensation attempt;
- cross-tenant rejection and offline Evidence Pack verification.

The checked-in sample report is
[`artifacts/milestone-a-acceptance.json`](../../artifacts/milestone-a-acceptance.json).
CI builds the Compose product, reruns the same command, and publishes its
fresh JSON report as a workflow artifact.

## Reproducible real UI media

The screenshots and video under `docs/assets/control-center/` are
captured from a live seeded Gateway with an authenticated Chromium
session:

```bash
pip install playwright
playwright install chromium
python scripts/capture_control_center.py
python scripts/record_control_center_demo.py  # also requires ffmpeg
```

The seed fixture first passes the buyer acceptance command, then creates
one pending and one cleanly verified refund. It does not substitute mock
HTML, hardcoded success, or generated imagery.

## What this package does not claim

- SOC 2, ISO 27001, PCI-DSS, or independent security certification
- production SLAs or production operating history
- SSO, MFA, server-enforced RBAC, shared multi-node sessions, or admin UX
- Stripe, Adyen, SendGrid, KMS/HSM, or any real provider integration

Read [limitations](../limitations.md), the
[security model](../security-model.md), and the
[threat model](../threat-model.md) before evaluating deployment scope.
