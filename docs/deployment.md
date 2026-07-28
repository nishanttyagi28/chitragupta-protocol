# Deployment

## Scope

This covers running the CLI and the optional FastAPI control plane
locally or in a container. It does not cover multi-region deployment,
autoscaling, or a managed-service offering — none of that exists for this
project.

## Package installation

```bash
pip install chitragupta-protocol            # core (CLI, engine, adapters)
pip install chitragupta-protocol[api]       # + FastAPI control plane + console
pip install chitragupta-protocol[redis]     # + distributed grant store
pip install chitragupta-protocol[langgraph] # + LangGraph integration
pip install chitragupta-protocol[all]       # everything
```

## Configuration

Environment variables:

| Variable | Purpose |
|---|---|
| `CHITRAGUPTA_HOME` | Override the CLI's default `.chitragupta` workspace path |
| `CHITRAGUPTA_API_DEV_MODE` | Set to `1` to disable API/console authentication for **local development only** |
| `CHITRAGUPTA_API_TOKEN` | Bearer token required for API/console access outside dev mode |
| `CHITRAGUPTA_PUBLIC_DEMO` | Set to `1` to mount the safe, unauthenticated `/demo/*` sandbox (see below). Refuses to start if combined with `CHITRAGUPTA_API_DEV_MODE=1`. |
| `CHITRAGUPTA_DEMO_TTL_SECONDS` | How long the shared public-demo sandbox lives before auto-resetting (default `900` = 15 minutes) |
| `CHITRAGUPTA_DEMO_RATE_LIMIT_PER_MINUTE` | Per-IP request cap on `/demo/*` routes (default `30`) |
| `REDIS_URL` | Used by the Redis grant-store test suite to locate a test instance; not read by production code (pass a `redis.Redis` client directly to `RedisGrantStore`) |

See `.env.example` for a template with no real secrets.

## Public sandbox demo mode

`CHITRAGUPTA_PUBLIC_DEMO=1` mounts an additional, entirely separate router
at `/demo/*` (see `chitragupta.web.demo_router`) meant to be safe to expose
to anonymous internet traffic:

- Uses only the SQLite/email/payment **simulators** — no real email is
  sent, no real money moves, no arbitrary SQL is ever accepted.
- Operates on its own isolated, in-memory `DemoSession` (never `ApiState`)
  that auto-resets on a timer (`CHITRAGUPTA_DEMO_TTL_SECONDS`) and can be
  reset on demand from the UI.
- Every `/demo/*` route is rate-limited per client IP
  (`CHITRAGUPTA_DEMO_RATE_LIMIT_PER_MINUTE`).
- Never displays real signing key material — only key IDs and public
  verification keys ever appear on any page.
- Disables the interactive API docs (`/docs`, `/redoc`, `/openapi.json`)
  so the admin/kill-switch surface isn't advertised.
- The authenticated control-plane API (`/manifests`, `/kill-switch`, …)
  and console (`/console/*`) are **unaffected** — they remain fail-closed
  exactly as documented above. `create_app()` refuses to start at all if
  `CHITRAGUPTA_PUBLIC_DEMO=1` and `CHITRAGUPTA_API_DEV_MODE=1` are both
  set, so a misconfigured deployment cannot accidentally expose both the
  safe public demo and an unauthenticated admin API at once.

### Deploying the public demo to Render.com

`render.yaml` at the repo root is a ready-to-use
[Render Blueprint](https://render.com/docs/blueprint-spec) that deploys
the existing `Dockerfile` unmodified, in public-demo mode, with a
`/health` health check. To deploy:

1. Sign in to [render.com](https://render.com) (GitHub login works) and
   connect the `nishanttyagi28/chitragupta-protocol` GitHub repository.
2. Click **New > Blueprint**, select the repository and the branch to
   deploy, and Render will detect `render.yaml` automatically.
3. Click **Apply** to create the service. No manual environment variable
   entry is required — `render.yaml` already sets
   `CHITRAGUPTA_PUBLIC_DEMO=1` and leaves `CHITRAGUPTA_API_DEV_MODE`/
   `CHITRAGUPTA_API_TOKEN` unset.
4. Wait for the first build to finish, then open the assigned
   `https://<service-name>.onrender.com` URL and confirm `/health`
   returns `{"status": "ok"}` and `/demo/` renders the sandbox landing
   page.

**Free-tier limitation, stated honestly:** Render's free web service plan
spins the container down after roughly 15 minutes of no incoming
requests, and the next request pays a 30-60 second cold-start cost to
wake it back up. This is expected free-tier behavior for a reference demo,
not a defect — a paid always-on plan (or a different host) removes it.

Any other Dockerfile-compatible host (Fly.io, Railway, a plain VM running
`docker run`, etc.) works the same way: build the existing `Dockerfile`,
set `CHITRAGUPTA_PUBLIC_DEMO=1`, and leave dev-mode/token unset.

## Docker

```bash
docker build -t chitragupta-protocol .
docker run -p 8000:8000 -e CHITRAGUPTA_API_DEV_MODE=1 chitragupta-protocol
```

`docker-compose.yml` brings up the API alongside a Redis instance for
exercising the distributed grant store:

```bash
docker compose up
```

This starts the control plane in dev mode (unauthenticated, local-only —
never use this compose file's default configuration on a network-reachable
host) plus a Redis container. Set `CHITRAGUPTA_API_TOKEN` and remove
`CHITRAGUPTA_API_DEV_MODE` for anything beyond local experimentation.

## Signing keys in production

The dev-mode key generation (`chitragupta key generate`,
`generate_signing_key()`) writes raw Ed25519 private key bytes to a local
file with best-effort restrictive permissions
(`save_signing_key_to_file` — POSIX `chmod 0600`; Windows ACLs are not
specially hardened). This is adequate for local development and the demo
suite. **It is not a production key-management solution.** For real
deployments:

- Load keys via `load_signing_key_from_env()` backed by a proper secret
  manager (not a plain `.env` file committed anywhere), or integrate an
  HSM/KMS-backed signer implementing the same `sign(data: bytes) -> str`
  interface as `SigningKey`.
- Rotate keys using `Keyring.add_key()`/`.remove_key()` — add the new key,
  redeploy signers to use it, then remove the old key once all
  outstanding grants signed with it have expired.
- Never commit private key files to version control (`.gitignore` already
  excludes `*.pem`, `*.priv`, `.env`).

## Storage in production

- Single-node: the SQLite backends (`SQLiteGrantStore`,
  `SQLiteAuditBackend`) are adequate — see
  [docs/storage-semantics.md](storage-semantics.md).
- Multi-node: use `RedisGrantStore` for the grant store; the audit backend
  still needs a durable, ideally append-only-friendly store of your
  choosing implementing the small `AuditBackend` protocol (only two
  backends ship today: in-memory and SQLite).

## What's not provided

- TLS termination (put a reverse proxy in front of the API).
- Log aggregation, metrics, tracing.
- A Kubernetes manifest, Helm chart, or Terraform module.
- Backup/restore tooling for the SQLite files beyond "copy the file."
