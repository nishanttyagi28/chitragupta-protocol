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
| `REDIS_URL` | Used by the Redis grant-store test suite to locate a test instance; not read by production code (pass a `redis.Redis` client directly to `RedisGrantStore`) |

See `.env.example` for a template with no real secrets.

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
