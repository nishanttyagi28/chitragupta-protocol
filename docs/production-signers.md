# Production Signer Interfaces (extreme-v2 Phase 16)

Honest abstractions so production hosts can plug HSM/KMS-backed signing
without changing protocol call sites. **No real cloud KMS or HSM is
implemented.**

## Surfaces

| Type | Role |
|---|---|
| `Signer` | Protocol: `key_id`, `algorithm`, `sign`, `verification_key` |
| `LocalDevSigner` | Explicit local-dev wrap of `SigningKey` |
| `EmulatedKmsSigner` | Local Ed25519 behind a fake `kms_key_ref` constructor |
| `require_signer_env` | Fail closed if the env secret is missing |

## Honesty

- Emulated KMS never performs network I/O or imports AWS/GCP SDKs.
- Missing production secrets raise `KeyLoadError` — keys are never invented.
- Existing `SigningKey` remains fully supported and already satisfies `Signer`.
