# Security Model: the 30 Invariants

Each invariant below is implemented in a specific, named location and
verified by at least one named test. This list exists so a reviewer can
check "is invariant N actually enforced, or just asserted in prose" in
under a minute per row.

| # | Invariant | Enforced in | Verified by |
|---|---|---|---|
| 1 | No consequential effect executes without a valid grant | `engine.commit()` requires a grant; every check in `commit()` runs before `adapter.commit()` | `test_engine.py` (whole `commit()` suite), demo scenario 1 |
| 2 | A grant for manifest A cannot execute manifest B | `commit()` checks `grant.manifest_hash == sealed.seal.manifest_hash` | `test_grant_bound_to_different_manifest_is_rejected` |
| 3 | Changing one security-relevant field invalidates the seal | `SealedManifest.verify_integrity()` recomputes the hash | `test_changed_target_after_seal_invalidates_seal`, `test_manifest_hash_changes_with_any_security_field`, property tests |
| 4 | A single-use grant cannot execute more than once | `GrantStore.reserve()`/`.commit()` atomic use-count | `test_single_use_grant_cannot_execute_twice` |
| 5 | Concurrent attempts using the same grant result in at most one commit | Lock-guarded (memory) / `UPDATE...WHERE` (SQLite) / Lua script (Redis) atomic reserve | `test_concurrent_commits_produce_at_most_one_success` (8-thread), `test_store_idempotency_properties.py` |
| 6 | Expired grants fail closed | `verify_grant_time_window()` | `test_expired_grant_is_blocked`, `test_grant_time_properties.py` |
| 7 | Revoked grants fail closed | `GrantStore.is_revoked()` checked in `commit()` | `test_revoked_grant_is_blocked` |
| 8 | A grant cannot be used before its `not_before` | `verify_grant_time_window()` | `test_time_window_boundaries` |
| 9 | Clock-skew policy is explicit, configurable, bounded, tested | `ClockSkewPolicy.leeway_seconds` (≤300s, validated) | `test_clock_skew_leeway_extends_boundaries` |
| 10 | Store outages or indeterminate states fail closed | No `try/except` swallows store exceptions in `commit()` | `test_store_outage_at_revocation_check_fails_closed` |
| 11 | Invalid signatures fail closed | `verify_seal()`/`verify_grant_signature()` called before any effect | `test_forged_seal_signature_with_unchanged_content_is_blocked`, demo scenario 10 |
| 12 | Unknown keys fail closed | `Keyring.get()` raises `UnknownKeyError` | `test_unknown_key_fails_closed`, `test_keyring_unknown_key_fails_closed` |
| 13 | Adapter identity and version are bound to authorization | `commit()` checks `manifest.adapter == (adapter.adapter_id, adapter.adapter_version)` and `adapter.adapter_id in grant.audience` | `test_adapter_identity_mismatch_is_blocked`, `test_adapter_not_in_audience_is_blocked` |
| 14 | External state changes after preparation invalidate the manifest unless safely re-prepared | `adapter.validate_preconditions()` re-checked at commit time (TOCTOU) | `test_stale_manifest_detected_on_precondition_change`, `test_stale_version_detected_as_toctou`, demo scenario 8 |
| 15 | An agent cannot widen its authority through delegation | `assert_grant_narrower_or_equal()` in `engine.delegate()` | `test_engine_delegate_wider_amount_rejected`, demo scenario 6 |
| 16 | A child grant must be ≤ its parent on every security dimension | `delegation/attenuation.py` (all dimensions) | `test_delegation.py`, `test_delegation_properties.py` |
| 17 | A child cannot outlive its parent | `expires_at` comparison in `assert_grant_narrower_or_equal` | `test_grant_expiry_cannot_outlive_parent` |
| 18 | A child cannot increase max uses, monetary limits, resource access, audience, or effect types | Per-dimension checks in `assert_grant_narrower_or_equal`/`assert_scope_narrower_or_equal` | `test_grant_max_uses_cannot_exceed_parent`, `test_wider_amount_rejected`, `test_wider_recipient_rejected` |
| 19 | Duplicate retries remain idempotent | Idempotency ledger keyed by `manifest.idempotency_key`, checked before calling the adapter | `test_idempotent_retry_does_not_recommit`, adapter-level idempotency tests |
| 20 | A successful API response alone is not proof of the intended outcome | `verify()` is a separate step from `commit()`; the payment simulator's ambiguous-timeout mode demonstrates this concretely | `test_ambiguous_timeout_settles_but_reports_failure`, demo scenario 12 |
| 21 | Verification must use independently observed external state whenever possible | Every adapter's `verify()` re-reads its own external system of record, never trusts `commit_result` alone | `test_verify_detects_mismatch_via_independent_outbox_read`, sqlite/payment verify tests |
| 22 | Audit records are append-only and tamper-evident | Hash-chained `AuditJournal`; `previous_hash`/`event_hash` per event | `test_audit_journal.py`, `test_audit_sqlite.py` (direct-file tamper test), demo scenario 11 |
| 23 | Audit failure before a consequential commit blocks execution | `commit()`'s transition-to-`COMMITTING` audit write happens before `adapter.commit()`; failure propagates and releases the reservation | `test_audit_backend_failure_blocks_commit_before_adapter_is_called` |
| 24 | Irreversible actions must never be described as reversible | `EmailSandboxAdapter` always sets `reversibility=IRREVERSIBLE`; `SQLiteRowAdapter` delete is `IRREVERSIBLE` | `test_irreversible_after_send_refuses_compensation`, `test_delete_is_irreversible` |
| 25 | Compensation is best-effort and never described as guaranteed rollback | `CompensationResult.attempted`/`.succeeded` are independent booleans; a settled payment's compensation is `attempted=True, succeeded=False` with an explicit reason | `test_compensation_of_settled_payment_is_honestly_refused` |
| 26 | Revocation cannot undo an already-completed irreversible effect | `engine.revoke()` returns `stopped_at_safepoint=False` past `COMMITTING`; the effect is untouched | `test_revocation_after_commit_does_not_undo_effect` |
| 27 | Mid-flight revocation must stop execution only at defined safe checkpoints | `REVOCABLE_STATES` excludes `COMMITTING` onward | `test_committing_committed_verified_are_not_revocable`, `test_pre_commit_states_are_revocable` |
| 28 | All timestamps use timezone-aware UTC internally | `config/clock.py::ensure_utc()` rejects naive datetimes everywhere they're accepted | `test_manifest_rejects_naive_datetime` |
| 29 | Error messages must not leak secrets | `SigningKey.__repr__` redacts private key material; no log statement anywhere serializes a `SigningKey` or raw token | `test_private_key_never_in_repr`, `test_export_contains_no_secrets_or_raw_credentials` |
| 30 | The model or agent must never make the final authorization decision | `issue_grant()`/`engine.authorize()`/`engine.delegate()` raise `GrantIssuerNotAuthorizedError` if `issuer.principal_type == AGENT` | `test_agent_cannot_issue_grant`, `test_agent_cannot_be_the_authorizing_issuer` (LangGraph) |
| 31 | A grant bound to a policy bundle cannot commit against a missing, different, tampered, expired, or unsigned-by-an-untrusted-key policy bundle | `engine.commit()`'s `policy_bundle_hash` check (only enforced when the grant declares one; see [docs/policy-bundles.md](policy-bundles.md)) | `test_commit_missing_required_policy_bundle_is_rejected`, `test_commit_with_swapped_policy_bundle_is_rejected`, `test_commit_with_tampered_policy_bundle_is_rejected`, `tests/adversarial/test_policy_bundle_gaming.py` |
| 32 | An agent principal cannot be the issuer of a signed policy bundle | `build_policy_bundle()` raises `PolicyBundleIssuerNotAuthorizedError` if `issuer.principal_type == AGENT` | `test_agent_cannot_be_policy_bundle_issuer` |

## What this table does not claim

Passing these tests demonstrates that the stated behavior holds under the
scenarios exercised. It is not a formal proof, a fuzzed exhaustive search
of the state space, or a third-party security audit — see
[docs/limitations.md](limitations.md) and [docs/threat-model.md](threat-model.md).
