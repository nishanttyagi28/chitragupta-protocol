# Delegation and Attenuation

A parent grant may delegate a child grant that is narrower than or equal
to itself on every dimension — never wider. This is enforced by
`delegation/attenuation.py` (per-dimension comparison) and
`delegation/chain.py` (full root-to-leaf chain verification).

## Worked examples (from the spec)

```text
Parent:
  refunds up to INR 5,000 for merchant A

Valid child:
  refund up to INR 1,500 for order 421 at merchant A

Invalid child:
  refund up to INR 7,000                    -> ConstraintWideningError (amount)

Invalid child:
  refund INR 1,500 for merchant B           -> ConstraintWideningError (recipients)

Invalid child:
  grant expires after parent                -> ConstraintWideningError (expires_at)
```

All four of these are literal test cases in `tests/unit/test_delegation.py`
and `tests/property/test_delegation_properties.py` (the property tests
generate randomized recipient sets/amounts and confirm the subset/
monotonicity relationship holds in general, not just for these examples).

## Dimensions compared

`ScopeConstraints`: `target_resources`, `recipients`, `max_amount`,
`allowed_fields`, `environments` — each is either an explicit allow-list
(child must be a subset of parent's) or `None` (unrestricted; a child may
narrow `None` to an explicit list, but never widen an explicit parent list
back to `None`).

`ExecutionGrant` itself: `expires_at` (child ≤ parent), `not_before` (child
≥ parent), `max_uses` (child ≤ parent), `audience` (subset), and
`allowed_effect_types` (subset).

## Incomparable constraints fail closed

Comparing a child amount in USD against a parent cap in INR is not
"probably fine" — it's `IncomparableConstraintError`, a distinct exception
from `ConstraintWideningError`, and callers must treat it identically:
reject the delegation. There is no silent "assume compatible" path.

```python
from karmasakshi.delegation import assert_scope_narrower_or_equal
from karmasakshi.domain.common import MonetaryAmount
from karmasakshi.grants.model import ScopeConstraints

parent = ScopeConstraints(max_amount=MonetaryAmount(currency="INR", minor_units=500_000))
child = ScopeConstraints(max_amount=MonetaryAmount(currency="USD", minor_units=100))
assert_scope_narrower_or_equal(child, parent)  # raises IncomparableConstraintError
```

## Multi-hop chains

`delegation.verify_delegation_chain([root, mid, leaf], keyring=..., grant_store=..., now=...)`
verifies, in one call:

1. Every grant in the chain independently verifies (signature + time
   window via `verify_grant`).
2. No grant in the chain is revoked (`grant_store.is_revoked(...)`).
3. `chain[0].parent_grant_id is None` (the chain actually starts at a
   root).
4. For every adjacent pair, `child.parent_grant_id == parent.grant_id`
   (lineage integrity — a grant can't claim a parent it doesn't actually
   narrow from) and `assert_grant_narrower_or_equal(child, parent)`.

## Revocation propagation

`engine.commit()` checks one hop of ancestor revocation automatically: if
`grant.parent_grant_id` is set and that parent grant_id is revoked in the
store, the child is blocked (`GrantRevokedError`) even though the child
itself was never directly revoked. This is deliberately limited to one
hop — the `GrantStore` only tracks revocation by `grant_id`, not full
lineage, so it cannot walk further than the immediate parent without the
caller supplying the full chain. **For a delegation chain deeper than one
hop, call `verify_delegation_chain()` explicitly with the full chain of
grant objects before commit** if you need guaranteed multi-hop revocation
propagation; `engine.commit()` alone does not reconstruct unknown
ancestors.

## `engine.delegate()`

```python
child = engine.delegate(
    parent_grant,
    issuer=human_or_service_principal,  # never the agent
    subject=child_agent_principal,
    signing_key=signing_key,
    scope=narrower_scope,  # omit to inherit parent's exact scope
    expires_at=earlier_or_equal_datetime,  # omit to inherit parent's
    max_uses=narrower_or_equal_int,  # omit to inherit parent's
)
```

Fields left unspecified inherit the parent's exact value (the narrowest
safe default). `delegate()` signs the candidate child first, then checks
attenuation before returning it — if the check fails, the signed object is
simply discarded and never returned to the caller (harmless, since nothing
outside this call ever saw it).
