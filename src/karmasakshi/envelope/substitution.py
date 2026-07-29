"""Deterministic parameter substitution under a Decision Envelope.

Given a sealed (or at least well-formed) envelope and a partial choice of
parameter values, produce the exact parameter dict a concrete
``EffectManifest`` must carry. Exact constraints are filled automatically;
enum/range constraints require an explicit choice. The result is sorted by
key for stable canonicalization.

This is pure library logic in Phase 6: it does not itself prepare or seal a
manifest. Callers that want "authorize an envelope, pick concrete values
later, then execute" still need a later execution-wiring phase; substitution
exists here so that wiring cannot invent its own non-deterministic rules.
"""

from __future__ import annotations

from karmasakshi.domain.manifest import ParameterValue
from karmasakshi.envelope.constraints import ParameterConstraint
from karmasakshi.envelope.model import DecisionEnvelope
from karmasakshi.errors import DecisionEnvelopeConstraintError, DecisionEnvelopeSubstitutionError


def substitute_parameters(
    envelope: DecisionEnvelope,
    choices: dict[str, ParameterValue],
) -> dict[str, ParameterValue]:
    """Resolve ``choices`` against ``envelope`` into a complete parameter dict.

    Rules (fail closed):

    1. Every key in ``choices`` must be a constrained parameter name.
    2. Every non-``exact`` constraint requires an explicit choice.
    3. ``exact`` constraints ignore caller choices that disagree and always
       emit the sealed exact value (a disagreeing choice is rejected, not
       silently overridden -- fail closed on conflict).
    4. Every emitted value must ``accepts()`` under its constraint.
    5. Result keys are sorted lexicographically.
    """
    constrained = envelope.parameter_constraints
    unknown = sorted(set(choices) - set(constrained))
    if unknown:
        raise DecisionEnvelopeSubstitutionError(
            f"substitution choices reference unconstrained parameters: {unknown}"
        )

    resolved: dict[str, ParameterValue] = {}
    for key in sorted(constrained):
        constraint = constrained[key]
        if constraint.kind == "exact":
            if key in choices and choices[key] != constraint.exact_value:
                raise DecisionEnvelopeSubstitutionError(
                    f"parameter {key!r}: choice {choices[key]!r} conflicts with "
                    f"exact constraint {constraint.exact_value!r}"
                )
            value: ParameterValue = constraint.exact_value
        else:
            if key not in choices:
                raise DecisionEnvelopeSubstitutionError(
                    f"parameter {key!r}: constraint kind {constraint.kind!r} "
                    "requires an explicit substitution choice"
                )
            value = choices[key]
        try:
            constraint.accepts(value)
        except DecisionEnvelopeConstraintError as exc:
            raise DecisionEnvelopeSubstitutionError(
                f"parameter {key!r}: substituted value rejected ({exc})"
            ) from exc
        resolved[key] = value
    return resolved


def default_exact_parameters(envelope: DecisionEnvelope) -> dict[str, ParameterValue]:
    """Return only the exact-constrained parameters (no choices required)."""
    return {
        key: constraint.exact_value
        for key, constraint in sorted(envelope.parameter_constraints.items())
        if constraint.kind == "exact"
    }


def missing_substitution_keys(
    envelope: DecisionEnvelope, choices: dict[str, ParameterValue]
) -> tuple[str, ...]:
    """Names of non-exact constraints still lacking a choice."""
    missing = [
        key
        for key, constraint in envelope.parameter_constraints.items()
        if constraint.kind != "exact" and key not in choices
    ]
    return tuple(sorted(missing))


def is_fully_exact(envelope: DecisionEnvelope) -> bool:
    """True when every constraint is ``exact`` -- substitution needs no choices."""
    return all(c.kind == "exact" for c in envelope.parameter_constraints.values())


def constraint_summary(constraint: ParameterConstraint) -> dict[str, object]:
    """Stable, JSON-friendly summary for audit/API surfaces."""
    data: dict[str, object] = {"kind": constraint.kind}
    if constraint.kind == "exact":
        data["exact_value"] = constraint.exact_value
    elif constraint.kind == "enum":
        data["allowed_values"] = list(constraint.allowed_values or ())
    elif constraint.kind == "integer_range":
        data["min_int"] = constraint.min_int
        data["max_int"] = constraint.max_int
    elif constraint.kind == "monetary_range":
        data["currency"] = constraint.currency
        data["min_minor_units"] = (
            constraint.min_amount.minor_units if constraint.min_amount else None
        )
        data["max_minor_units"] = (
            constraint.max_amount.minor_units if constraint.max_amount else None
        )
    return data


__all__ = [
    "constraint_summary",
    "default_exact_parameters",
    "is_fully_exact",
    "missing_substitution_keys",
    "substitute_parameters",
]
