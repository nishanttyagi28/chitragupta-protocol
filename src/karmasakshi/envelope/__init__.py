"""Constrained Decision Envelopes and atomic plan authorization (Phase 6)."""

from karmasakshi.envelope.constraints import (
    MAX_CONSTRAINT_KEY_LENGTH,
    MAX_ENUM_VALUES,
    ParameterConstraint,
    assert_constraint_narrower_or_equal,
    enum_of,
    exact,
    integer_range,
    monetary_range,
)
from karmasakshi.envelope.model import (
    ENVELOPE_SCHEMA_VERSION,
    DecisionEnvelope,
    assert_envelope_narrower_or_equal,
    assert_manifest_fits_envelope,
    build_decision_envelope,
)
from karmasakshi.envelope.plan import (
    assert_manifest_in_plan,
    plan_node_count,
    require_matching_plan_hash,
)
from karmasakshi.envelope.sealing import (
    seal_decision_envelope,
    verify_decision_envelope,
)
from karmasakshi.envelope.substitution import (
    is_fully_exact,
    missing_substitution_keys,
    substitute_parameters,
)

__all__ = [
    "ENVELOPE_SCHEMA_VERSION",
    "MAX_CONSTRAINT_KEY_LENGTH",
    "MAX_ENUM_VALUES",
    "DecisionEnvelope",
    "ParameterConstraint",
    "assert_constraint_narrower_or_equal",
    "assert_envelope_narrower_or_equal",
    "assert_manifest_fits_envelope",
    "assert_manifest_in_plan",
    "build_decision_envelope",
    "enum_of",
    "exact",
    "integer_range",
    "is_fully_exact",
    "missing_substitution_keys",
    "monetary_range",
    "plan_node_count",
    "require_matching_plan_hash",
    "seal_decision_envelope",
    "substitute_parameters",
    "verify_decision_envelope",
]
