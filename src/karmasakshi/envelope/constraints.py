"""Canonical parameter constraints for Decision Envelopes.

A constraint describes the *only* values a single manifest parameter may
take under a sealed authorization envelope. Evaluation is pure and
deterministic: the same constraint + value always yields the same verdict,
and incomparable or unknown shapes fail closed.

See docs/decision-envelopes.md.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.domain.common import MonetaryAmount
from karmasakshi.domain.manifest import ParameterValue
from karmasakshi.errors import (
    DecisionEnvelopeConstraintError,
    IncomparableConstraintError,
)

ConstraintKind = Literal["exact", "enum", "integer_range", "monetary_range"]

MAX_ENUM_VALUES = 64
MAX_CONSTRAINT_KEY_LENGTH = 64


class ParameterConstraint(BaseModel):
    """One named parameter's allowed value space.

    Exactly one shape is active per ``kind``:

    - ``exact``: ``exact_value`` must be set; the parameter must equal it.
    - ``enum``: ``allowed_values`` is a non-empty allow-list.
    - ``integer_range``: ``min_int``/``max_int`` bound an ``int`` parameter
      (inclusive). Either bound may be omitted for an open end.
    - ``monetary_range``: ``min_amount``/``max_amount`` bound a monetary
      parameter encoded as integer minor units (the parameter value itself
      is an ``int``); currency is fixed by the constraint and must match
      any amount comparison during narrowing.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ConstraintKind
    exact_value: ParameterValue = None
    allowed_values: tuple[ParameterValue, ...] | None = None
    min_int: int | None = None
    max_int: int | None = None
    currency: str | None = None
    min_amount: MonetaryAmount | None = None
    max_amount: MonetaryAmount | None = None

    @field_validator("allowed_values")
    @classmethod
    def _sort_allowed_values(
        cls, value: tuple[ParameterValue, ...] | None
    ) -> tuple[ParameterValue, ...] | None:
        if value is None:
            return None
        return tuple(sorted(value, key=_sort_key))

    @model_validator(mode="after")
    def _validate_shape(self) -> ParameterConstraint:
        if self.kind == "exact":
            if "exact_value" not in self.model_fields_set:
                raise ValueError("exact constraints require exact_value")
            if (
                self.allowed_values is not None
                or self.min_int is not None
                or self.max_int is not None
            ):
                raise ValueError("exact constraints must not set range/enum fields")
            if (
                self.min_amount is not None
                or self.max_amount is not None
                or self.currency is not None
            ):
                raise ValueError("exact constraints must not set monetary fields")
            return self
        if self.kind == "enum":
            if not self.allowed_values:
                raise ValueError("enum constraints require a non-empty allowed_values")
            if len(self.allowed_values) > MAX_ENUM_VALUES:
                raise ValueError(f"enum constraints allow at most {MAX_ENUM_VALUES} values")
            if len(set(self.allowed_values)) != len(self.allowed_values):
                raise ValueError("enum allowed_values must be unique")
            if self.min_int is not None or self.max_int is not None:
                raise ValueError("enum constraints must not set integer range fields")
            if (
                self.min_amount is not None
                or self.max_amount is not None
                or self.currency is not None
            ):
                raise ValueError("enum constraints must not set monetary fields")
            return self
        if self.kind == "integer_range":
            if self.min_int is None and self.max_int is None:
                raise ValueError("integer_range requires at least one of min_int/max_int")
            if (
                self.min_int is not None
                and self.max_int is not None
                and self.min_int > self.max_int
            ):
                raise ValueError("integer_range min_int must be <= max_int")
            if self.allowed_values is not None:
                raise ValueError("integer_range must not set allowed_values")
            if (
                self.min_amount is not None
                or self.max_amount is not None
                or self.currency is not None
            ):
                raise ValueError("integer_range must not set monetary fields")
            if "exact_value" in self.model_fields_set:
                raise ValueError("integer_range must not set exact_value")
            return self
        if self.kind == "monetary_range":
            if self.min_amount is None and self.max_amount is None:
                raise ValueError("monetary_range requires at least one of min_amount/max_amount")
            if self.currency is None:
                raise ValueError("monetary_range requires a currency")
            for amount in (self.min_amount, self.max_amount):
                if amount is not None and amount.currency != self.currency:
                    raise ValueError("monetary_range amounts must share one currency")
            if (
                self.min_amount is not None
                and self.max_amount is not None
                and self.min_amount.minor_units > self.max_amount.minor_units
            ):
                raise ValueError("monetary_range min_amount must be <= max_amount")
            if (
                self.allowed_values is not None
                or self.min_int is not None
                or self.max_int is not None
            ):
                raise ValueError("monetary_range must not set enum/integer fields")
            if "exact_value" in self.model_fields_set:
                raise ValueError("monetary_range must not set exact_value")
            return self
        raise ValueError(f"unknown constraint kind: {self.kind!r}")

    def accepts(self, value: ParameterValue) -> None:
        """Raise :class:`DecisionEnvelopeConstraintError` if ``value`` is out of bounds."""
        if self.kind == "exact":
            if value != self.exact_value:
                raise DecisionEnvelopeConstraintError(
                    f"value {value!r} does not equal exact constraint {self.exact_value!r}"
                )
            return
        if self.kind == "enum":
            if self.allowed_values is None:  # pragma: no cover - guarded by validator
                raise DecisionEnvelopeConstraintError("enum constraint missing allowed_values")
            if value not in self.allowed_values:
                raise DecisionEnvelopeConstraintError(
                    f"value {value!r} is not in allowed_values {list(self.allowed_values)!r}"
                )
            return
        if self.kind == "integer_range":
            if not isinstance(value, int) or isinstance(value, bool):
                raise DecisionEnvelopeConstraintError(
                    f"integer_range requires an int value, got {type(value).__name__}"
                )
            if self.min_int is not None and value < self.min_int:
                raise DecisionEnvelopeConstraintError(
                    f"value {value} is below integer_range min_int {self.min_int}"
                )
            if self.max_int is not None and value > self.max_int:
                raise DecisionEnvelopeConstraintError(
                    f"value {value} exceeds integer_range max_int {self.max_int}"
                )
            return
        if self.kind == "monetary_range":
            if not isinstance(value, int) or isinstance(value, bool):
                raise DecisionEnvelopeConstraintError(
                    f"monetary_range requires integer minor units, got {type(value).__name__}"
                )
            if self.currency is None:  # pragma: no cover - guarded by validator
                raise DecisionEnvelopeConstraintError("monetary_range missing currency")
            amount = MonetaryAmount(currency=self.currency, minor_units=value)
            if self.min_amount is not None and amount.minor_units < self.min_amount.minor_units:
                raise DecisionEnvelopeConstraintError(
                    f"amount {amount} is below monetary_range min {self.min_amount}"
                )
            if self.max_amount is not None and amount.minor_units > self.max_amount.minor_units:
                raise DecisionEnvelopeConstraintError(
                    f"amount {amount} exceeds monetary_range max {self.max_amount}"
                )
            return
        raise DecisionEnvelopeConstraintError(f"unknown constraint kind: {self.kind!r}")


def exact(value: ParameterValue) -> ParameterConstraint:
    return ParameterConstraint(kind="exact", exact_value=value)


def enum_of(*values: ParameterValue) -> ParameterConstraint:
    return ParameterConstraint(
        kind="enum",
        allowed_values=tuple(sorted(values, key=_sort_key)),
    )


def integer_range(*, min_int: int | None = None, max_int: int | None = None) -> ParameterConstraint:
    return ParameterConstraint(kind="integer_range", min_int=min_int, max_int=max_int)


def monetary_range(
    *,
    currency: str,
    min_minor_units: int | None = None,
    max_minor_units: int | None = None,
) -> ParameterConstraint:
    min_amount = (
        MonetaryAmount(currency=currency, minor_units=min_minor_units)
        if min_minor_units is not None
        else None
    )
    max_amount = (
        MonetaryAmount(currency=currency, minor_units=max_minor_units)
        if max_minor_units is not None
        else None
    )
    return ParameterConstraint(
        kind="monetary_range",
        currency=currency,
        min_amount=min_amount,
        max_amount=max_amount,
    )


def assert_constraint_narrower_or_equal(
    child: ParameterConstraint, parent: ParameterConstraint, *, name: str
) -> None:
    """Raise if ``child`` is not a subset of ``parent``'s allowed value space."""
    if child.kind == "exact":
        try:
            parent.accepts(child.exact_value)
        except DecisionEnvelopeConstraintError as exc:
            raise DecisionEnvelopeConstraintError(
                f"{name}: exact child value is outside parent constraint ({exc})"
            ) from exc
        return

    if parent.kind == "exact":
        raise DecisionEnvelopeConstraintError(
            f"{name}: child kind {child.kind!r} widens parent exact constraint"
        )

    if child.kind == "enum" and parent.kind == "enum":
        if child.allowed_values is None or parent.allowed_values is None:
            raise DecisionEnvelopeConstraintError(f"{name}: enum constraint missing allowed_values")
        if not set(child.allowed_values).issubset(parent.allowed_values):
            extra = sorted(set(child.allowed_values) - set(parent.allowed_values), key=_sort_key)
            raise DecisionEnvelopeConstraintError(
                f"{name}: enum child allows {extra!r} outside parent allow-list"
            )
        return

    if child.kind == "integer_range" and parent.kind == "integer_range":
        _assert_int_bounds_narrower(child, parent, name=name)
        return

    if child.kind == "monetary_range" and parent.kind == "monetary_range":
        if child.currency != parent.currency:
            raise IncomparableConstraintError(
                f"{name}: cannot compare monetary currencies "
                f"{child.currency!r} vs {parent.currency!r}; treated as widening"
            )
        _assert_money_bounds_narrower(child, parent, name=name)
        return

    if child.kind == "enum" and parent.kind == "integer_range":
        if child.allowed_values is None:
            raise DecisionEnvelopeConstraintError(f"{name}: enum constraint missing allowed_values")
        for value in child.allowed_values:
            try:
                parent.accepts(value)
            except DecisionEnvelopeConstraintError as exc:
                raise DecisionEnvelopeConstraintError(
                    f"{name}: enum child value outside parent integer_range ({exc})"
                ) from exc
        return

    if child.kind == "enum" and parent.kind == "monetary_range":
        if child.allowed_values is None:
            raise DecisionEnvelopeConstraintError(f"{name}: enum constraint missing allowed_values")
        for value in child.allowed_values:
            try:
                parent.accepts(value)
            except DecisionEnvelopeConstraintError as exc:
                raise DecisionEnvelopeConstraintError(
                    f"{name}: enum child value outside parent monetary_range ({exc})"
                ) from exc
        return

    raise IncomparableConstraintError(
        f"{name}: cannot safely compare child kind {child.kind!r} with "
        f"parent kind {parent.kind!r}; treated as widening"
    )


def _assert_int_bounds_narrower(
    child: ParameterConstraint, parent: ParameterConstraint, *, name: str
) -> None:
    if parent.min_int is not None and (child.min_int is None or child.min_int < parent.min_int):
        raise DecisionEnvelopeConstraintError(
            f"{name}: integer_range child min_int widens parent floor"
        )
    if parent.max_int is not None and (child.max_int is None or child.max_int > parent.max_int):
        raise DecisionEnvelopeConstraintError(
            f"{name}: integer_range child max_int widens parent ceiling"
        )


def _assert_money_bounds_narrower(
    child: ParameterConstraint, parent: ParameterConstraint, *, name: str
) -> None:
    if parent.min_amount is not None and (
        child.min_amount is None or child.min_amount.minor_units < parent.min_amount.minor_units
    ):
        raise DecisionEnvelopeConstraintError(
            f"{name}: monetary_range child min_amount widens parent floor"
        )
    if parent.max_amount is not None and (
        child.max_amount is None or child.max_amount.minor_units > parent.max_amount.minor_units
    ):
        raise DecisionEnvelopeConstraintError(
            f"{name}: monetary_range child max_amount widens parent ceiling"
        )


def _sort_key(value: ParameterValue) -> tuple[str, str]:
    return (type(value).__name__, repr(value))


def validate_constraint_key(key: str) -> str:
    if not key or len(key) > MAX_CONSTRAINT_KEY_LENGTH:
        raise ValueError(f"parameter constraint key must be 1-{MAX_CONSTRAINT_KEY_LENGTH} chars")
    if any(ord(c) < 0x20 for c in key):
        raise ValueError("parameter constraint key must not contain control characters")
    return key


__all__ = [
    "MAX_CONSTRAINT_KEY_LENGTH",
    "MAX_ENUM_VALUES",
    "ConstraintKind",
    "ParameterConstraint",
    "assert_constraint_narrower_or_equal",
    "enum_of",
    "exact",
    "integer_range",
    "monetary_range",
    "validate_constraint_key",
]
