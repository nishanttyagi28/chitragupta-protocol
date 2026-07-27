"""Shared value objects used across the Effect Manifest and grants."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator

from chitragupta.domain.enums import PrincipalType, StateFingerprintKind

_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _validate_id(value: str, field_name: str) -> str:
    if not value or not _ID_RE.match(value):
        raise ValueError(
            f"{field_name} must be 1-128 chars, start alphanumeric, and contain only "
            "[A-Za-z0-9._:-]"
        )
    return value


class Principal(BaseModel):
    """A human, service, or agent identity referenced by a manifest or grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str
    principal_type: PrincipalType
    display_name: str | None = None

    @field_validator("principal_id")
    @classmethod
    def _validate_principal_id(cls, v: str) -> str:
        return _validate_id(v, "principal_id")

    @field_validator("display_name")
    @classmethod
    def _validate_display_name(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 256:
            raise ValueError("display_name must be <= 256 chars")
        return v


class AdapterIdentity(BaseModel):
    """Identity + version of the effect adapter a manifest/grant is bound to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_id: str
    adapter_version: str

    @field_validator("adapter_id")
    @classmethod
    def _validate_adapter_id(cls, v: str) -> str:
        return _validate_id(v, "adapter_id")

    @field_validator("adapter_version")
    @classmethod
    def _validate_adapter_version(cls, v: str) -> str:
        if not v or len(v) > 64:
            raise ValueError("adapter_version must be 1-64 chars")
        return v


class MonetaryAmount(BaseModel):
    """An exact monetary amount. Always integer minor units -- never float."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    currency: str
    minor_units: int

    @field_validator("currency")
    @classmethod
    def _validate_currency(cls, v: str) -> str:
        if not _CURRENCY_RE.match(v):
            raise ValueError("currency must be a 3-letter uppercase ISO 4217 code")
        return v

    @field_validator("minor_units")
    @classmethod
    def _validate_minor_units(cls, v: int) -> int:
        if v < 0:
            raise ValueError("minor_units must be >= 0")
        if v > 10**15:
            raise ValueError("minor_units exceeds sane upper bound")
        return v

    def __le__(self, other: MonetaryAmount) -> bool:
        if self.currency != other.currency:
            raise ValueError(
                f"cannot compare amounts in different currencies: "
                f"{self.currency} vs {other.currency}"
            )
        return self.minor_units <= other.minor_units

    def __str__(self) -> str:
        return f"{self.currency} {self.minor_units}"


class StateFingerprint(BaseModel):
    """A precondition-binding fingerprint of external resource state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: StateFingerprintKind
    value: str

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str) -> str:
        if not v or len(v) > 512:
            raise ValueError("state fingerprint value must be 1-512 chars")
        return v


class Precondition(BaseModel):
    """An explicit precondition that must hold at commit time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: str
    fingerprint: StateFingerprint

    @field_validator("description")
    @classmethod
    def _validate_description(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("precondition description must be 1-256 chars")
        return v
