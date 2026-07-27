"""Runtime configuration.

Kept intentionally small and explicit: every security-relevant tunable
(clock skew tolerance, metadata limits, blast-radius ceilings) is a named
field here rather than a magic number buried in engine code.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClockSkewPolicy:
    """Bounded, explicit clock-skew tolerance (invariant #9).

    ``leeway_seconds`` is applied symmetrically around ``not_before`` and
    ``expires_at`` boundaries: a grant is usable if
    ``not_before - leeway <= now <= expires_at + leeway``.
    """

    leeway_seconds: int = 5

    def __post_init__(self) -> None:
        if self.leeway_seconds < 0:
            raise ValueError("leeway_seconds must be >= 0")
        if self.leeway_seconds > 300:
            raise ValueError("leeway_seconds must be bounded (<= 300s) by policy")


@dataclass(frozen=True)
class MetadataLimits:
    """Strict size/type limits for manifest metadata (spec section 4)."""

    max_keys: int = 16
    max_key_length: int = 64
    max_value_length: int = 512
    max_total_bytes: int = 8192


@dataclass(frozen=True)
class ManifestLimits:
    max_parameters: int = 64
    max_parameter_key_length: int = 128
    max_parameter_value_length: int = 4096
    max_target_resource_length: int = 512
    default_ttl_seconds: int = 900


@dataclass(frozen=True)
class Settings:
    clock_skew: ClockSkewPolicy = field(default_factory=ClockSkewPolicy)
    metadata_limits: MetadataLimits = field(default_factory=MetadataLimits)
    manifest_limits: ManifestLimits = field(default_factory=ManifestLimits)
    schema_version: str = "1.0"
    max_delegation_depth: int = 8


DEFAULT_SETTINGS = Settings()
