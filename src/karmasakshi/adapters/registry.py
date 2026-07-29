"""Trusted adapter registry (extreme-v2 Phase 17).

A versioned allow-list of effect adapters the control plane may invoke.
When an :class:`~karmasakshi.engine.context.EngineContext` carries a
registry, prepare/commit/verify/compensate paths fail closed on unknown
``(adapter_id, adapter_version)`` pairs, revoked entries, or effect types
outside the declared capability set.

There is no dynamic plugin discovery and no semver range matching —
exact version pins only.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from threading import RLock

from karmasakshi.adapters.base import EffectAdapter
from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.domain.common import AdapterIdentity
from karmasakshi.errors import UntrustedAdapterError
from karmasakshi.intelligence.facts import AssessmentFacts

_MAX_EFFECT_TYPES = 64
_MAX_ENVIRONMENTS = 32
_ID_MAX = 128
_VERSION_MAX = 64


def _validate_id(value: str, field: str) -> str:
    if not value or len(value) > _ID_MAX:
        raise ValueError(f"{field} must be 1-{_ID_MAX} chars")
    return value


def _validate_version(value: str) -> str:
    if not value or len(value) > _VERSION_MAX:
        raise ValueError(f"adapter_version must be 1-{_VERSION_MAX} chars")
    return value


@dataclass(frozen=True)
class AdapterCapability:
    """Declared capabilities for one exact adapter identity+version.

    Capability facts are operator-supplied declarations used for allow-list
    enforcement and (optionally) Effect Intelligence scoring. They are not
    runtime probes of a provider.
    """

    adapter_id: str
    adapter_version: str
    supported_effect_types: tuple[str, ...]
    environments: tuple[str, ...] = ()
    provider_idempotent: bool | None = None
    compensation_feasible: bool | None = None
    description: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "adapter_id", _validate_id(self.adapter_id, "adapter_id"))
        object.__setattr__(self, "adapter_version", _validate_version(self.adapter_version))
        if not self.supported_effect_types:
            raise ValueError("supported_effect_types must be non-empty")
        if len(self.supported_effect_types) > _MAX_EFFECT_TYPES:
            raise ValueError(f"supported_effect_types exceeds {_MAX_EFFECT_TYPES}")
        for et in self.supported_effect_types:
            if not et or len(et) > 128:
                raise ValueError("supported_effect_types entries must be 1-128 chars")
        if len(self.environments) > _MAX_ENVIRONMENTS:
            raise ValueError(f"environments exceeds {_MAX_ENVIRONMENTS}")
        for env in self.environments:
            if not env or len(env) > 64:
                raise ValueError("environments entries must be 1-64 chars")
        if self.description is not None and len(self.description) > 512:
            raise ValueError("description must be <= 512 chars")
        # Normalize to sorted unique tuples for deterministic hashing.
        object.__setattr__(
            self,
            "supported_effect_types",
            tuple(sorted(set(self.supported_effect_types))),
        )
        object.__setattr__(
            self,
            "environments",
            tuple(sorted(set(self.environments))),
        )

    @property
    def identity(self) -> AdapterIdentity:
        return AdapterIdentity(adapter_id=self.adapter_id, adapter_version=self.adapter_version)

    def supports_effect_type(self, effect_type: str) -> bool:
        return effect_type in self.supported_effect_types

    def canonical_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "supported_effect_types": list(self.supported_effect_types),
            "environments": list(self.environments),
            "provider_idempotent": self.provider_idempotent,
            "compensation_feasible": self.compensation_feasible,
            "description": self.description,
        }

    def canonical_hash(self) -> str:
        return canonical_hash(self.canonical_dict())


@dataclass(frozen=True)
class RegistryEntry:
    """One allow-listed capability, optionally revoked."""

    capability: AdapterCapability
    revoked: bool = False
    revoked_at: datetime | None = None
    revoke_reason: str | None = None

    def __post_init__(self) -> None:
        if self.revoked and self.revoked_at is None:
            raise ValueError("revoked entry requires revoked_at")
        if self.revoke_reason is not None and len(self.revoke_reason) > 256:
            raise ValueError("revoke_reason must be <= 256 chars")
        if self.revoked_at is not None and self.revoked_at.tzinfo is None:
            raise ValueError("revoked_at must be timezone-aware UTC")


def _key(adapter_id: str, adapter_version: str) -> tuple[str, str]:
    return (adapter_id, adapter_version)


class TrustedAdapterRegistry:
    """Process-local versioned adapter allow-list.

    Thread-safe under an ``RLock``. Not a multi-node consensus store —
    operators must provision the same allow-list on each control-plane
    instance.
    """

    def __init__(self, entries: Iterable[AdapterCapability] | None = None) -> None:
        self._lock = RLock()
        self._entries: dict[tuple[str, str], RegistryEntry] = {}
        if entries is not None:
            for cap in entries:
                self.register(cap)

    def register(self, capability: AdapterCapability) -> RegistryEntry:
        """Add or replace a trusted capability (exact id+version).

        Replacing a previously revoked entry clears the revocation
        (operator must re-revoke explicitly if still untrusted).
        """
        key = _key(capability.adapter_id, capability.adapter_version)
        entry = RegistryEntry(capability=capability, revoked=False)
        with self._lock:
            self._entries[key] = entry
        return entry

    def revoke(
        self,
        adapter_id: str,
        adapter_version: str,
        *,
        revoked_at: datetime,
        reason: str | None = None,
    ) -> RegistryEntry:
        """Mark an exact (id, version) pair untrusted. Fail closed thereafter."""
        key = _key(adapter_id, adapter_version)
        with self._lock:
            existing = self._entries.get(key)
            if existing is None:
                raise UntrustedAdapterError(
                    f"cannot revoke unknown adapter {adapter_id}@{adapter_version}; "
                    "refuse to invent a registry entry (fail closed)"
                )
            entry = RegistryEntry(
                capability=existing.capability,
                revoked=True,
                revoked_at=revoked_at,
                revoke_reason=reason,
            )
            self._entries[key] = entry
            return entry

    def lookup(self, adapter_id: str, adapter_version: str) -> RegistryEntry | None:
        with self._lock:
            return self._entries.get(_key(adapter_id, adapter_version))

    def is_trusted(self, adapter_id: str, adapter_version: str) -> bool:
        entry = self.lookup(adapter_id, adapter_version)
        return entry is not None and not entry.revoked

    def require(self, adapter_id: str, adapter_version: str) -> AdapterCapability:
        """Return the capability or raise :class:`UntrustedAdapterError`."""
        entry = self.lookup(adapter_id, adapter_version)
        if entry is None:
            raise UntrustedAdapterError(
                f"adapter {adapter_id}@{adapter_version} is not on the trusted "
                "adapter registry allow-list (fail closed)"
            )
        if entry.revoked:
            reason = entry.revoke_reason or "revoked"
            raise UntrustedAdapterError(
                f"adapter {adapter_id}@{adapter_version} is revoked "
                f"({reason}); refuse to use (fail closed)"
            )
        return entry.capability

    def require_adapter(self, adapter: EffectAdapter) -> AdapterCapability:
        """Require the executing adapter instance is on the allow-list."""
        return self.require(adapter.adapter_id, adapter.adapter_version)

    def require_effect(
        self, adapter_id: str, adapter_version: str, effect_type: str
    ) -> AdapterCapability:
        """Require trust *and* that ``effect_type`` is declared."""
        capability = self.require(adapter_id, adapter_version)
        if not capability.supports_effect_type(effect_type):
            raise UntrustedAdapterError(
                f"effect_type {effect_type!r} is not declared in trusted "
                f"capability for {adapter_id}@{adapter_version} "
                f"(allowed={list(capability.supported_effect_types)}); fail closed"
            )
        return capability

    def require_environment(
        self, adapter_id: str, adapter_version: str, environment: str
    ) -> AdapterCapability:
        """When the capability lists environments, require membership."""
        capability = self.require(adapter_id, adapter_version)
        if capability.environments and environment not in capability.environments:
            raise UntrustedAdapterError(
                f"environment {environment!r} is not allowed for "
                f"{adapter_id}@{adapter_version} "
                f"(allowed={list(capability.environments)}); fail closed"
            )
        return capability

    def list_entries(self) -> tuple[RegistryEntry, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self._entries.values(),
                    key=lambda e: (e.capability.adapter_id, e.capability.adapter_version),
                )
            )

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


def facts_from_capability(
    capability: AdapterCapability,
    *,
    base: AssessmentFacts | None = None,
) -> AssessmentFacts:
    """Merge capability declarations into AssessmentFacts (explicit, not guessed)."""
    base = base or AssessmentFacts()
    return AssessmentFacts(
        delegation_depth=base.delegation_depth,
        historical_recurrence_count=base.historical_recurrence_count,
        historical_failure_count=base.historical_failure_count,
        provider_idempotent=(
            capability.provider_idempotent
            if capability.provider_idempotent is not None
            else base.provider_idempotent
        ),
        compensation_feasible=(
            capability.compensation_feasible
            if capability.compensation_feasible is not None
            else base.compensation_feasible
        ),
        cross_tenant=base.cross_tenant,
        unusual_parameter_change=base.unusual_parameter_change,
        policy_violations=base.policy_violations,
    )


def reference_adapter_capabilities() -> tuple[AdapterCapability, ...]:
    """Capabilities for the three shipped reference adapters."""
    return (
        AdapterCapability(
            adapter_id="payment.simulator",
            adapter_version="1.0.0",
            supported_effect_types=("payment.transfer",),
            environments=("dev", "eval", "demo"),
            provider_idempotent=True,
            compensation_feasible=True,
            description="Deterministic payment simulator (no real money)",
        ),
        AdapterCapability(
            adapter_id="email.sandbox",
            adapter_version="1.0.0",
            supported_effect_types=("email.send",),
            environments=("dev", "eval", "demo"),
            provider_idempotent=True,
            compensation_feasible=False,
            description="In-memory email sandbox (send is irreversible)",
        ),
        AdapterCapability(
            adapter_id="sqlite.row",
            adapter_version="1.0.0",
            supported_effect_types=(
                "sqlite.row.delete",
                "sqlite.row.insert",
                "sqlite.row.update",
            ),
            environments=("dev", "eval", "demo"),
            provider_idempotent=True,
            compensation_feasible=True,
            description="Local SQLite row adapter",
        ),
    )


def build_reference_registry() -> TrustedAdapterRegistry:
    """Allow-list containing only the three reference adapters."""
    return TrustedAdapterRegistry(reference_adapter_capabilities())


__all__ = [
    "AdapterCapability",
    "RegistryEntry",
    "TrustedAdapterRegistry",
    "build_reference_registry",
    "facts_from_capability",
    "reference_adapter_capabilities",
]
