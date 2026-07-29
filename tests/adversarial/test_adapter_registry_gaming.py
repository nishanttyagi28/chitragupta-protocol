"""Adversarial tests for trusted adapter registry (Phase 17)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from karmasakshi.adapters.registry import AdapterCapability, TrustedAdapterRegistry
from karmasakshi.errors import UntrustedAdapterError

NOW = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)


def test_cannot_swap_version_to_bypass_allow_list():
    registry = TrustedAdapterRegistry(
        [
            AdapterCapability(
                adapter_id="payment.simulator",
                adapter_version="1.0.0",
                supported_effect_types=("payment.transfer",),
            )
        ]
    )
    with pytest.raises(UntrustedAdapterError):
        registry.require("payment.simulator", "9.9.9")


def test_cannot_use_sibling_adapter_id():
    registry = TrustedAdapterRegistry(
        [
            AdapterCapability(
                adapter_id="payment.simulator",
                adapter_version="1.0.0",
                supported_effect_types=("payment.transfer",),
            )
        ]
    )
    with pytest.raises(UntrustedAdapterError):
        registry.require("payment.simulator.evil", "1.0.0")


def test_re_register_clears_revocation_explicitly():
    """Re-register after revoke is an intentional operator action, not silent."""
    registry = TrustedAdapterRegistry(
        [
            AdapterCapability(
                adapter_id="payment.simulator",
                adapter_version="1.0.0",
                supported_effect_types=("payment.transfer",),
            )
        ]
    )
    registry.revoke("payment.simulator", "1.0.0", revoked_at=NOW, reason="temp")
    with pytest.raises(UntrustedAdapterError):
        registry.require("payment.simulator", "1.0.0")
    registry.register(
        AdapterCapability(
            adapter_id="payment.simulator",
            adapter_version="1.0.0",
            supported_effect_types=("payment.transfer",),
        )
    )
    assert registry.is_trusted("payment.simulator", "1.0.0")


def test_capability_hash_stable_under_effect_type_reorder():
    a = AdapterCapability(
        adapter_id="sqlite.row",
        adapter_version="1.0.0",
        supported_effect_types=("sqlite.row.update", "sqlite.row.insert"),
    )
    b = AdapterCapability(
        adapter_id="sqlite.row",
        adapter_version="1.0.0",
        supported_effect_types=("sqlite.row.insert", "sqlite.row.update"),
    )
    assert a.canonical_hash() == b.canonical_hash()
