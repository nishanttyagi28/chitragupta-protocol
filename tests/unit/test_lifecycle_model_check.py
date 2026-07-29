"""Tests for bounded lifecycle model checking (Phase 22)."""

from __future__ import annotations

from karmasakshi.state_machine.model_check import check_lifecycle_model


def test_lifecycle_model_check_passes_at_default_bound():
    report = check_lifecycle_model()
    assert report.passed, [f for f in report.findings if not f.passed]
    assert report.paths_explored > 0


def test_lifecycle_model_check_passes_at_deeper_bound():
    report = check_lifecycle_model(depth_bound=20)
    assert report.passed
    assert all(f.passed for f in report.findings)


def test_model_check_rejects_invalid_depth():
    import pytest

    with pytest.raises(ValueError):
        check_lifecycle_model(depth_bound=0)
