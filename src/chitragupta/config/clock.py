"""Clock abstraction.

All lifecycle timing decisions (expiry, not-before, clock skew) go through a
:class:`Clock` so tests can inject deterministic time instead of sleeping
(see docs/threat-model.md and the test strategy in BUILD_STATUS.md).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


class Clock:
    """Real wall-clock, always timezone-aware UTC."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FixedClock(Clock):
    """Deterministic clock for tests. Advance explicitly with `.advance()`."""

    def __init__(self, initial: datetime) -> None:
        if initial.tzinfo is None:
            raise ValueError("FixedClock requires a timezone-aware datetime")
        self._now = initial.astimezone(timezone.utc)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now = self._now + delta

    def set(self, value: datetime) -> None:
        if value.tzinfo is None:
            raise ValueError("FixedClock requires a timezone-aware datetime")
        self._now = value.astimezone(timezone.utc)


SYSTEM_CLOCK = Clock()


def ensure_utc(value: datetime) -> datetime:
    """Normalize any timezone-aware datetime to UTC. Reject naive datetimes."""
    if value.tzinfo is None:
        raise ValueError("naive datetimes are not permitted; all timestamps must be tz-aware UTC")
    return value.astimezone(timezone.utc)
