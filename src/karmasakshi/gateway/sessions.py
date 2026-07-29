"""In-process Gateway session tokens (Milestone A).

Sessions are issued after `GatewayStore.authenticate()` succeeds and are
the bearer credential for org-scoped Gateway HTTP endpoints. This is a
process-local, in-memory store -- like the protocol core's
`InMemoryAuditBackend`, not a claim of durability or multi-process
sharing. A real deployment scaling the Gateway horizontally would need a
shared session backend (Redis or similar); that is explicitly deferred
to Milestone B. See docs/gateway.md and docs/limitations.md.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from karmasakshi.config.clock import SYSTEM_CLOCK, Clock
from karmasakshi.gateway.models import GatewayUser

DEFAULT_SESSION_TTL = timedelta(hours=12)
_TOKEN_BYTES = 32


@dataclass(frozen=True)
class GatewaySession:
    token: str
    user_id: str
    org_id: str
    issued_at: datetime
    expires_at: datetime

    def is_expired(self, at: datetime) -> bool:
        return at >= self.expires_at


class GatewaySessionStore:
    """Issues and validates bearer session tokens for authenticated
    `GatewayUser`s. Thread-safe; expired sessions are rejected (and
    lazily evicted) rather than silently extended."""

    def __init__(
        self, *, ttl: timedelta = DEFAULT_SESSION_TTL, clock: Clock = SYSTEM_CLOCK
    ) -> None:
        self._ttl = ttl
        self._clock = clock
        self._sessions: dict[str, GatewaySession] = {}
        self._lock = threading.Lock()

    def issue(self, user: GatewayUser) -> GatewaySession:
        now = self._clock.now()
        session = GatewaySession(
            token=secrets.token_urlsafe(_TOKEN_BYTES),
            user_id=user.user_id,
            org_id=user.org_id,
            issued_at=now,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._sessions[session.token] = session
        return session

    def get(self, token: str) -> GatewaySession | None:
        """Return the live session for ``token``, or ``None`` if it does
        not exist or has expired. An expired session is evicted, never
        treated as valid -- there is no silent renewal."""
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if session.is_expired(self._clock.now()):
                del self._sessions[token]
                return None
            return session

    def revoke(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def revoke_all_for_user(self, user_id: str) -> None:
        with self._lock:
            for token in [t for t, s in self._sessions.items() if s.user_id == user_id]:
                del self._sessions[token]


__all__ = ["DEFAULT_SESSION_TTL", "GatewaySession", "GatewaySessionStore"]
