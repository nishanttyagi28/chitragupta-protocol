"""Redis-backed audit journal sink (extreme-v2 Phase 14).

Shared append across processes/machines that share one Redis instance.
Atomicity is a single Lua ``EVAL`` (read-tail sequence check + RPUSH) —
the same honesty bar as ``RedisGrantStore``. This is **not** Raft, etcd,
or multi-DC consensus.

``redis`` is an optional dependency
(``pip install karmasakshi-protocol[redis]``).
"""

from __future__ import annotations

from typing import Any

from karmasakshi.audit.events import AuditEvent
from karmasakshi.errors import AuditWriteError, StoreUnavailableError

_APPEND_SCRIPT = """
local list_key = KEYS[1]
local payload = ARGV[1]
local expected_seq = tonumber(ARGV[2])
local len = redis.call('LLEN', list_key)
if (len + 1) ~= expected_seq then
  return 0
end
redis.call('RPUSH', list_key, payload)
return 1
"""


class RedisAuditBackend:
    """Append-only audit event list in Redis.

    Pass an existing ``redis.Redis`` (or compatible) client — this class
    does not manage the connection lifecycle.
    """

    def __init__(self, client: Any, namespace: str = "karmasakshi") -> None:
        try:
            import redis  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise StoreUnavailableError(
                "the 'redis' package is required for RedisAuditBackend; "
                "install with `pip install karmasakshi-protocol[redis]`"
            ) from exc
        self._client = client
        self._ns = namespace
        self._list_key = f"{namespace}:audit:events"
        self._append_script = client.register_script(_APPEND_SCRIPT)

    def append(self, event: AuditEvent) -> None:
        payload = event.model_dump_json()
        try:
            ok = self._append_script(keys=[self._list_key], args=[payload, event.sequence])
        except Exception as exc:
            raise AuditWriteError(
                f"redis audit append failed for sequence={event.sequence}"
            ) from exc
        if int(ok) != 1:
            raise AuditWriteError(
                f"redis audit append rejected sequence={event.sequence} "
                "(concurrent writer or stale journal tip); fail closed"
            )

    def all_events(self) -> list[AuditEvent]:
        try:
            raw = self._client.lrange(self._list_key, 0, -1)
        except Exception as exc:
            raise AuditWriteError("redis audit all_events failed") from exc
        return [AuditEvent.model_validate_json(item) for item in raw]

    def last_event(self) -> AuditEvent | None:
        try:
            raw = self._client.lindex(self._list_key, -1)
        except Exception as exc:
            raise AuditWriteError("redis audit last_event failed") from exc
        if raw is None:
            return None
        return AuditEvent.model_validate_json(raw)


__all__ = ["RedisAuditBackend"]
