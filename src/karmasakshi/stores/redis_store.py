"""Redis-backed grant store for distributed atomic consumption and revocation.

``redis`` is an optional dependency (``pip install karmasakshi-protocol[redis]``).
Atomicity is provided by a single Lua script evaluated server-side (Redis
guarantees ``EVAL`` runs atomically with respect to all other clients),
which is what makes ``reserve`` safe across multiple processes/machines
sharing one Redis instance -- unlike the SQLite backend, which is explicitly
single-node only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from karmasakshi.errors import StoreUnavailableError

if TYPE_CHECKING:
    pass

_RESERVE_SCRIPT = """
local revoked_key = KEYS[1]
local uses_key = KEYS[2]
local reserved_key = KEYS[3]
local max_uses = tonumber(ARGV[1])

if redis.call('GET', revoked_key) == '1' then
    return 0
end
if redis.call('GET', reserved_key) == '1' then
    return 0
end
local uses = tonumber(redis.call('GET', uses_key) or '0')
if uses >= max_uses then
    return 0
end
redis.call('SET', reserved_key, '1')
return 1
"""

_COMMIT_SCRIPT = """
local uses_key = KEYS[1]
local reserved_key = KEYS[2]
local idem_key = KEYS[3]
local outcome_ref = ARGV[1]

if redis.call('GET', reserved_key) ~= '1' then
    return 0
end
redis.call('INCR', uses_key)
redis.call('SET', reserved_key, '0')
redis.call('SET', idem_key, outcome_ref)
return 1
"""


class RedisGrantStore:
    """Atomic grant consumption backed by Redis.

    Pass an existing ``redis.Redis`` (or compatible) client -- this class
    does not manage the connection lifecycle.
    """

    def __init__(self, client: Any, namespace: str = "karmasakshi") -> None:
        try:
            import redis  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise StoreUnavailableError(
                "the 'redis' package is required for RedisGrantStore; "
                "install with `pip install karmasakshi-protocol[redis]`"
            ) from exc
        self._client = client
        self._ns = namespace
        self._reserve_script = client.register_script(_RESERVE_SCRIPT)
        self._commit_script = client.register_script(_COMMIT_SCRIPT)

    def _key(self, grant_id: str, suffix: str) -> str:
        return f"{self._ns}:grant:{grant_id}:{suffix}"

    def _idem_key(self, idempotency_key: str) -> str:
        return f"{self._ns}:idem:{idempotency_key}"

    def _decode(self, value: Any) -> str | None:
        if value is None:
            return None
        return value.decode("utf-8") if isinstance(value, bytes) else str(value)

    def reserve(self, grant_id: str, max_uses: int) -> bool:
        try:
            result = self._reserve_script(
                keys=[
                    self._key(grant_id, "revoked"),
                    self._key(grant_id, "uses"),
                    self._key(grant_id, "reserved"),
                ],
                args=[max_uses],
            )
        except Exception as exc:
            raise StoreUnavailableError(f"redis reserve() failed for grant {grant_id}") from exc
        return bool(int(result))

    def release(self, grant_id: str) -> None:
        try:
            self._client.set(self._key(grant_id, "reserved"), "0")
        except Exception as exc:
            raise StoreUnavailableError(f"redis release() failed for grant {grant_id}") from exc

    def commit(self, grant_id: str, idempotency_key: str, outcome_ref: str) -> None:
        try:
            result = self._commit_script(
                keys=[
                    self._key(grant_id, "uses"),
                    self._key(grant_id, "reserved"),
                    self._idem_key(idempotency_key),
                ],
                args=[outcome_ref],
            )
        except Exception as exc:
            raise StoreUnavailableError(f"redis commit() failed for grant {grant_id}") from exc
        if not int(result):
            raise StoreUnavailableError(
                f"commit() called for grant {grant_id!r} without a held reservation"
            )

    def revoke(self, grant_id: str) -> None:
        try:
            self._client.set(self._key(grant_id, "revoked"), "1")
        except Exception as exc:
            raise StoreUnavailableError(f"redis revoke() failed for grant {grant_id}") from exc

    def is_revoked(self, grant_id: str) -> bool:
        try:
            value = self._client.get(self._key(grant_id, "revoked"))
        except Exception as exc:
            raise StoreUnavailableError(f"redis is_revoked() failed for grant {grant_id}") from exc
        return self._decode(value) == "1"

    def get_use_count(self, grant_id: str) -> int:
        try:
            value = self._client.get(self._key(grant_id, "uses"))
        except Exception as exc:
            raise StoreUnavailableError(
                f"redis get_use_count() failed for grant {grant_id}"
            ) from exc
        decoded = self._decode(value)
        return int(decoded) if decoded is not None else 0

    def get_idempotent_outcome(self, idempotency_key: str) -> str | None:
        try:
            value = self._client.get(self._idem_key(idempotency_key))
        except Exception as exc:
            raise StoreUnavailableError(
                f"redis get_idempotent_outcome() failed for key {idempotency_key}"
            ) from exc
        return self._decode(value)

    def record_idempotent_outcome(self, idempotency_key: str, outcome_ref: str) -> None:
        try:
            self._client.set(self._idem_key(idempotency_key), outcome_ref)
        except Exception as exc:
            raise StoreUnavailableError(
                f"redis record_idempotent_outcome() failed for key {idempotency_key}"
            ) from exc

    def record_lineage(self, grant_id: str, parent_grant_id: str | None) -> None:
        try:
            # Sentinel distinguishes recorded root (empty) from unknown (missing key).
            value = parent_grant_id if parent_grant_id is not None else ""
            self._client.set(self._key(grant_id, "parent"), value)
        except Exception as exc:
            raise StoreUnavailableError(
                f"redis record_lineage() failed for grant {grant_id}"
            ) from exc

    def get_parent_grant_id(self, grant_id: str) -> str | None:
        try:
            value = self._client.get(self._key(grant_id, "parent"))
        except Exception as exc:
            raise StoreUnavailableError(
                f"redis get_parent_grant_id() failed for grant {grant_id}"
            ) from exc
        decoded = self._decode(value)
        if decoded is None or decoded == "":
            return None
        return decoded

    def has_lineage(self, grant_id: str) -> bool:
        try:
            return bool(self._client.exists(self._key(grant_id, "parent")))
        except Exception as exc:
            raise StoreUnavailableError(f"redis has_lineage() failed for grant {grant_id}") from exc


__all__ = ["RedisGrantStore"]
