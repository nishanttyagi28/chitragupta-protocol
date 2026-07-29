"""Multi-tenant identity (extreme-v2 Phase 19).

A ``Tenant`` is the isolation boundary for control-plane state. Protocol
objects may optionally carry ``tenant_id`` (e.g. ``PolicyBundle.tenant_id``);
when an :class:`~karmasakshi.engine.context.EngineContext` is bound to a
tenant, mismatches fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from karmasakshi.canonical.serialize import canonical_hash

TenantStatus = Literal["active", "suspended"]


@dataclass(frozen=True)
class Tenant:
    tenant_id: str
    display_name: str
    status: TenantStatus = "active"
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.tenant_id or len(self.tenant_id) > 128:
            raise ValueError("tenant_id must be 1-128 chars")
        if not self.display_name or len(self.display_name) > 256:
            raise ValueError("display_name must be 1-256 chars")
        if self.status not in ("active", "suspended"):
            raise ValueError("status must be 'active' or 'suspended'")
        if self.created_at is not None and self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware UTC")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "display_name": self.display_name,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def canonical_hash(self) -> str:
        return canonical_hash(self.canonical_dict())


__all__ = ["Tenant", "TenantStatus"]
