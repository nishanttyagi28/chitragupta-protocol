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
from karmasakshi.tenant.org_id import validate_canonical_org_id

TenantStatus = Literal["active", "suspended"]


@dataclass(frozen=True)
class Tenant:
    tenant_id: str
    display_name: str
    status: TenantStatus = "active"
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        # RA-001: tenant_id is used as a filesystem path segment by the
        # control plane, so it must satisfy the canonical id rules here at
        # the model boundary, not only at the HTTP schema boundary.
        validate_canonical_org_id(self.tenant_id)
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
