"""KarmaSakshi Gateway: the commercial-layer durable organization model
(Milestone A).

Additive to the open-core protocol -- nothing here changes
`karmasakshi.engine`, `karmasakshi.domain`, or any existing invariant.
See docs/gateway.md and docs/product/COMMERCIAL_ARCHITECTURE.md.
"""

from __future__ import annotations

from karmasakshi.gateway.migrations import MIGRATIONS, Migration, apply_migrations
from karmasakshi.gateway.models import (
    GatewayUser,
    GatewayUserRole,
    Organization,
    OrganizationStatus,
)
from karmasakshi.gateway.store import GatewayStore, default_gateway_db_path

__all__ = [
    "MIGRATIONS",
    "GatewayStore",
    "GatewayUser",
    "GatewayUserRole",
    "Migration",
    "Organization",
    "OrganizationStatus",
    "apply_migrations",
    "default_gateway_db_path",
]
