"""KarmaSakshi Gateway: the commercial-layer durable organization model
(Milestone A).

Additive to the open-core protocol -- nothing here changes
`karmasakshi.engine`, `karmasakshi.domain`, or any existing invariant.
See docs/gateway.md and docs/product/COMMERCIAL_ARCHITECTURE.md.
"""

from __future__ import annotations

from karmasakshi.gateway.migrations import MIGRATIONS, Migration, apply_migrations
from karmasakshi.gateway.models import (
    GatewayAdapterRegistration,
    GatewayAgent,
    GatewayUser,
    GatewayUserRole,
    Organization,
    OrganizationStatus,
)
from karmasakshi.gateway.sessions import DEFAULT_SESSION_TTL, GatewaySession, GatewaySessionStore
from karmasakshi.gateway.store import GatewayStore, default_gateway_db_path

__all__ = [
    "DEFAULT_SESSION_TTL",
    "MIGRATIONS",
    "GatewayAdapterRegistration",
    "GatewayAgent",
    "GatewaySession",
    "GatewaySessionStore",
    "GatewayStore",
    "GatewayUser",
    "GatewayUserRole",
    "Migration",
    "Organization",
    "OrganizationStatus",
    "apply_migrations",
    "default_gateway_db_path",
]
