from __future__ import annotations

from enum import Enum


class PrincipalType(str, Enum):
    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"


class RiskClassification(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReversibilityClassification(str, Enum):
    REVERSIBLE = "reversible"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"


class BlastRadiusClassification(str, Enum):
    SINGLE_RESOURCE = "single_resource"
    BOUNDED_SET = "bounded_set"
    BROAD = "broad"
    UNBOUNDED = "unbounded"


class StateFingerprintKind(str, Enum):
    ROW_VERSION = "row_version"
    ETAG = "etag"
    REVISION = "revision"
    UPDATED_AT_DIGEST = "updated_at_digest"
    CONTENT_HASH = "content_hash"
    PROVIDER_STATUS = "provider_status"
    CUSTOM = "custom"
