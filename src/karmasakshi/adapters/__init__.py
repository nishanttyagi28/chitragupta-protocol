from __future__ import annotations

from karmasakshi.adapters.base import (
    AsyncEffectAdapter,
    CommitResult,
    CompensationResult,
    EffectAdapter,
    OutcomeProof,
    PreconditionResult,
)
from karmasakshi.adapters.email_sandbox import (
    EmailRequest,
    EmailSandboxAdapter,
    SandboxOutbox,
    SentMessage,
)
from karmasakshi.adapters.payment_simulator import (
    PaymentRecord,
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from karmasakshi.adapters.registry import (
    AdapterCapability,
    RegistryEntry,
    TrustedAdapterRegistry,
    build_reference_registry,
    facts_from_capability,
    reference_adapter_capabilities,
)
from karmasakshi.adapters.sqlite_db import RowEffectRequest, SQLiteRowAdapter

__all__ = [
    "AdapterCapability",
    "AsyncEffectAdapter",
    "CommitResult",
    "CompensationResult",
    "EffectAdapter",
    "EmailRequest",
    "EmailSandboxAdapter",
    "OutcomeProof",
    "PaymentRecord",
    "PaymentRequest",
    "PaymentSimulator",
    "PaymentSimulatorAdapter",
    "PreconditionResult",
    "RegistryEntry",
    "RowEffectRequest",
    "SQLiteRowAdapter",
    "SandboxOutbox",
    "SentMessage",
    "TrustedAdapterRegistry",
    "build_reference_registry",
    "facts_from_capability",
    "reference_adapter_capabilities",
]
