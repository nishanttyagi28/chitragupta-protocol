"""Constrained Decision Envelopes: the authorized parameter space for one effect.

A ``DecisionEnvelope`` is a signed, versioned bound on what concrete
``EffectManifest`` parameters (and related identity fields) may be
authorized. It is the Phase 6 counterpart to binding a grant to one exact
manifest hash: authorization may instead bind to this envelope's hash, and
any later concrete effect must fit inside it.

A grant may bind to *either* a decision envelope *or* a sealed causal
effect graph (atomic plan), never both. See docs/decision-envelopes.md.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from karmasakshi.canonical.serialize import canonical_hash
from karmasakshi.config.clock import ensure_utc
from karmasakshi.domain.common import AdapterIdentity, MonetaryAmount, Principal
from karmasakshi.domain.enums import PrincipalType
from karmasakshi.domain.manifest import EffectManifest
from karmasakshi.envelope.constraints import (
    ParameterConstraint,
    assert_constraint_narrower_or_equal,
    validate_constraint_key,
)
from karmasakshi.errors import (
    DecisionEnvelopeConstraintError,
    DecisionEnvelopeIssuerNotAuthorizedError,
    DecisionEnvelopeMismatchError,
    IncomparableConstraintError,
)

MAX_ENVELOPE_CONSTRAINTS = 64
MAX_TARGET_RESOURCES = 64
ENVELOPE_SCHEMA_VERSION = "1.0"


class DecisionEnvelope(BaseModel):
    """Canonical constrained decision space for one authorized effect family.

    Immutable. ``canonical_hash()`` binds every field. The issuer must be a
    human or service principal -- never an agent (mirrors invariant #30).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = ENVELOPE_SCHEMA_VERSION
    envelope_id: str
    effect_type: str
    adapter: AdapterIdentity
    target_resources: tuple[str, ...]
    parameter_constraints: dict[str, ParameterConstraint]
    #: When True (default), every key in a candidate manifest's
    #: ``parameters`` must appear in ``parameter_constraints``. Extra keys
    #: fail closed rather than being silently ignored.
    forbid_unknown_parameters: bool = True
    #: When True (default), every key in ``parameter_constraints`` must be
    #: present on the candidate manifest.
    require_all_constrained_parameters: bool = True
    max_estimated_cost: MonetaryAmount | None = None
    #: Optional binding to one sealed causal graph. When set, a grant that
    #: carries this envelope's hash is also plan-scoped to that graph; the
    #: grant itself still records only ``decision_envelope_hash`` (the
    #: envelope hash covers the graph hash). A grant may not *also* set
    #: ``causal_graph_hash`` directly -- see ``ExecutionGrant`` validation.
    causal_graph_hash: str | None = None
    issuer: Principal
    created_at: datetime
    not_before: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    algorithm: Literal["ed25519"] = "ed25519"
    signature: str | None = None

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != ENVELOPE_SCHEMA_VERSION:
            raise ValueError(f"unsupported decision envelope schema_version {value!r}")
        return value

    @field_validator("envelope_id", "effect_type", "nonce", "key_id")
    @classmethod
    def _ids(cls, value: str) -> str:
        if not value or len(value) > 128:
            raise ValueError("must be 1-128 chars")
        return value

    @field_validator("target_resources")
    @classmethod
    def _targets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("target_resources must contain at least one resource")
        if len(value) > MAX_TARGET_RESOURCES:
            raise ValueError(f"target_resources exceeds {MAX_TARGET_RESOURCES}")
        if len(set(value)) != len(value):
            raise ValueError("target_resources must be unique")
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("each target_resource must be 1-256 chars")
            if any(ord(c) < 0x20 for c in item):
                raise ValueError("target_resource must not contain control characters")
        return tuple(sorted(value))

    @field_validator("parameter_constraints")
    @classmethod
    def _constraints(cls, value: dict[str, ParameterConstraint]) -> dict[str, ParameterConstraint]:
        if len(value) > MAX_ENVELOPE_CONSTRAINTS:
            raise ValueError(f"at most {MAX_ENVELOPE_CONSTRAINTS} parameter constraints")
        normalized: dict[str, ParameterConstraint] = {}
        for key, constraint in value.items():
            validate_constraint_key(key)
            normalized[key] = constraint
        return dict(sorted(normalized.items()))

    @field_validator("causal_graph_hash")
    @classmethod
    def _graph_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("sha256:") or len(value) != len("sha256:") + 64:
            raise ValueError("causal_graph_hash must be a sha256:<hex> digest")
        return value

    @field_validator("created_at", "not_before", "expires_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def _window_and_issuer(self) -> DecisionEnvelope:
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must be strictly after not_before")
        return self

    def signing_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", exclude={"signature"})

    def canonical_hash(self) -> str:
        return canonical_hash(self.signing_payload())

    def is_effective_at(self, when: datetime) -> bool:
        when = ensure_utc(when)
        return self.not_before <= when < self.expires_at


def build_decision_envelope(
    *,
    effect_type: str,
    adapter: AdapterIdentity,
    target_resources: tuple[str, ...],
    parameter_constraints: dict[str, ParameterConstraint],
    issuer: Principal,
    not_before: datetime,
    expires_at: datetime,
    signing_key_id: str,
    envelope_id: str | None = None,
    nonce: str | None = None,
    created_at: datetime | None = None,
    forbid_unknown_parameters: bool = True,
    require_all_constrained_parameters: bool = True,
    max_estimated_cost: MonetaryAmount | None = None,
    causal_graph_hash: str | None = None,
) -> DecisionEnvelope:
    """Construct an *unsigned* decision envelope (signature is ``None``).

    Raises :class:`DecisionEnvelopeIssuerNotAuthorizedError` if ``issuer``
    is an agent principal.
    """
    from karmasakshi.config.clock import SYSTEM_CLOCK

    if issuer.principal_type == PrincipalType.AGENT:
        raise DecisionEnvelopeIssuerNotAuthorizedError(
            "an agent principal cannot issue a decision envelope; "
            "authorization constraints must come from a human or service "
            "principal (invariant #30 applied to envelopes)"
        )

    return DecisionEnvelope(
        envelope_id=envelope_id or str(uuid.uuid4()),
        effect_type=effect_type,
        adapter=adapter,
        target_resources=target_resources,
        parameter_constraints=parameter_constraints,
        forbid_unknown_parameters=forbid_unknown_parameters,
        require_all_constrained_parameters=require_all_constrained_parameters,
        max_estimated_cost=max_estimated_cost,
        causal_graph_hash=causal_graph_hash,
        issuer=issuer,
        created_at=created_at or SYSTEM_CLOCK.now(),
        not_before=not_before,
        expires_at=expires_at,
        nonce=nonce or uuid.uuid4().hex,
        key_id=signing_key_id,
        signature=None,
    )


def assert_manifest_fits_envelope(manifest: EffectManifest, envelope: DecisionEnvelope) -> None:
    """Raise if ``manifest`` is outside ``envelope``'s authorized space.

    Checks effect type, adapter identity/version, target resource allow-list,
    every parameter constraint, unknown-parameter policy, required-parameter
    policy, and optional ``max_estimated_cost``.
    """
    if manifest.effect_type != envelope.effect_type:
        raise DecisionEnvelopeConstraintError(
            f"manifest effect_type {manifest.effect_type!r} does not match "
            f"envelope {envelope.effect_type!r}"
        )
    if (
        manifest.adapter.adapter_id != envelope.adapter.adapter_id
        or manifest.adapter.adapter_version != envelope.adapter.adapter_version
    ):
        raise DecisionEnvelopeConstraintError(
            f"manifest adapter {manifest.adapter.adapter_id}@"
            f"{manifest.adapter.adapter_version} does not match envelope "
            f"{envelope.adapter.adapter_id}@{envelope.adapter.adapter_version}"
        )
    if manifest.target_resource not in envelope.target_resources:
        raise DecisionEnvelopeConstraintError(
            f"manifest target_resource {manifest.target_resource!r} is not in "
            f"envelope allow-list {list(envelope.target_resources)!r}"
        )

    params = manifest.parameters
    constrained_keys = set(envelope.parameter_constraints)
    param_keys = set(params)

    if envelope.forbid_unknown_parameters:
        unknown = sorted(param_keys - constrained_keys)
        if unknown:
            raise DecisionEnvelopeConstraintError(
                f"manifest has parameters outside envelope constraints: {unknown}"
            )
    if envelope.require_all_constrained_parameters:
        missing = sorted(constrained_keys - param_keys)
        if missing:
            raise DecisionEnvelopeConstraintError(
                f"manifest is missing required constrained parameters: {missing}"
            )

    for key, constraint in envelope.parameter_constraints.items():
        if key not in params:
            continue
        try:
            constraint.accepts(params[key])
        except DecisionEnvelopeConstraintError as exc:
            raise DecisionEnvelopeConstraintError(
                f"parameter {key!r} violates envelope constraint: {exc}"
            ) from exc

    if envelope.max_estimated_cost is not None:
        cost = manifest.estimated_cost
        if cost is None:
            raise DecisionEnvelopeConstraintError(
                "envelope caps max_estimated_cost but manifest has no estimated_cost"
            )
        if cost.currency != envelope.max_estimated_cost.currency:
            raise DecisionEnvelopeConstraintError(
                f"manifest estimated_cost currency {cost.currency!r} does not match "
                f"envelope cap currency {envelope.max_estimated_cost.currency!r}"
            )
        if cost.minor_units > envelope.max_estimated_cost.minor_units:
            raise DecisionEnvelopeConstraintError(
                f"manifest estimated_cost {cost} exceeds envelope cap {envelope.max_estimated_cost}"
            )


def assert_envelope_narrower_or_equal(child: DecisionEnvelope, parent: DecisionEnvelope) -> None:
    """Raise if ``child`` widens authority relative to ``parent``.

    Used for envelope attenuation / adversarial widening tests. Incomparable
    dimensions (e.g. different effect types or adapter identities) fail closed.
    """
    if child.effect_type != parent.effect_type:
        raise IncomparableConstraintError(
            f"effect_type: cannot attenuate {child.effect_type!r} from "
            f"{parent.effect_type!r}; treated as widening"
        )
    if (
        child.adapter.adapter_id != parent.adapter.adapter_id
        or child.adapter.adapter_version != parent.adapter.adapter_version
    ):
        raise IncomparableConstraintError(
            "adapter: child and parent adapter identities differ; treated as widening"
        )
    if not set(child.target_resources).issubset(parent.target_resources):
        extra = sorted(set(child.target_resources) - set(parent.target_resources))
        raise DecisionEnvelopeConstraintError(
            f"target_resources: child allows {extra} which parent does not"
        )
    if parent.max_estimated_cost is not None:
        if child.max_estimated_cost is None:
            raise DecisionEnvelopeConstraintError(
                "max_estimated_cost: child is unrestricted but parent caps cost"
            )
        if child.max_estimated_cost.currency != parent.max_estimated_cost.currency:
            raise IncomparableConstraintError(
                "max_estimated_cost: currency mismatch; treated as widening"
            )
        if child.max_estimated_cost.minor_units > parent.max_estimated_cost.minor_units:
            raise DecisionEnvelopeConstraintError(
                "max_estimated_cost: child cap exceeds parent cap"
            )
    if parent.causal_graph_hash is not None:
        if child.causal_graph_hash != parent.causal_graph_hash:
            raise DecisionEnvelopeConstraintError(
                "causal_graph_hash: child must preserve the parent's sealed graph binding"
            )
    elif child.causal_graph_hash is not None:
        raise DecisionEnvelopeConstraintError(
            "causal_graph_hash: child introduces a graph binding the parent did not have"
        )

    # Child may not relax unknown-parameter / required-parameter strictness.
    if parent.forbid_unknown_parameters and not child.forbid_unknown_parameters:
        raise DecisionEnvelopeConstraintError(
            "forbid_unknown_parameters: child relaxes parent's strict unknown-key policy"
        )
    if parent.require_all_constrained_parameters and not child.require_all_constrained_parameters:
        raise DecisionEnvelopeConstraintError(
            "require_all_constrained_parameters: child relaxes parent's required-key policy"
        )

    parent_keys = set(parent.parameter_constraints)
    child_keys = set(child.parameter_constraints)

    # Child may add constraints (narrower) or keep the same keys; removing a
    # parent constraint would widen the space for that parameter.
    missing = sorted(parent_keys - child_keys)
    if missing:
        raise DecisionEnvelopeConstraintError(
            f"parameter_constraints: child drops parent constraints for {missing}"
        )

    for key in sorted(parent_keys):
        assert_constraint_narrower_or_equal(
            child.parameter_constraints[key],
            parent.parameter_constraints[key],
            name=key,
        )

    if child.expires_at > parent.expires_at:
        raise DecisionEnvelopeConstraintError("expires_at: child outlives parent")
    if child.not_before < parent.not_before:
        raise DecisionEnvelopeConstraintError("not_before: child starts before parent")


def require_matching_envelope_hash(envelope: DecisionEnvelope, expected_hash: str) -> None:
    actual = envelope.canonical_hash()
    if actual != expected_hash:
        raise DecisionEnvelopeMismatchError(
            f"decision envelope hash mismatch: recomputed {actual} != expected {expected_hash}"
        )


__all__ = [
    "ENVELOPE_SCHEMA_VERSION",
    "MAX_ENVELOPE_CONSTRAINTS",
    "MAX_TARGET_RESOURCES",
    "DecisionEnvelope",
    "assert_envelope_narrower_or_equal",
    "assert_manifest_fits_envelope",
    "build_decision_envelope",
    "require_matching_envelope_hash",
]
