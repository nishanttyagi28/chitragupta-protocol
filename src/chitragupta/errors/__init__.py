"""Shared exception hierarchy for Chitragupta Protocol.

All security-relevant failures raise a subclass of :class:`ChitraguptaError` so
callers can fail closed deterministically instead of relying on generic
exceptions. Messages must never leak secrets (private keys, raw tokens,
full credential material) -- see docs/security-model.md.
"""

from __future__ import annotations


class ChitraguptaError(Exception):
    """Base class for all protocol errors."""


# --- Manifest / canonicalization -------------------------------------------------


class ManifestError(ChitraguptaError):
    """Base class for manifest validation and integrity errors."""


class ManifestValidationError(ManifestError):
    """Manifest failed schema validation (unknown/ambiguous/oversized fields)."""


class ManifestTamperedError(ManifestError):
    """Recomputed manifest hash does not match the sealed hash."""


class SchemaVersionError(ManifestError):
    """Manifest or grant declares an unsupported schema version."""


# --- Cryptography ------------------------------------------------------------------


class CryptoError(ChitraguptaError):
    """Base class for signing/verification errors."""


class UnknownKeyError(CryptoError):
    """Signature references a key id not present in the trusted keyring."""


class InvalidSignatureError(CryptoError):
    """Signature verification failed."""


class UnsupportedAlgorithmError(CryptoError):
    """Requested signing/verification algorithm is not supported."""


class KeyLoadError(CryptoError):
    """Key material could not be loaded safely."""


# --- Grants --------------------------------------------------------------------


class GrantError(ChitraguptaError):
    """Base class for execution grant errors."""


class GrantExpiredError(GrantError):
    pass


class GrantNotYetValidError(GrantError):
    pass


class GrantRevokedError(GrantError):
    pass


class GrantExhaustedError(GrantError):
    """Grant has reached its maximum number of uses."""


class GrantManifestMismatchError(GrantError):
    """Grant's bound manifest_hash does not match the manifest being executed."""


class GrantAudienceError(GrantError):
    """Adapter identity/version is not within the grant's audience."""


class GrantIssuerNotAuthorizedError(GrantError):
    """Attempted to issue/authorize a grant from a principal that may not authorize
    (e.g. the model/agent itself), violating invariant #30."""


# --- Delegation ------------------------------------------------------------------


class DelegationError(ChitraguptaError):
    """Base class for delegation/attenuation errors."""


class ConstraintWideningError(DelegationError):
    """Child grant attempts to widen authority relative to its parent."""


class IncomparableConstraintError(DelegationError):
    """Two constraints cannot be safely compared; treated as widening (fail closed)."""


# --- State machine ---------------------------------------------------------------


class StateMachineError(ChitraguptaError):
    """Base class for lifecycle state machine errors."""


class IllegalTransitionError(StateMachineError):
    """Attempted transition is not permitted from the current state."""


# --- TOCTOU / preconditions -------------------------------------------------------


class PreconditionError(ChitraguptaError):
    """Base class for precondition/TOCTOU failures."""


class StaleManifestError(PreconditionError):
    """Observed external state no longer matches the sealed preconditions."""


# --- Storage / atomicity ----------------------------------------------------------


class StoreError(ChitraguptaError):
    """Base class for storage backend errors. Storage failures must fail closed."""


class StoreUnavailableError(StoreError):
    """Storage backend is unreachable or in an indeterminate state."""


class ConcurrentConsumptionError(StoreError):
    """A concurrent process already consumed/reserved this grant."""


# --- Audit ---------------------------------------------------------------------


class AuditError(ChitraguptaError):
    """Base class for audit journal errors."""


class AuditWriteError(AuditError):
    """Audit record could not be durably written; execution must not proceed."""


class AuditTamperedError(AuditError):
    """Audit chain hash verification failed."""


# --- Adapters --------------------------------------------------------------------


class AdapterError(ChitraguptaError):
    """Base class for effect adapter errors."""


class AdapterMismatchError(AdapterError):
    """Manifest's adapter identity/version does not match the executing adapter."""


class UnsupportedCompensationError(AdapterError):
    """The effect is irreversible and cannot honestly be compensated."""


class BlastRadiusExceededError(AdapterError):
    """Effect would affect more resources than the configured safety ceiling."""


class RecipientNotAllowedError(AdapterError):
    """A recipient/target is not on the adapter's configured allow-list."""
