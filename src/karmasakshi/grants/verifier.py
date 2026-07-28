"""Grant verification: structural, cryptographic, and time-window validity.

This module deliberately does *not* check consumption/use-count or manifest
binding -- those require durable, atomic state (see ``stores/``) and are the
engine's responsibility. This module is pure and side-effect free so it can
be exhaustively unit- and property-tested in isolation.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from karmasakshi.crypto.keyring import Keyring
from karmasakshi.crypto.keys import assert_supported_algorithm
from karmasakshi.errors import GrantExpiredError, GrantNotYetValidError, InvalidSignatureError
from karmasakshi.grants.model import ExecutionGrant
from karmasakshi.protocol.versioning import assert_supported_schema_version


def verify_grant_signature(grant: ExecutionGrant, keyring: Keyring) -> None:
    """Verify schema version, algorithm, and cryptographic signature only."""
    assert_supported_schema_version(grant.schema_version)
    assert_supported_algorithm(grant.algorithm)
    if grant.signature is None:
        raise InvalidSignatureError(f"grant {grant.grant_id} is unsigned")
    payload_hash = grant.canonical_hash()
    keyring.verify(grant.key_id, payload_hash.encode("utf-8"), grant.signature)


def verify_grant_time_window(
    grant: ExecutionGrant,
    now: datetime,
    leeway: timedelta = timedelta(seconds=0),
) -> None:
    """Verify ``now`` falls within ``[not_before - leeway, expires_at + leeway]``."""
    earliest = grant.not_before - leeway
    latest = grant.expires_at + leeway
    if now < earliest:
        raise GrantNotYetValidError(
            f"grant {grant.grant_id} is not valid before {grant.not_before.isoformat()} "
            f"(now={now.isoformat()}, leeway={leeway})"
        )
    if now > latest:
        raise GrantExpiredError(
            f"grant {grant.grant_id} expired at {grant.expires_at.isoformat()} "
            f"(now={now.isoformat()}, leeway={leeway})"
        )


def verify_grant(
    grant: ExecutionGrant,
    keyring: Keyring,
    now: datetime,
    leeway: timedelta = timedelta(seconds=0),
) -> None:
    """Full structural verification: signature, then time window."""
    verify_grant_signature(grant, keyring)
    verify_grant_time_window(grant, now, leeway)


__all__ = ["verify_grant", "verify_grant_signature", "verify_grant_time_window"]
