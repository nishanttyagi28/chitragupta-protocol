"""Compensation status: refused / attempted / verified (never conflated)."""

from __future__ import annotations

from enum import Enum


class CompensationStatus(str, Enum):
    """Honest outcome of a compensation effect.

    - ``REFUSED``: compensation was honestly not attempted (irreversible /
      unsupported). Never report this as success.
    - ``ATTEMPTED``: a compensating effect was committed (or the adapter
      reported an attempt). Not yet independently verified.
    - ``VERIFIED``: independent observation confirmed the compensating
      effect matched expectation (mirrors invariants #20/#21).
    """

    REFUSED = "refused"
    ATTEMPTED = "attempted"
    VERIFIED = "verified"


__all__ = ["CompensationStatus"]
