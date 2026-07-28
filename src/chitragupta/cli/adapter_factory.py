"""Resolves the CLI's ``--adapter`` choice to a concrete reference adapter.

Only the three reference adapters ship with the CLI; third-party adapters
are wired programmatically via the Python API (see docs/adapter-authoring.md),
not dynamically loaded from CLI strings, to avoid an arbitrary-code-loading
surface in a security-focused CLI.

Note: the payment and email adapters hold their state in memory, so a
fresh CLI process starts them from empty (zero balance / empty outbox).
Only the SQLite adapter persists naturally across separate CLI
invocations. Use ``chitragupta demo`` to see a full single-process
walkthrough of all three, or drive the Python API directly for real
multi-step usage.
"""

from __future__ import annotations

from typing import Annotated

import typer

from chitragupta.adapters.base import EffectAdapter
from chitragupta.adapters.email_sandbox import EmailRequest, EmailSandboxAdapter, SandboxOutbox
from chitragupta.adapters.payment_simulator import (
    PaymentRequest,
    PaymentSimulator,
    PaymentSimulatorAdapter,
)
from chitragupta.adapters.sqlite_db import RowEffectRequest, RowOperation, SQLiteRowAdapter
from chitragupta.domain.common import Principal

AdapterChoice = Annotated[str, typer.Option("--adapter", help="One of: sqlite, email, payment")]


def build_adapter(
    choice: str,
    *,
    sqlite_db_path: str | None,
    sqlite_table: str,
    fund_source_account: int | None,
    fund_account_id: str,
) -> EffectAdapter:
    if choice == "sqlite":
        if not sqlite_db_path:
            raise ValueError("--sqlite-db-path is required for the sqlite adapter")
        return SQLiteRowAdapter(sqlite_db_path, table=sqlite_table)
    if choice == "email":
        return EmailSandboxAdapter(SandboxOutbox())
    if choice == "payment":
        simulator = PaymentSimulator()
        if fund_source_account is not None:
            simulator.fund_account(fund_account_id, fund_source_account)
        return PaymentSimulatorAdapter(simulator)
    raise ValueError(f"unknown adapter choice: {choice!r} (expected sqlite, email, or payment)")


def build_request(
    choice: str,
    *,
    actor: Principal,
    principal: Principal,
    idempotency_key: str,
    ttl_seconds: int,
    row_operation: RowOperation | None,
    row_id: str | None,
    new_balance: int | None,
    recipients: list[str],
    subject: str | None,
    body: str | None,
    source_account: str | None,
    beneficiary: str | None,
    amount_minor_units: int | None,
    currency: str,
    reference: str | None,
    fee_minor_units: int,
) -> RowEffectRequest | EmailRequest | PaymentRequest:
    if choice == "sqlite":
        if not row_operation or not row_id:
            raise ValueError("--row-operation and --row-id are required for the sqlite adapter")
        return RowEffectRequest(
            operation=row_operation,
            row_id=row_id,
            actor=actor,
            principal=principal,
            new_balance=new_balance,
            idempotency_key=idempotency_key,
            ttl_seconds=ttl_seconds,
        )
    if choice == "email":
        if not recipients or not subject or body is None:
            raise ValueError(
                "--recipient, --subject, and --body are required for the email adapter"
            )
        return EmailRequest(
            actor=actor,
            principal=principal,
            recipients=tuple(recipients),
            subject=subject,
            body=body,
            idempotency_key=idempotency_key,
            ttl_seconds=ttl_seconds,
        )
    if choice == "payment":
        if not source_account or not beneficiary or amount_minor_units is None or not reference:
            raise ValueError(
                "--source-account, --beneficiary, --amount-minor-units, and --reference "
                "are required for the payment adapter"
            )
        return PaymentRequest(
            actor=actor,
            principal=principal,
            source_account=source_account,
            beneficiary=beneficiary,
            amount_minor_units=amount_minor_units,
            currency=currency,
            reference=reference,
            fee_minor_units=fee_minor_units,
            idempotency_key=idempotency_key,
            ttl_seconds=ttl_seconds,
        )
    raise ValueError(f"unknown adapter choice: {choice!r} (expected sqlite, email, or payment)")


__all__ = ["AdapterChoice", "build_adapter", "build_request"]
