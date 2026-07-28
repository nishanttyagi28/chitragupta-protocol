from __future__ import annotations

from datetime import datetime, timezone

import typer

from chitragupta.cli.common import console, emit
from chitragupta.cli.workspace import Workspace
from chitragupta.errors import ChitraguptaError


def doctor(ctx: typer.Context) -> None:
    """Check workspace configuration, storage connectivity, key availability,
    clock configuration, adapter registration, and audit integrity.

    Never prints secret material -- only pass/fail status and counts.
    """
    workspace: Workspace = ctx.obj["workspace"]
    as_json: bool = ctx.obj["json"]

    checks: list[dict[str, object]] = []

    def check(name: str, fn) -> None:  # type: ignore[no-untyped-def]
        try:
            detail = fn()
            checks.append({"name": name, "status": "ok", "detail": detail})
        except Exception as exc:  # noqa: BLE001 - doctor must report, not crash
            checks.append({"name": name, "status": "fail", "detail": str(exc)})

    def _workspace_check() -> str:
        if not workspace.is_initialized():
            raise ChitraguptaError(f"workspace not initialized at {workspace.root}")
        return str(workspace.root)

    def _keys_check() -> str:
        key_ids = workspace.list_key_ids()
        if not key_ids:
            raise ChitraguptaError("no keys found; run `chitragupta key generate <id>`")
        return f"{len(key_ids)} key(s): {', '.join(key_ids)}"

    def _grant_store_check() -> str:
        store = workspace.open_grant_store()
        store.get_use_count("doctor-probe-nonexistent-grant")
        return f"reachable at {workspace.root / 'grants.db'}"

    def _audit_check() -> str:
        audit = workspace.open_audit()
        audit.verify_chain()
        return f"{len(audit.all_events())} event(s), chain verified"

    def _clock_check() -> str:
        now = datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ChitraguptaError("system clock is not timezone-aware")
        return f"UTC now: {now.isoformat()}"

    def _adapters_check() -> str:
        from chitragupta.adapters.email_sandbox import EmailSandboxAdapter
        from chitragupta.adapters.payment_simulator import PaymentSimulatorAdapter
        from chitragupta.adapters.sqlite_db import SQLiteRowAdapter

        return (
            f"{SQLiteRowAdapter.adapter_id}, {EmailSandboxAdapter.adapter_id}, "
            f"{PaymentSimulatorAdapter.adapter_id}"
        )

    check("workspace", _workspace_check)
    check("keys", _keys_check)
    check("grant_store", _grant_store_check)
    check("audit", _audit_check)
    check("clock", _clock_check)
    check("adapters", _adapters_check)

    any_failed = any(c["status"] == "fail" for c in checks)

    if as_json:
        emit({"checks": checks, "ok": not any_failed}, as_json=True)
    else:
        for c in checks:
            symbol = "[green]OK[/green]" if c["status"] == "ok" else "[red]FAIL[/red]"
            console.print(f"{symbol} {c['name']}: {c['detail']}")

    if any_failed:
        raise typer.Exit(code=1)


__all__ = ["doctor"]
