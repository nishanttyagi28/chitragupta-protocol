"""Shared CLI utilities: output formatting, exit codes, error handling."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any, TypeVar

import typer
from rich.console import Console

from karmasakshi.errors import KarmaSakshiError

console = Console()
err_console = Console(stderr=True)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DENIED = 2

T = TypeVar("T")


def emit(data: dict[str, Any], *, as_json: bool, human: str | None = None) -> None:
    if as_json:
        console.print_json(json.dumps(data, default=str))
    else:
        console.print(human if human is not None else str(data))


def run_guarded(as_json: bool, fn: Callable[[], T]) -> T:
    """Run ``fn``, translating protocol errors into a clean CLI failure with
    a stable exit code instead of a raw traceback."""
    try:
        return fn()
    except KarmaSakshiError as exc:
        if as_json:
            console.print_json(json.dumps({"error": type(exc).__name__, "detail": str(exc)}))
        else:
            err_console.print(f"[bold red]{type(exc).__name__}[/bold red]: {exc}")
        raise typer.Exit(code=EXIT_DENIED) from exc
    except (FileNotFoundError, ValueError, TypeError) as exc:
        if as_json:
            console.print_json(json.dumps({"error": type(exc).__name__, "detail": str(exc)}))
        else:
            err_console.print(f"[bold red]{type(exc).__name__}[/bold red]: {exc}")
        raise typer.Exit(code=EXIT_ERROR) from exc


def fail(message: str, *, as_json: bool, code: int = EXIT_ERROR) -> None:
    if as_json:
        console.print_json(json.dumps({"error": message}))
    else:
        err_console.print(f"[bold red]Error[/bold red]: {message}")
    sys.exit(code)


__all__ = [
    "EXIT_DENIED",
    "EXIT_ERROR",
    "EXIT_OK",
    "console",
    "emit",
    "err_console",
    "fail",
    "run_guarded",
]
