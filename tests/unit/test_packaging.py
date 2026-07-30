"""RA-006 regression: the `karmasakshi-acceptance` console script is a base
package entry point (`project.scripts` in pyproject.toml), so every runtime
dependency it lazily imports (`httpx`) must be an unconditional base
dependency -- a base `pip install karmasakshi-protocol` with no extras must
be able to run it past the point of importing httpx.

The release audit's exact reproduction: a fresh virtual environment
containing only the built wheel and declared base dependencies could import
and run `karmasakshi.acceptance`'s CLI help, but calling the real command
raised ``ModuleNotFoundError: No module named 'httpx'``.

Deliberately avoids a TOML parser dependency (the project supports Python
3.10, where stdlib ``tomllib`` does not exist yet) -- this only needs to
locate one bracketed array in a known-shape file.
"""

from __future__ import annotations

import re
from pathlib import Path

PYPROJECT_PATH = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _base_dependencies_block() -> str:
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    match = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, flags=re.DOTALL | re.MULTILINE)
    assert match is not None, "could not locate [project] dependencies array in pyproject.toml"
    return match.group(1)


def test_httpx_is_a_base_dependency_not_only_an_extra() -> None:
    block = _base_dependencies_block()
    assert '"httpx' in block, (
        "httpx must be a base dependency: `karmasakshi-acceptance` "
        "(project.scripts) imports it at runtime and is installed "
        "unconditionally, not behind an extra"
    )


def test_acceptance_console_script_is_registered_in_base_project() -> None:
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    assert 'karmasakshi-acceptance = "karmasakshi.acceptance:main"' in text


def test_acceptance_module_imports_httpx_lazily_inside_functions_not_at_module_scope() -> None:
    """Guard the specific shape of the bug: httpx must not become a hard
    import-time failure for anything that merely imports the module (e.g.
    ``--help``), while still being required once the command actually
    runs -- both are satisfied by keeping the import inside the function
    body, which this test pins so a future refactor doesn't accidentally
    move it back to module scope in a way that breaks `--help` elsewhere.
    """
    source = Path("src/karmasakshi/acceptance.py").read_text(encoding="utf-8")
    module_level_lines = [
        line
        for line in source.splitlines()
        if line.strip() == "import httpx" and not line.startswith((" ", "\t"))
    ]
    assert module_level_lines == []
    assert "    import httpx" in source
