"""Tests for attacks/run_all.py's Docker-dispatch orchestrator.

The property these tests exist to catch a regression of: a real bug found on the first actual live
verification attempt (`python -m attacks.run_all` on a bare Windows host, no project dependencies
installed) — `run_all.py` imported `attacks.a1`..`a9` at module level, which transitively imports
`pep.pipeline` -> `identity.tokens` -> the `cryptography` package, crashing with
`ModuleNotFoundError` before Docker dispatch mode ever got a chance to run. Docker dispatch mode
must work with only `docker` on PATH and the standard library — never a project dependency install
on the host running the orchestrator.
"""

from __future__ import annotations

import ast
from pathlib import Path

RUN_ALL_PATH = Path(__file__).resolve().parent.parent / "attacks" / "run_all.py"

# Any of these appearing as a top-level (module-level) import in run_all.py would drag in the full
# project dependency set (fastapi, httpx, cryptography, pydantic, ...) just to *decide* which mode
# to run in - exactly the bug this test exists to catch a regression of.
_FORBIDDEN_TOP_LEVEL_MODULES = (
    "attacks.a1",
    "attacks.a2",
    "attacks.a3",
    "attacks.a4",
    "attacks.a5",
    "attacks.a6",
    "attacks.a7",
    "attacks.a8",
    "attacks.a9",
    "attacks.a10",
    "attacks.common",
    "risk.scorer",
    "pep.pipeline",
    "identity.tokens",
)


def _top_level_import_targets() -> set[str]:
    tree = ast.parse(RUN_ALL_PATH.read_text(encoding="utf-8"))
    targets: set[str] = set()
    for node in tree.body:  # module-level statements only - deliberately not ast.walk()
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            targets.add(node.module)
    return targets


def test_run_all_imports_no_project_dependencies_at_module_level():
    """The regression test: Docker dispatch mode must be reachable using only `docker` on PATH and
    the standard library. If this fails, `python -m attacks.run_all` will crash with
    ModuleNotFoundError on any host that has Docker but not this project's Python dependencies
    installed - exactly what happened on the first real live-verification attempt."""
    top_level = _top_level_import_targets()
    offending = {
        mod
        for mod in top_level
        if any(
            mod == forbidden or mod.startswith(forbidden + ".")
            for forbidden in _FORBIDDEN_TOP_LEVEL_MODULES
        )
    }
    assert not offending, (
        f"run_all.py imports {offending} at module level - this pulls in the full project "
        "dependency set (cryptography, fastapi, httpx, ...) before Docker dispatch mode ever "
        "gets a chance to run. Move these imports inside _run_in_process_fallback()."
    )


def test_run_all_only_imports_stdlib_at_module_level():
    """A stronger, positive version of the same property: every module-level import must resolve
    to something in the standard library, not just "not one of the forbidden list.\" """
    import sys

    stdlib_ok = {"json", "shutil", "subprocess", "sys", "__future__"}
    top_level = {mod.split(".")[0] for mod in _top_level_import_targets()}
    non_stdlib = top_level - stdlib_ok - set(sys.stdlib_module_names)
    assert not non_stdlib, f"run_all.py imports non-stdlib modules at module level: {non_stdlib}"


def test_unverified_constant_matches_attacks_common():
    """run_all.py hardcodes "UNVERIFIED" as a literal (attacks.common cannot be imported at module
    level - see above) - this must never silently drift from the real constant."""
    from attacks.common import UNVERIFIED
    from attacks.run_all import _UNVERIFIED

    assert _UNVERIFIED == UNVERIFIED


def test_attack_specs_cover_a1_through_a9_with_correct_services():
    from attacks.run_all import ATTACK_SPECS

    expected = {
        "A1": "agent",
        "A2": "finance-agent",
        "A3": "agent",  # admin_agent has no real service - dispatched from `agent`, always
        #                 structurally UNVERIFIED for its live path (see attacks/a3.py).
        "A4": "agent",
        "A5": "support-agent",
        "A6": "agent",
        "A7": "agent",
        "A8": "finance-agent",
        "A9": "agent",
    }
    actual = {attack_id: service for attack_id, _module_path, service in ATTACK_SPECS}
    assert actual == expected


def test_stack_reachable_returns_false_when_docker_not_on_path(monkeypatch):
    import shutil

    from attacks.run_all import _stack_reachable

    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert _stack_reachable() is False


def test_main_falls_back_to_in_process_mode_when_docker_unreachable(monkeypatch, capsys):
    """End-to-end: with no Docker reachable, main() must run the in-process fallback (importing
    attacks.a1..a9 lazily, inside that one function) and return a nonzero exit code, since nothing
    can be genuinely_verified without a live stack - never crash, never silently claim success."""
    import attacks.run_all as run_all

    monkeypatch.setattr(run_all, "_stack_reachable", lambda: False)
    exit_code = run_all.main()
    assert exit_code != 0
    out = capsys.readouterr().out
    assert "In-process fallback" in out
    assert "GENUINELY VERIFIED" in out
