"""Architecture tests.

A layering rule that is only written down in a README stops being true within
a few pull requests. These tests fail the build instead.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent / "netintel"
HEAVY_DEPENDENCIES = {"PyQt5", "scapy", "nmap", "requests"}


def module_files(*relative: str) -> list[Path]:
    return sorted(path for part in relative for path in (PACKAGE_ROOT / part).rglob("*.py"))


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def top_level(names: set[str]) -> set[str]:
    return {name.split(".")[0] for name in names}


@pytest.mark.parametrize("path", module_files("core"), ids=lambda p: p.name)
def test_core_does_not_import_a_ui_toolkit(path: Path) -> None:
    assert "PyQt5" not in top_level(imported_names(path))


@pytest.mark.parametrize("path", module_files("core"), ids=lambda p: p.name)
def test_core_does_not_import_a_concrete_backend(path: Path) -> None:
    """``core`` talks to ports; adapters own the libraries."""
    offenders = top_level(imported_names(path)) & {"scapy", "nmap", "requests"}
    assert not offenders, f"{path.name} imports {offenders}"


@pytest.mark.parametrize("path", module_files("core", "cli"), ids=lambda p: p.name)
def test_nothing_below_the_ui_imports_the_ui(path: Path) -> None:
    assert not any(name.startswith("netintel.ui") for name in imported_names(path))


@pytest.mark.parametrize("path", module_files("adapters"), ids=lambda p: p.name)
def test_adapters_import_their_libraries_lazily(path: Path) -> None:
    """Heavy imports must sit inside a function, not at module scope.

    This is what keeps ``import netintel`` free of scapy's multi-second import
    and lets the CLI run with none of the optional stack installed.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module_level = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    }
    assert not (module_level & HEAVY_DEPENDENCIES)


def test_importing_the_package_pulls_in_no_optional_dependency() -> None:
    """Run in a subprocess so an earlier test import cannot mask a regression."""
    script = (
        "import sys; import netintel; import netintel.cli.main; "
        "loaded = {name.split('.')[0] for name in sys.modules}; "
        f"bad = loaded & {HEAVY_DEPENDENCIES!r}; "
        "print(sorted(bad))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=PACKAGE_ROOT.parent,
        check=True,
    )
    assert result.stdout.strip() == "[]", result.stdout


def test_every_core_module_has_a_docstring() -> None:
    for path in module_files("core"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert ast.get_docstring(tree), f"{path.name} has no module docstring"
