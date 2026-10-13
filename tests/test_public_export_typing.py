"""Root exports are visible to type checkers, not typed Any by the lazy loader."""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit._exports import PUBLIC_EXPORT_MAP

INIT = Path(__file__).resolve().parents[1] / "role_aware_dashboard_toolkit" / "__init__.py"


def expected_type_checking_block() -> str:
    """The import block __init__.py must carry, generated from PUBLIC_EXPORT_MAP."""
    lines = ["if TYPE_CHECKING:"]
    lines += [
        f"    from .{module} import {attr} as {name}"
        for name, (module, attr) in PUBLIC_EXPORT_MAP.items()
    ]
    return "\n".join(lines)


def _type_checking_imports(tree: ast.Module) -> list[tuple[str, str, str]]:
    for node in tree.body:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
            return [
                (str(item.module), alias.name, str(alias.asname))
                for item in node.body if isinstance(item, ast.ImportFrom) and item.level == 1
                for alias in item.names
            ]
    return []


def test_type_checking_imports_match_the_export_map():
    imports = _type_checking_imports(ast.parse(INIT.read_text(encoding="utf-8")))
    expected = [(module, attr, name) for name, (module, attr) in PUBLIC_EXPORT_MAP.items()]

    assert imports == expected, (
        "role_aware_dashboard_toolkit/__init__.py must import every root export for type "
        "checkers. Replace its TYPE_CHECKING block with:\n\n" + expected_type_checking_block()
    )


def test_lazy_loader_is_hidden_from_type_checkers():
    tree = ast.parse(INIT.read_text(encoding="utf-8"))
    top_level_functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}

    assert "__getattr__" not in top_level_functions, (
        "A module-level __getattr__ visible to type checkers types every unknown root "
        "attribute as Any; define it under 'if not TYPE_CHECKING:'."
    )


def test_typos_through_the_root_namespace_are_type_errors(tmp_path):
    pytest.importorskip("mypy")
    probe = tmp_path / "probe.py"
    probe.write_text(textwrap.dedent('''\
        import role_aware_dashboard_toolkit as radt
        from role_aware_dashboard_toolkit import ControlRegistry

        registry: radt.ControlRegistry = radt.ControlRegistry()
        registry.register("Mode", kind="select", options=["a", "b"])
        radt.ControlRegistry().regster("x")
        ControlRegistry().regster("y")
        radt.ControlRegistrx
    '''), encoding="utf-8")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("MYPYPATH", None)
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--cache-dir", str(tmp_path / "cache"),
         "--no-error-summary", "--show-error-codes", "probe.py"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, check=False, timeout=300,
    )
    output = result.stdout + result.stderr
    if "import-not-found" in output or "Cannot find implementation" in output:
        pytest.skip("mypy cannot locate the installed package from this environment")
    probe_errors = sorted(
        line.split(":")[1] for line in output.splitlines()
        if line.startswith("probe.py:") and ": error:" in line
    )

    assert probe_errors == ["6", "7", "8"], output
    assert 'has no attribute "regster"' in output
    assert 'Module has no attribute "ControlRegistrx"' in output


def test_registry_accepts_streamlit_session_state_for_type_checkers(tmp_path):
    """Root exports are now typed, so documented calls with st.session_state must type-check."""
    pytest.importorskip("mypy")
    pytest.importorskip("streamlit")
    probe = tmp_path / "probe.py"
    probe.write_text(textwrap.dedent('''\
        import streamlit as st
        import role_aware_dashboard_toolkit as radt

        registry = radt.ControlRegistry()
        registry.register("Weekly target", kind="number", key="weekly_target", default=40)
        registry.ensure_defaults(st.session_state)
        registry.sanitize_session_state(st.session_state)
        values = registry.persistable_snapshot(st.session_state)
        current = registry.snapshot(st.session_state)
        registry.restore(st.session_state, values)
        registry.mark_user_set("weekly_target", st.session_state)
        if registry.is_user_set("weekly_target", st.session_state):
            registry.clear_user_set("weekly_target", st.session_state)
        registry.clear_all_user_set(st.session_state)
    '''), encoding="utf-8")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("MYPYPATH", None)
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--cache-dir", str(tmp_path / "cache"),
         "--no-error-summary", "--show-error-codes", "probe.py"],
        cwd=str(tmp_path), env=env, text=True, capture_output=True, check=False, timeout=300,
    )
    output = result.stdout + result.stderr
    if "import-not-found" in output or "Cannot find implementation" in output:
        pytest.skip("mypy cannot locate the installed package from this environment")
    assert [line for line in output.splitlines() if line.startswith("probe.py:")] == [], output
