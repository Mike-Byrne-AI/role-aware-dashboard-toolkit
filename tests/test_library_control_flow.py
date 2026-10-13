"""Library control flow must survive ``python -O``, which strips assert statements."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit.controls import ControlDef, _sanitize_numeric

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "role_aware_dashboard_toolkit"


def _assert_sites() -> list[str]:
    sites = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        sites.extend(
            f"{path.relative_to(PACKAGE_ROOT.parent).as_posix()}:{node.lineno}"
            for node in ast.walk(tree) if isinstance(node, ast.Assert)
        )
    return sites


def test_shipped_code_does_not_use_assert_for_control_flow():
    assert _assert_sites() == []


@pytest.mark.parametrize("kind", ["number", "slider"])
def test_numeric_sanitizer_falls_back_without_relying_on_assert(kind):
    control = ControlDef(name="Limit", kind=kind, key="limit", default=None,
                         min_value=None, max_value=None)

    assert _sanitize_numeric(control, "not-a-number") == 0.0
