import subprocess
import sys
from pathlib import Path

import role_aware_dashboard_toolkit
from role_aware_dashboard_toolkit._exports import PUBLIC_EXPORT_MAP, PUBLIC_EXPORTS
from role_aware_dashboard_toolkit.public_api import list_public_exports, public_api_manifest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_root_exports_are_exact_unique_and_resolvable():
    assert tuple(role_aware_dashboard_toolkit.__all__) == PUBLIC_EXPORTS
    assert tuple(PUBLIC_EXPORT_MAP) == PUBLIC_EXPORTS
    assert len(PUBLIC_EXPORTS) == len(set(PUBLIC_EXPORTS)) == 59
    assert list_public_exports() == list(PUBLIC_EXPORTS)
    for symbol in PUBLIC_EXPORTS:
        assert getattr(role_aware_dashboard_toolkit, symbol) is not None


def test_root_has_no_product_or_integration_exports():
    rendered = "\n".join(PUBLIC_EXPORTS).lower()
    for forbidden in (
        "repoos",
        "codex_builder",
        "harness",
        "federation",
        "semantic",
        "pack_registry",
        "portable",
        "harvest",
    ):
        assert forbidden not in rendered
    manifest = public_api_manifest()
    assert manifest["undocumented_export_count"] == 0
    assert set(manifest["export_classification"].values()) == {"stable"}


def test_clean_root_import_loads_no_optional_or_archived_modules():
    script = r"""
import sys
import role_aware_dashboard_toolkit

assert len(role_aware_dashboard_toolkit.__all__) == 59
blocked_roots = {"streamlit", "pandas", "fastapi", "PIL"}
assert blocked_roots.isdisjoint(sys.modules)
blocked_role_aware_dashboard_toolkit = (
    "role_aware_dashboard_toolkit.integrations",
    "role_aware_dashboard_toolkit.codex_builder",
    "role_aware_dashboard_toolkit.federation",
    "role_aware_dashboard_toolkit.semantic",
    "role_aware_dashboard_toolkit.portable",
    "role_aware_dashboard_toolkit._archive_review",
)
assert not any(
    name == prefix or name.startswith(prefix + ".")
    for name in sys.modules
    for prefix in blocked_role_aware_dashboard_toolkit
)
print("ok")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_removed_modules_are_not_importable():
    script = r"""
import importlib.util

removed = (
    "role_aware_dashboard_toolkit.integrations",
    "role_aware_dashboard_toolkit.codex_builder_adapter",
    "role_aware_dashboard_toolkit.federation",
    "role_aware_dashboard_toolkit.semantic_records",
    "role_aware_dashboard_toolkit.portable_core",
    "role_aware_dashboard_toolkit.tools.pack_scaffold",
    "role_aware_dashboard_toolkit.dashboard_stub",
)
for name in removed:
    try:
        spec = importlib.util.find_spec(name)
    except ModuleNotFoundError:
        spec = None
    assert spec is None, name
print("ok")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
