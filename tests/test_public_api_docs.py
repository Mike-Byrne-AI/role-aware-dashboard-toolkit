import pytest

from role_aware_dashboard_toolkit import __all__ as ROOT_EXPORTS
from role_aware_dashboard_toolkit.public_api import (
    build_public_api_reference_markdown,
    iter_documented_public_symbols,
    list_public_api_families,
    public_api_manifest,
)
from role_aware_dashboard_toolkit.public_api_parts.manifest_tools import (
    build_export_classification_map,
)


def test_public_api_manifest_matches_the_small_root_boundary():
    manifest = public_api_manifest()

    assert manifest["exports"] == ROOT_EXPORTS
    assert manifest["export_count"] == 59
    assert manifest["export_count"] <= manifest["root_export_budget"]["total"] == 60
    assert manifest["classification_counts"] == {
        "experimental": 0,
        "stable": 59,
    }
    assert manifest["undocumented_exports"] == []


def test_undocumented_root_export_fails_closed():
    with pytest.raises(
        AssertionError,
        match="Public exports missing a documented API family: undocumented",
    ):
        build_export_classification_map(families=[], exports=["undocumented"])


def test_every_root_export_belongs_to_a_documented_family():
    documented = set(iter_documented_public_symbols())
    assert set(ROOT_EXPORTS) <= documented
    assert len(list_public_api_families()) >= 8


def test_generated_public_api_reference_is_product_neutral():
    markdown = build_public_api_reference_markdown()
    lowered = markdown.lower()

    assert "# Role-Aware Dashboard Toolkit public API families" in markdown
    assert "Total root exports: `59`" in markdown
    for forbidden in (
        "repoos",
        "codex builder",
        "harness",
        "federation",
        "semantic snapshot",
        "pack-sdk",
    ):
        assert forbidden not in lowered


def test_generated_usage_recipes_install_from_source_or_local_wheel():
    markdown = build_public_api_reference_markdown()
    assert "GitHub-source release" in markdown
    assert "From your reviewed toolkit source" in markdown
    assert 'python -m pip install ".[workbench]"' in markdown
    assert 'python -m pip install ".[api]"' in markdown
    assert "absolute source path or reviewed local wheel" in markdown
    assert "No package-index release is assumed" in markdown
    assert "Install `role-aware-dashboard-toolkit[api]`" not in markdown
