import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit.distribution import (
    ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY,
    build_distribution_strategy_markdown,
)
from role_aware_dashboard_toolkit.public_api import list_public_api_families
from role_aware_dashboard_toolkit.release_audit import (
    audit_release_artifact_members,
    build_release_audit_markdown,
    build_release_manifest,
)


EXPECTED_FAMILIES = {
    "app-shell",
    "controls-and-security",
    "operator-records",
    "optional-api",
    "packets",
    "profiles-and-audit",
    "release-tooling",
    "runbook-and-snapshots",
    "runtime-and-observability",
    "validation-and-protocol",
}
EXPECTED_ARTIFACTS = {"core", "workbench", "api", "pandas", "full"}


def test_distribution_strategy_is_explicit_and_product_neutral():
    assert (
        ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY
        == "single-package-optional-extras"
    )
    markdown = build_distribution_strategy_markdown()
    assert "single-package-optional-extras" in markdown
    assert "`role-aware-dashboard-toolkit` is the only published package" in markdown
    assert "Product-specific adapters and application integrations are not part" in markdown


def test_public_api_family_registry_is_exactly_the_retained_oss_surface():
    families = {
        item["family_id"]: item
        for item in list_public_api_families()
    }

    assert set(families) == EXPECTED_FAMILIES
    assert all(
        family["classification"] == "stable"
        for family in families.values()
    )
    assert all(
        family["classification"] != "integration-specific"
        for family in families.values()
    )


def test_release_manifest_covers_only_supported_public_artifacts():
    manifest = build_release_manifest()

    assert manifest["version"] == radt.__version__
    assert (
        manifest["distribution_strategy"]
        == ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY
    )
    assert set(manifest["artifact_ids"]) == EXPECTED_ARTIFACTS
    assert "pack_ids" not in manifest
    assert set(manifest["family_ids"]) == EXPECTED_FAMILIES


def test_release_audit_markdown_tracks_the_oss_standard_shape():
    audit_markdown = build_release_audit_markdown()
    lowered = audit_markdown.lower()

    assert f"Version: `{radt.__version__}`" in audit_markdown
    for artifact_id in EXPECTED_ARTIFACTS:
        assert f"`{artifact_id}`" in audit_markdown
    assert "Stable root exports: `58`" in audit_markdown
    assert "Integration-specific root exports" not in audit_markdown
    assert "Undocumented root exports: `0`" in audit_markdown
    for forbidden in ("repoos", "codex builder", "harness", "federation"):
        assert forbidden not in lowered


def test_release_artifact_hygiene_rejects_non_public_material():
    audit = audit_release_artifact_members(
        [
            "role_aware_dashboard_toolkit/__init__.py",
            "docs/release_audit.md",
            "build/__pycache__/cache.cpython-312.pyc",
            ".coverage",
            "assets/.DS_Store",
            "tests/test_private_contract.py",
            "role_aware_dashboard_toolkit/_archive_review/README.md",
            "role_aware_dashboard_toolkit/integrations/product_adapter.py",
            "portable/bundle.json",
            "snapshot_manifests/release.json",
        ]
    )

    assert audit["ok"] is False
    assert set(audit["blocked_members"]) == {
        "build/__pycache__/cache.cpython-312.pyc",
        ".coverage",
        "assets/.DS_Store",
        "tests/test_private_contract.py",
        "role_aware_dashboard_toolkit/_archive_review/README.md",
        "role_aware_dashboard_toolkit/integrations/product_adapter.py",
        "portable/bundle.json",
        "snapshot_manifests/release.json",
    }
    for marker in (
        "__pycache__/",
        "tests/",
        "role_aware_dashboard_toolkit/_archive_review/",
        "role_aware_dashboard_toolkit/integrations/",
        "portable/",
        "snapshot_manifests/",
    ):
        assert marker in audit["blocklist"]
