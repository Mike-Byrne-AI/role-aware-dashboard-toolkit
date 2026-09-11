from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 CI
    import tomli as tomllib

from role_aware_dashboard_toolkit.distribution import (
    ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY,
    build_distribution_reference_markdown,
    build_distribution_strategy_markdown,
    build_install_target,
    build_release_gate_reference_markdown,
    list_distribution_artifacts,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_EXTRAS = {"workbench", "api", "pandas", "full"}
ARCHIVE_EXCLUDES = {
    "/role_aware_dashboard_toolkit/_archive_review",
    "/role_aware_dashboard_toolkit/_archive_review/**",
}


def _load_pyproject() -> dict:
    return tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )


def test_package_declares_pep561_marker_file():
    assert (REPO_ROOT / "role_aware_dashboard_toolkit" / "py.typed").is_file()


def test_distribution_artifacts_are_exactly_the_oss_standard_shapes():
    artifacts = {
        item["artifact_id"]: item
        for item in list_distribution_artifacts()
    }

    assert set(artifacts) == {"core", *PUBLIC_EXTRAS}
    assert artifacts["core"]["install_target"] == "role-aware-dashboard-toolkit"
    for extra_name in PUBLIC_EXTRAS:
        assert (
            artifacts[extra_name]["install_target"]
            == f"role-aware-dashboard-toolkit[{extra_name}]"
        )
    assert all("pack_ids" not in artifact for artifact in artifacts.values())


def test_install_target_is_deterministic():
    assert build_install_target("role-aware-dashboard-toolkit") == "role-aware-dashboard-toolkit"
    assert (
        build_install_target("role-aware-dashboard-toolkit", ("api", "pandas"))
        == "role-aware-dashboard-toolkit[api,pandas]"
    )


def test_pyproject_declares_only_public_runtime_extras_and_dev_tooling():
    pyproject = _load_pyproject()
    extras = pyproject["project"]["optional-dependencies"]

    assert set(extras) == {*PUBLIC_EXTRAS, "dev"}
    assert set(extras["full"]) == {
        *extras["workbench"],
        *extras["api"],
        *extras["pandas"],
    }
    rendered = str(extras).lower()
    for forbidden in ("pillow", "repoos", "builder", "harness", "pack-"):
        assert forbidden not in rendered


def test_wheel_and_sdist_explicitly_exclude_archive_review_material():
    pyproject = _load_pyproject()
    targets = pyproject["tool"]["hatch"]["build"]["targets"]

    assert set(targets["wheel"]["exclude"]) == ARCHIVE_EXCLUDES
    assert set(targets["sdist"]["exclude"]) == ARCHIVE_EXCLUDES


def test_sdist_uses_explicit_public_docs_examples_and_schema_allowlists():
    include = set(
        _load_pyproject()["tool"]["hatch"]["build"]["targets"]["sdist"][
            "include"
        ]
    )

    assert "/role_aware_dashboard_toolkit" in include
    assert "/docs" not in include
    assert "/schemas" not in include
    assert "/portable" not in include
    assert "/snapshot_manifests" not in include
    assert {
        path
        for path in include
        if path.startswith("/examples/") and path.endswith(".py")
    } == {
        "/examples/core_library.py",
        "/examples/dashboard_admin_controls_app.py",
        "/examples/plugin_template.py",
        "/examples/studio_dispatch/app.py",
    }
    assert not any("semantic" in path.lower() for path in include)
    assert not any("builder" in path.lower() for path in include)
    assert not any("harness" in path.lower() for path in include)
    assert not any("repoos" in path.lower() for path in include)


def test_ruff_ignores_do_not_reference_archived_product_modules():
    ignores = _load_pyproject()["tool"]["ruff"]["lint"]["per-file-ignores"]

    assert set(ignores) == {
        "role_aware_dashboard_toolkit/__init__.py",
        "role_aware_dashboard_toolkit/*.py",
        "role_aware_dashboard_toolkit/**/*.py",
        "tests/**/*.py",
        "tools/**/*.py",
    }
    rendered = str(ignores).lower()
    for forbidden in ("repoos", "semantic_records", "builder", "harness"):
        assert forbidden not in rendered


def test_distribution_reference_contains_no_product_integration_lane():
    rendered = "\n".join(
        [
            build_distribution_reference_markdown(),
            build_distribution_strategy_markdown(),
            build_release_gate_reference_markdown(),
        ]
    ).lower()

    assert ROLE_AWARE_DASHBOARD_TOOLKIT_DISTRIBUTION_STRATEGY == "single-package-optional-extras"
    for forbidden in (
        "repoos",
        "codex builder",
        "harness",
        "federation",
        "pack-sdk",
    ):
        assert forbidden not in rendered
    assert "dependency-free core" in rendered
    assert "product-specific adapters and application integrations are not part" in rendered
