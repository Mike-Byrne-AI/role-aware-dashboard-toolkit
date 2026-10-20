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
PUBLIC_EXTRAS = {"workbench", "auth", "api", "pandas", "full"}
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
        *extras["auth"],
        *extras["api"],
        *extras["pandas"],
    }
    rendered = str(extras).lower()
    for forbidden in ("pillow", "repoos", "builder", "harness", "pack-"):
        assert forbidden not in rendered


def test_host_extras_require_reviewed_dependency_floors_without_changing_core():
    project = _load_pyproject()["project"]
    extras = project["optional-dependencies"]
    server_floors = {
        "starlette>=1.3.1",
        "anyio>=4.14.2",
        "python-multipart>=0.0.31",
        "h11>=0.16.0",
        "urllib3>=2.8.0",
    }
    auth_floors = {
        "streamlit[auth]>=1.65.0",
        "Authlib>=1.6.11",
        "cryptography>=50.0.0",
        "joserfc>=1.7.4",
        *server_floors,
    }

    assert project["dependencies"] == []
    assert project["requires-python"] == ">=3.10"
    assert {"streamlit>=1.65.0", *server_floors} <= set(extras["workbench"])
    api_floors = {
        "fastapi>=0.133.0",
        "starlette>=1.3.1",
        "anyio>=4.14.2",
        "h11>=0.16.0",
    }
    assert api_floors <= set(extras["api"])
    for extra in ("auth", "full", "dev"):
        assert auth_floors <= set(extras[extra]), extra
    assert set(extras["workbench"]) <= set(extras["dev"])
    assert set(extras["auth"]) <= set(extras["dev"])
    assert set(extras["api"]) <= set(extras["dev"])


def test_dependency_floors_install_from_wheels_at_the_lowest_resolution():
    # Checked with `uv pip compile --resolution lowest-direct --only-binary :all:`
    # for Python 3.10-3.14 on Linux, macOS and Windows, then installed and tested.
    # pandas < 2.2.2 fails to import against numpy 2; fastapi 0.133 needs
    # pydantic 2.7; older pandas and pydantic-core lack 3.13/3.14 wheels.
    extras = _load_pyproject()["project"]["optional-dependencies"]
    pandas_floors = {
        "pandas>=2.2.2",
        "pandas>=2.2.3; python_version >= '3.13'",
        "pandas>=2.3.3; python_version >= '3.14'",
    }
    pydantic_floors = {
        "pydantic>=2.7.0",
        "pydantic>=2.8.1; python_version >= '3.13'",
        "pydantic>=2.12.0; python_version >= '3.14'",
    }
    for extra in ("pandas", "full", "dev"):
        assert {dep for dep in extras[extra] if dep.startswith("pandas")} == pandas_floors, extra
    for extra in ("api", "full", "dev"):
        assert {dep for dep in extras[extra] if dep.startswith("pydantic")} == pydantic_floors, extra
    assert "black>=24.1.0" in extras["dev"]


def test_release_checker_requires_metadata_25_compatible_twine():
    extras = _load_pyproject()["project"]["optional-dependencies"]
    assert "twine>=7.0.0" in extras["dev"]


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
        "/examples/operator_review/app.py",
        "/examples/operator_review/workflow.py",
        "/examples/operator_review/report.py",
        "/examples/section_access/app.py",
        "/examples/section_access/demo.py",
        "/examples/section_access/policy.py",
        "/examples/section_access/provision.py",
        "/examples/host_integration/service.py",
        "/examples/host_integration/demo.py",
        "/examples/record_workflows/actions.py",
        "/examples/record_workflows/service.py",
        "/examples/record_workflows/demo.py",
        "/examples/record_workflows/app.py",
        "/examples/record_workflows/acceptance.py",
        "/examples/landscaping/run.py",
        "/examples/business_dashboard/run.py",
        "/examples/business_dashboard/hosting/pilot.py",
        "/examples/business_dashboard/business/__init__.py",
        "/examples/business_dashboard/business/db.py",
        "/examples/business_dashboard/business/security.py",
        "/examples/business_dashboard/business/mfa.py",
        "/examples/business_dashboard/business/abuse.py",
        "/examples/business_dashboard/business/seed.py",
        "/examples/business_dashboard/business/models.py",
        "/examples/business_dashboard/business/request_security.py",
        "/examples/business_dashboard/business/app.py",
        "/examples/business_dashboard/business/auth_routes.py",
        "/examples/business_dashboard/business/submission_routes.py",
        "/examples/business_dashboard/business/work_limits.py",
        "/examples/landscaping/hosting/pilot.py",
        "/examples/landscaping/landscape/__init__.py",
        "/examples/landscaping/landscape/action_workflow.py",
        "/examples/landscaping/landscape/app.py",
        "/examples/landscaping/landscape/db.py",
        "/examples/landscaping/landscape/seed.py",
        "/examples/landscaping/landscape/security.py",
        "/examples/landscaping/landscape/paths.py",
        "/examples/landscaping/landscape/launcher.py",
        "/examples/landscaping/scripts/browser_check.py",
        "/examples/landscaping/scripts/operational_check.py",
        "/examples/landscaping/scripts/hosted_acceptance.py",
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


def test_dev_extra_provides_every_tool_the_suite_skips_without():
    """A test that importorskips a tool the dev extra lacks is skipped in CI, silently."""
    import re

    extras = _load_pyproject()["project"]["optional-dependencies"]
    dev = {re.split(r"[<>=!~;\[ ]", dep, maxsplit=1)[0].lower() for dep in extras["dev"]}
    # Installed by a dev requirement rather than named in it.
    transitive = {"pyarrow": "streamlit"}
    skipped: set[str] = set()
    for path in (REPO_ROOT / "tests").glob("test_*.py"):
        text = path.read_text(encoding="utf-8")
        skipped |= {name.split(".")[0] for name in re.findall(r'importorskip\(\s*"([^"]+)"', text)}
    assert {"streamlit", "fastapi", "mypy"} <= skipped
    missing = sorted(name for name in skipped if name not in dev and transitive.get(name) not in dev)
    assert missing == []
