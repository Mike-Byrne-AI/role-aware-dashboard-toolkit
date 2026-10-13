import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import __version__
from role_aware_dashboard_toolkit.version import __version__ as version_module_version

import tests.conftest as conftest_module
from tests.release_hygiene_helpers import (
    DEMOTED_CI_ROOT_SYMBOLS,
    REPO_ROOT,
    extract_permissions_blocks,
    extract_python_matrix_versions,
    extract_top_level_permissions,
    load_pyproject,
    read_ci_workflow,
)


def test_runtime_version_matches_pyproject_version():
    pyproject = load_pyproject()
    assert pyproject["project"]["version"] == __version__


def test_changelog_mentions_current_runtime_version():
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## {__version__}" in changelog


def test_changelog_starts_with_canonical_heading():
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    lines = changelog.splitlines()
    assert lines
    assert lines[0].strip() == "# Changelog"
    assert sum(1 for line in lines if line.strip() == "# Changelog") == 1


def test_gitignore_blocks_local_cache_artifacts():
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    for marker in [
        ".coverage",
        ".pytest_cache/",
        ".pytest-runtime-tmp/",
        ".mypy_cache/",
        ".ruff_cache/",
        "__pycache__/",
        ".wheel-smoke/",
        ".wheel-smoke-win/",
        ".wheel-extras-smoke/",
        ".sdist-smoke/",
        ".release-smoke/",
        ".testpypi-smoke/",
        ".pypi-smoke/",
    ]:
        assert marker in gitignore


def test_public_code_and_docs_do_not_carry_mojibake_or_banner_markers():
    markers = ("\u00e2", "\ufffd", "\u2550", "\u2500")
    scanned_roots = [
        "role_aware_dashboard_toolkit",
        "docs",
        "tools",
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "pyproject.toml",
    ]
    excluded_parts = {
        "history",
        "fixtures",
        "repoos_visuals",
    }
    checked_suffixes = {".py", ".md", ".toml"}
    offenders = []
    for root_name in scanned_roots:
        root = REPO_ROOT / root_name
        paths = [root] if root.is_file() else list(root.rglob("*"))
        for path in paths:
            relative = path.relative_to(REPO_ROOT)
            if not path.is_file() or path.suffix not in checked_suffixes:
                continue
            if any(part in excluded_parts for part in relative.parts):
                continue
            text = path.read_text(encoding="utf-8")
            if any(marker in text for marker in markers):
                offenders.append(relative.as_posix())

    assert offenders == []


def test_pytest_cacheprovider_is_disabled_for_workbench_runs():
    pyproject = load_pyproject()
    addopts = pyproject["tool"]["pytest"]["ini_options"]["addopts"]
    assert "-p no:cacheprovider" in addopts
    assert "--cov" not in addopts


def test_lint_selection_is_explicit_across_ruff_default_changes():
    lint = load_pyproject()["tool"]["ruff"]["lint"]
    assert set(lint["select"]) == {"E4", "E7", "E9", "F"}


def test_ci_and_contributor_commands_disable_bytecode_before_python_startup():
    for workflow_name in ("ci.yml", "contributor-ci.yml", "dependency-audit.yml"):
        workflow = (REPO_ROOT / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
        assert re.search(r'^env:\n  PYTHONDONTWRITEBYTECODE: "1"$', workflow, re.MULTILINE)
    for relative_path in (
        "CONTRIBUTING.md", "docs/release_checklist.md",
    ):
        document = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        setting = document.index('$env:PYTHONDONTWRITEBYTECODE = "1"')
        assert setting < document.index("-m pytest")


def test_pytest_uses_managed_workspace_basetemp_by_default():
    conftest = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    checklist = (REPO_ROOT / "docs" / "release_checklist.md").read_text(encoding="utf-8")
    checklist_lower = checklist.lower()

    for marker in [
        ".pytest-runtime-tmp",
        "pytest_configure",
        "pytest_sessionfinish",
        "_role_aware_dashboard_toolkit_managed_basetemp",
        "_role_aware_dashboard_toolkit_managed_basetemp_root",
        "tempfile.mkdtemp",
        "shutil.rmtree",
        "_emit_managed_basetemp_cleanup_warning",
        "managed basetemp cleanup failed",
        "_emit_managed_basetemp_cleanup_refusal",
        "managed basetemp cleanup refused",
    ]:
        assert marker in conftest
    assert '".pytest-runtime-tmp"' in (REPO_ROOT / "tools" / "pre_release_check.py").read_text(encoding="utf-8")
    assert ".pytest-runtime-tmp/" in checklist
    assert "unique session-owned child" in checklist_lower
    assert "explicit `--basetemp` overrides must be cleaned" in checklist_lower


def test_managed_pytest_basetemp_is_unique_and_cleanup_is_session_scoped(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(conftest_module, "ROOT", tmp_path)
    managed_root = tmp_path / "managed"
    monkeypatch.setattr(
        conftest_module, "_MANAGED_BASETEMP_ROOT", managed_root
    )
    config_a = SimpleNamespace(option=SimpleNamespace(basetemp=None))
    config_b = SimpleNamespace(option=SimpleNamespace(basetemp=None))

    conftest_module.pytest_configure(config_a)
    conftest_module.pytest_configure(config_b)

    target_a = Path(config_a.option.basetemp)
    target_b = Path(config_b.option.basetemp)
    assert target_a != target_b
    assert target_a.parent == managed_root.resolve()
    assert target_b.parent == managed_root.resolve()
    (target_a / "a.txt").write_text("owned by a", encoding="utf-8")
    sentinel_b = target_b / "b.txt"
    sentinel_b.write_text("owned by b", encoding="utf-8")

    conftest_module.pytest_sessionfinish(
        SimpleNamespace(config=config_a), exitstatus=0
    )

    assert not target_a.exists()
    assert sentinel_b.read_text(encoding="utf-8") == "owned by b"

    conftest_module.pytest_sessionfinish(
        SimpleNamespace(config=config_b), exitstatus=0
    )
    assert not target_b.exists()
    assert managed_root.exists()


def test_managed_pytest_basetemp_preserves_explicit_override(tmp_path):
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    sentinel = explicit / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    config = SimpleNamespace(
        option=SimpleNamespace(basetemp=str(explicit))
    )

    conftest_module.pytest_configure(config)
    conftest_module.pytest_sessionfinish(
        SimpleNamespace(config=config), exitstatus=0
    )

    assert config.option.basetemp == str(explicit)
    assert not hasattr(config, "_role_aware_dashboard_toolkit_managed_basetemp")
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_managed_pytest_cleanup_refuses_non_child_target(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(conftest_module, "ROOT", tmp_path)
    managed_root = tmp_path / "managed"
    monkeypatch.setattr(
        conftest_module, "_MANAGED_BASETEMP_ROOT", managed_root
    )
    config = SimpleNamespace(option=SimpleNamespace(basetemp=None))
    conftest_module.pytest_configure(config)
    owned_target = Path(config.option.basetemp)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    config._role_aware_dashboard_toolkit_managed_basetemp = outside

    conftest_module.pytest_sessionfinish(
        SimpleNamespace(config=config), exitstatus=0
    )

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert "managed basetemp cleanup refused" in capsys.readouterr().err
    config._role_aware_dashboard_toolkit_managed_basetemp = owned_target
    conftest_module.pytest_sessionfinish(
        SimpleNamespace(config=config), exitstatus=0
    )


def test_managed_pytest_cleanup_refuses_redirect_to_sibling_session(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(conftest_module, "ROOT", tmp_path)
    managed_root = tmp_path / "managed"
    monkeypatch.setattr(
        conftest_module, "_MANAGED_BASETEMP_ROOT", managed_root
    )
    config_a = SimpleNamespace(option=SimpleNamespace(basetemp=None))
    config_b = SimpleNamespace(option=SimpleNamespace(basetemp=None))
    conftest_module.pytest_configure(config_a)
    conftest_module.pytest_configure(config_b)
    target_a = Path(config_a.option.basetemp)
    target_b = Path(config_b.option.basetemp)
    sentinel_b = target_b / "keep.txt"
    sentinel_b.write_text("owned by b", encoding="utf-8")
    target_a.rmdir()
    try:
        target_a.symlink_to(target_b, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is not available")

    conftest_module.pytest_sessionfinish(
        SimpleNamespace(config=config_a), exitstatus=0
    )

    assert sentinel_b.read_text(encoding="utf-8") == "owned by b"
    assert "managed basetemp cleanup refused" in capsys.readouterr().err
    target_a.unlink()
    conftest_module.pytest_sessionfinish(
        SimpleNamespace(config=config_b), exitstatus=0
    )


def test_release_hygiene_plugin_loads_before_test_module_collection():
    conftest = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    distribution = (REPO_ROOT / "tests" / "test_release_hygiene_distribution.py").read_text(encoding="utf-8")
    plugin_declaration = 'pytest_plugins = ("tests.release_hygiene_helpers",)'

    assert plugin_declaration in conftest
    assert plugin_declaration not in distribution


def test_coverage_runs_as_dedicated_ci_gate():
    workflow = read_ci_workflow()
    checklist = (REPO_ROOT / "docs" / "release_checklist.md").read_text(encoding="utf-8")
    pyproject = load_pyproject()
    addopts = pyproject["tool"]["pytest"]["ini_options"]["addopts"]
    test_job = workflow.split("  coverage-gate:", 1)[0]
    coverage_job = workflow.split("  coverage-gate:", 1)[1].split("  packaging-release-smoke:", 1)[0]

    assert "--cov" not in addopts
    assert "--cov=role_aware_dashboard_toolkit" not in test_job
    for marker in [
        "coverage-gate:",
        "Coverage gate",
        "pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75",
    ]:
        assert marker in workflow
    for marker in [
        "coverage-gate",
        "--cov-fail-under=75",
        "pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75",
    ]:
        assert marker in checklist
    assert "--cov=role_aware_dashboard_toolkit" in coverage_job
    assert "--cov-fail-under=75" in coverage_job


def test_package_initializer_stays_below_export_table_threshold():
    init_path = REPO_ROOT / "role_aware_dashboard_toolkit" / "__init__.py"
    exports_path = REPO_ROOT / "role_aware_dashboard_toolkit" / "_exports.py"
    init_lines = init_path.read_text(encoding="utf-8").splitlines()
    exports = exports_path.read_text(encoding="utf-8")
    assert len(init_lines) <= 750
    assert "from ._exports import PUBLIC_EXPORT_MAP, PUBLIC_EXPORTS" in init_path.read_text(encoding="utf-8")
    assert "PUBLIC_EXPORT_MAP:" in exports


def test_ci_proves_declared_python_matrix_and_clean_wheel_import():
    workflow = read_ci_workflow()
    permissions = extract_top_level_permissions(workflow)
    permission_blocks = extract_permissions_blocks(workflow)
    versions = extract_python_matrix_versions(workflow)

    assert permissions.get("contents") == "read"
    for _indent, block in permission_blocks:
        assert "id-token" not in block
        assert "packages" not in block
    assert set(versions) == {"3.10", "3.11", "3.12", "3.13", "3.14"}
    assert "3.9" not in versions
    action_refs = re.findall(r"uses:\s+actions/[^@\s]+@([0-9a-f]+)", workflow)
    assert action_refs
    assert all(len(ref) == 40 for ref in action_refs)
    for marker in [
        "Wheel install smoke",
        "Wheel optional-extra smokes",
        "Sdist install smoke",
        "windows-release-smoke",
        "Windows focused tests",
        "python -m pytest tests/test_path_redaction.py tests/test_permission_boundaries.py tests/test_review_identifier_regressions.py tests/test_store_identifier_contract.py -q -p no:cacheprovider -o addopts=",
        "Wheel install smoke (Windows)",
        "Auth wheel install smoke (Windows)",
        'python -m venv "$RUNNER_TEMP/.wheel-smoke"',
        'python -m venv "$RUNNER_TEMP/.wheel-workbench-smoke"',
        'python -m venv "$RUNNER_TEMP/.wheel-auth-smoke"',
        'python -m venv "$RUNNER_TEMP/.wheel-api-smoke"',
        'python -m venv "$RUNNER_TEMP/.wheel-pandas-smoke"',
        'python -m venv "$RUNNER_TEMP/.wheel-full-smoke"',
        'python -m venv "$RUNNER_TEMP/.sdist-smoke"',
        '$venv = Join-Path $env:RUNNER_TEMP ".wheel-smoke-win"',
        '$authVenv = Join-Path $env:RUNNER_TEMP ".wheel-auth-smoke-win"',
        "python -m venv $venv",
        "--no-index --find-links dist role-aware-dashboard-toolkit",
        "role_aware_dashboard_toolkit-*.tar.gz",
        "_is_repo_path",
        "repo in path.parents",
        "tempfile.TemporaryDirectory",
        "os.chdir(tmpdir)",
        "from role_aware_dashboard_toolkit.release_audit import audit_release_artifact_members",
        "from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE",
        "build_run_packet",
    ]:
        assert marker in workflow
    assert '"$RUNNER_TEMP/.sdist-smoke/bin/python" -m pip install --use-pep517 "$sdist"' in workflow
    assert "--no-build-isolation" not in workflow
    assert "pip install hatchling" not in workflow
    for marker in [
        "import fastapi",
        "import pandas",
        "import pydantic",
        "import streamlit",
        "import uvicorn",
    ]:
        assert marker in workflow
    for retired_marker in [
        "codex_builder",
        "harness_plugin",
        "repoos",
        "pack_scaffold",
        "build_standalone_demo_bundle",
        "semantic_snapshot",
    ]:
        assert retired_marker not in workflow.lower()
    for symbol in DEMOTED_CI_ROOT_SYMBOLS:
        assert f"radt.{symbol}" not in workflow
        assert not re.search(
            rf"from\s+role_aware_dashboard_toolkit\s+import\s+(?:\([^)]+\)|[^\n]+)\b{re.escape(symbol)}\b",
            workflow,
            re.MULTILINE,
        )


def test_ci_permission_parser_catches_job_level_publish_scopes():
    workflow = """
permissions:
  contents: read
jobs:
  publish:
    permissions:
      id-token: write
      packages: write
"""
    blocks = extract_permissions_blocks(workflow)

    assert extract_top_level_permissions(workflow) == {"contents": "read"}
    assert any(block.get("id-token") == "write" for _indent, block in blocks)
    assert any(block.get("packages") == "write" for _indent, block in blocks)


def test_ci_python_matrix_parser_handles_multiline_lists():
    workflow = """
strategy:
  matrix:
    python-version:
      - "3.10"
      - "3.11"
      - "3.12"
"""

    assert extract_python_matrix_versions(workflow) == ["3.10", "3.11", "3.12"]


def test_python_support_policy_is_explicit_and_ci_backed():
    pyproject = load_pyproject()
    versions = extract_python_matrix_versions(read_ci_workflow())
    project = pyproject["project"]
    classifiers = set(project["classifiers"])
    dev_deps = project["optional-dependencies"]["dev"]

    assert project["requires-python"] == ">=3.10"
    assert "Programming Language :: Python :: 3.9" not in classifiers
    assert {
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    }.issubset(classifiers)
    assert set(versions) == {"3.10", "3.11", "3.12", "3.13", "3.14"}
    contributor = (REPO_ROOT / ".github" / "workflows" / "contributor-ci.yml").read_text(encoding="utf-8")
    assert set(extract_python_matrix_versions(contributor)) == set(versions)
    assert "3.9" not in versions
    assert any(dep.startswith("tomli>=") and "python_version < '3.11'" in dep for dep in dev_deps)


def test_ci_and_release_checklist_enforce_publication_hygiene():
    pyproject = load_pyproject()
    workflow = read_ci_workflow()
    checklist = (REPO_ROOT / "docs" / "release_checklist.md").read_text(encoding="utf-8")
    dev_deps = pyproject["project"]["optional-dependencies"]["dev"]
    ci_ruff = "python -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache"
    local_ruff = "& $releasePython -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache"
    assert any(dep.startswith("twine>=") for dep in dev_deps)
    assert (
        "python tools/pre_release_check.py --json --require-clean "
        "> pre_release_report.json || true"
    ) in workflow
    for marker in [
        "refs/heads/main",
        "required_checks",
        "oss_public_coordinates",
        "security_intake_contact",
        "pre_release_check requires all local configuration checks to pass",
        '("blocked", "blocked_count"), ("failures", "failure_count"), ("warnings", "warning_count")',
        '"live_validation_required"',
    ]:
        assert marker in workflow
    assert ci_ruff in workflow
    assert "python -m twine check dist/*" in workflow
    assert "from role_aware_dashboard_toolkit.release_audit import audit_release_artifact_members" in workflow
    assert "packaging-release-smoke:" in workflow
    test_job = workflow.split("  packaging-release-smoke:", 1)[0]
    packaging_job = workflow.split("  packaging-release-smoke:", 1)[1].split("  windows-release-smoke:", 1)[0]
    assert "python -m build" not in test_job
    assert "Wheel install smoke" not in test_job
    for marker in [
        "python -m build",
        "Publication hygiene",
        "python -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache",
        "python -m twine check dist/*",
        "Wheel install smoke",
        "Wheel optional-extra smokes",
        "Sdist install smoke",
        "Upload validated distribution artifacts",
    ]:
        assert marker in packaging_job
    windows_job = workflow.split("  windows-release-smoke:", 1)[1]
    assert "Windows focused tests" in windows_job
    assert "python -m pytest tests/test_path_redaction.py tests/test_permission_boundaries.py tests/test_review_identifier_regressions.py tests/test_store_identifier_contract.py -q -p no:cacheprovider -o addopts=" in windows_job
    assert "Windows focused tests" not in packaging_job
    for heading in [
        "## Public metadata",
        "## Source quality",
        "## Generated references",
        "## Build",
        "## Install smokes",
        "## CI and artifacts",
    ]:
        assert heading in checklist
    for command in [
        "& $releasePython -m pytest -q",
        "& $releasePython -m pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75",
        local_ruff,
        "& $releasePython tools/pre_release_check.py --json",
        "& $releasePython -m pip check",
        "& $releasePython -m build",
        "Get-ChildItem -LiteralPath dist -File",
        "& $releasePython @twineArgs",
    ]:
        assert command in checklist
    for policy in [
        "`oss_public_coordinates`",
        "`security_intake_contact`",
        "`failure_count` must remain `0`",
        "`role_aware_dashboard_toolkit.release_audit.audit_release_artifact_members`",
        "private records and internal maintenance data",
        "temporary directories outside the repository",
        "install and smoke `workbench`, `auth`, `api`, and `pandas` independently",
        "release candidate reuses the exact audited artifacts",
        "SHA-256 digests",
    ]:
        assert policy in checklist


def test_version_module_exports_match_package_version():
    assert version_module_version == __version__


def test_docs_do_not_contain_internal_citation_artifacts():
    roots = [REPO_ROOT / "README.md", REPO_ROOT / "docs"]
    bad_markers = ("îˆ€filecite", "sandbox:/mnt/data")
    for root in roots:
        paths = [root] if root.is_file() else [p for p in root.rglob("*.md") if p.is_file()]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for marker in bad_markers:
                assert marker not in text, f"{path} contains internal artifact marker: {marker}"


def test_maintainer_archive_is_not_linked_or_included_in_public_artifacts():
    docs_index = (REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    pyproject = load_pyproject()
    include_paths = set(pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])
    sdist_excludes = set(pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"])
    wheel_excludes = set(pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["exclude"])

    assert not (REPO_ROOT / "docs" / "history").exists()
    assert "docs/history/" not in docs_index
    assert "_archive_review" not in docs_index
    assert all("docs/history" not in path for path in include_paths)
    assert all("_archive_review" not in path for path in include_paths)
    for excludes in (sdist_excludes, wheel_excludes):
        assert "/role_aware_dashboard_toolkit/_archive_review" in excludes
        assert "/role_aware_dashboard_toolkit/_archive_review/**" in excludes


def test_packaging_extras_keep_core_streamlit_free_and_workbench_explicit():
    pyproject = load_pyproject()
    project = pyproject["project"]
    extras = project["optional-dependencies"]
    assert not any(dep.startswith("streamlit>=") for dep in project["dependencies"])
    assert any(dep.startswith("streamlit>=") for dep in extras["workbench"])


def test_pyproject_metadata_matches_public_product_positioning():
    pyproject = load_pyproject()
    project = pyproject["project"]
    description = project["description"].lower()
    keywords = set(project["keywords"])
    assert "dashboard/admin-control library" in description
    assert "governed operator controls" in description
    assert "profile workflows" in description
    assert "plugin surfaces" in description
    assert "visual control rooms" not in description
    assert "codex builder" not in description
    assert {
        "dashboard",
        "admin-controls",
        "profiles",
        "audit",
        "plugins",
        "observability",
        "rbac",
        "streamlit",
    }.issubset(keywords)
    assert {
        "control-room",
        "semantic-snapshot",
        "snapshot-auditor",
        "semantic-evidence",
        "operational-review",
        "codex-builder",
        "repoos",
        "harness",
    }.isdisjoint(keywords)


def test_core_import_path_does_not_require_streamlit():
    script = """
import importlib.abc
import sys

class BlockStreamlit(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "streamlit" or fullname.startswith("streamlit."):
            attempts.append(fullname)
            raise ModuleNotFoundError("blocked streamlit import", name="streamlit")
        return None

attempts = []
sys.meta_path.insert(0, BlockStreamlit())
import role_aware_dashboard_toolkit
assert "role_aware_dashboard_toolkit.dashboard" not in sys.modules
assert attempts == []

assert role_aware_dashboard_toolkit.__version__
from role_aware_dashboard_toolkit import dashboard as dashboard_module
from role_aware_dashboard_toolkit.audit import AuditLog
from role_aware_dashboard_toolkit.controls import ControlRegistry
from role_aware_dashboard_toolkit.plugins import PluginRegistry

assert attempts == []
assert "streamlit" not in sys.modules
assert role_aware_dashboard_toolkit.DashboardConfig is dashboard_module.DashboardConfig
assert role_aware_dashboard_toolkit.render is dashboard_module.render

default_config = role_aware_dashboard_toolkit.DashboardConfig(auth_mode="demo")
assert default_config.title == "Dashboard"
assert default_config.icon == ""
assert isinstance(default_config.registry, ControlRegistry)
assert isinstance(default_config.audit, AuditLog)
assert isinstance(default_config.plugins, PluginRegistry)

registry = ControlRegistry()
audit = AuditLog()
plugins = PluginRegistry()
profile_store = object()
run_store = object()
team_store = object()
decision_store = object()
operator_memory_store = object()
case_store = object()
governance_store = object()
on_change = lambda *_args: None
auth_hook = lambda: "operator"
observability = object()
config = role_aware_dashboard_toolkit.DashboardConfig(
    title="Core",
    subtitle="Dependency free",
    icon="Library",
    registry=registry,
    audit=audit,
    custom_roles={"operator": object()},
    profile_dir="core-profiles",
    profile_store=profile_store,
    on_change=on_change,
    layout="columns",
    columns_per_row=0,
    auth_hook=auth_hook,
    sanitize_session_state=False,
    observability=observability,
    plugins=plugins,
    run_store=run_store,
    runbook_title="Runs",
    team_store=team_store,
    team_ops_title="Team",
    decision_store=decision_store,
    decision_title="Decisions",
    operator_memory_store=operator_memory_store,
    timeline_title="Timeline",
    case_store=case_store,
    caseboard_title="Cases",
    governance_store=governance_store,
    governance_title="Policy",
    version="test-version",
    audit_dir="core-audit",
)
assert config.registry is registry
assert config.audit is audit
assert config.plugins is plugins
assert config.profile_store is profile_store
assert config.run_store is run_store
assert config.team_store is team_store
assert config.decision_store is decision_store
assert config.operator_memory_store is operator_memory_store
assert config.case_store is case_store
assert config.governance_store is governance_store
assert config.on_change is on_change
assert config.auth_hook is auth_hook
assert config.observability is observability
assert config.columns_per_row == 1
assert config.sanitize_session_state is False
assert attempts == []
try:
    role_aware_dashboard_toolkit.render(config)
except ModuleNotFoundError as exc:
    assert exc.name == "streamlit"
    assert str(exc).startswith(
        "Streamlit is required for Role-Aware Dashboard Toolkit dashboard rendering. "
        'From your reviewed toolkit source checkout, run: python -m pip install ".[workbench]". '
        "From another directory, use the absolute source path or local wheel filename "
        "with [workbench] appended. No package-index release is assumed."
    )
    assert exc.diagnostic["code"] == "RADT-STREAMLIT"
    assert exc.diagnostic["guide_command"] in str(exc)
else:
    raise AssertionError("dashboard render should require streamlit")
assert attempts == ["streamlit"]
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_dashboard_render_surfaces_transitive_streamlit_import_failures():
    script = """
import builtins

from role_aware_dashboard_toolkit import dashboard

real_import = builtins.__import__

def fail_streamlit_runtime(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "streamlit":
        raise ModuleNotFoundError("broken nested Streamlit import", name="streamlit.runtime")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = fail_streamlit_runtime
dashboard.st = None
try:
    dashboard.render(dashboard.DashboardConfig(auth_mode="demo"))
except ModuleNotFoundError as exc:
    assert exc.name == "streamlit.runtime"
    assert str(exc) == "broken nested Streamlit import"
    assert "role-aware-dashboard-toolkit[workbench]" not in str(exc)
else:
    raise AssertionError("transitive Streamlit import failure should surface")
"""
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=str(REPO_ROOT), text=True, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_boundary_docs_and_sdist_describe_generic_example_surface():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    examples_readme = (REPO_ROOT / "examples" / "README.md").read_text(encoding="utf-8")
    oss_boundary = (REPO_ROOT / "docs" / "oss_boundary.md").read_text(encoding="utf-8")
    distribution = (REPO_ROOT / "docs" / "distribution.md").read_text(encoding="utf-8")
    pyproject = load_pyproject()
    sdist_includes = set(pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])

    assert "python -m examples.core_library" in readme
    assert "examples/dashboard_admin_controls_app.py" in readme
    assert "python -m examples.core_library" in examples_readme
    assert "dashboard_admin_controls_app.py" in examples_readme
    assert "plugin_template.py" in examples_readme
    assert "source-distribution material, not modules installed" in examples_readme
    assert "public documentation and fixture-free examples" in oss_boundary
    assert "product-specific adapters or application integrations" in oss_boundary
    assert "private records and internal maintenance data" in oss_boundary
    assert "one Python distribution with a dependency-free core" in distribution
    for install_target in [
        "`role-aware-dashboard-toolkit`",
        "`role-aware-dashboard-toolkit[workbench]`",
        "`role-aware-dashboard-toolkit[api]`",
        "`role-aware-dashboard-toolkit[pandas]`",
        "`role-aware-dashboard-toolkit[full]`",
    ]:
        assert install_target in distribution
    assert {
        "/examples/README.md",
        "/examples/dashboard_admin_controls_app.py",
        "/examples/plugin_template.py",
        "/.github/workflows/ci.yml",
    }.issubset(sdist_includes)
    public_docs = "\n".join((readme, examples_readme, oss_boundary, distribution)).lower()
    for retired_marker in [
        "role_aware_dashboard_toolkit.demo_paths",
        "codex builder",
        "repoos",
        "harness plugin",
        "semantic snapshot",
    ]:
        assert retired_marker not in public_docs
