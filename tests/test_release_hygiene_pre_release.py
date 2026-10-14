import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.release_hygiene_helpers import REPO_ROOT, load_pre_release_check_module


def test_pre_release_check_json_entrypoint_reports_local_configuration_scope():
    script = REPO_ROOT / "tools" / "pre_release_check.py"
    result = subprocess.run(
        [sys.executable, str(script), "--json"], cwd=str(REPO_ROOT),
        text=True, capture_output=True, check=False,
    )
    payload = json.loads(result.stdout)
    assert result.returncode == 0, payload
    assert payload["ok"] is True
    assert payload["status"] == "pass"
    assert payload["validation_scope"] == "local-configuration"
    assert payload["release_channel"] == "github-source"
    assert set(payload["live_validation_required"]) == {
        "repository_reachability", "security_reporting_activation",
        "security_notification_configuration", "branch_protection",
        "hosted_ci_same_commit", "public_visibility",
    }
    checks = {item["id"]: item for item in payload["checks"]}
    assert len(checks) == 9
    assert all(item["status"] == "pass" for item in checks.values())
    assert "no PyPI ownership" in checks["distribution_name_ownership"]["detail"]
    assert "not verified" in checks["security_intake_contact"]["detail"]
    for field in ("blocked", "failures", "warnings"):
        assert payload[field] == []
    assert payload["blocked_count"] == payload["failure_count"] == payload["warning_count"] == 0


@pytest.mark.parametrize("heading,expected_status", [
    ("## 0.1.0", "pass"),
    ("## 0.1.0 - 2026-10-10", "pass"),
    ("## 0.1.0rc1", "fail"),
    ("## 0.1.0.post1", "fail"),
    ("## 0.1.01", "fail"),
    ("## 0x1x0", "fail"),
    ("### 0.1.0", "fail"),
    ("Release notes mention ## 0.1.0 here.", "fail"),
])
def test_changelog_gate_requires_exact_release_version_heading(monkeypatch, tmp_path, heading, expected_status):
    pre_release = load_pre_release_check_module()
    (tmp_path / "CHANGELOG.md").write_text(f"# Changelog\n\n{heading}\n\nRelease notes.\n", encoding="utf-8")
    monkeypatch.setattr(pre_release, "REPO_ROOT", tmp_path)

    result = pre_release._check_changelog(SimpleNamespace(__version__="0.1.0"))

    assert result["id"] == "changelog_version"
    assert result["status"] == expected_status


@pytest.mark.parametrize("unreleased,expected_status", [
    (None, "pass"),
    ("", "pass"),
    ("### Added\n\n### Fixed\n", "pass"),
    ("### Fixed\n\n- A fix that this release would ship.\n", "fail"),
    ("A paragraph describing unreleased work.\n", "fail"),
    ("* An asterisk bullet.\n", "fail"),
])
def test_release_gate_refuses_entries_left_under_unreleased(monkeypatch, tmp_path, unreleased, expected_status):
    pre_release = load_pre_release_check_module()
    section = "" if unreleased is None else f"## Unreleased\n\n{unreleased}\n"
    (tmp_path / "CHANGELOG.md").write_text(
        f"# Changelog\n\n{section}## 0.1.0 (2026-10-13)\n\n### Fixed\n\n- Shipped fix.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(pre_release, "REPO_ROOT", tmp_path)

    result = pre_release._check_changelog_unreleased()

    assert result["id"] == "changelog_unreleased"
    assert result["status"] == expected_status
    if expected_status == "fail":
        assert "Unreleased" in result["detail"]


def test_unreleased_gate_runs_only_in_release_mode(monkeypatch):
    pre_release = load_pre_release_check_module()
    monkeypatch.setattr(pre_release, "_check_source_tree_clean", lambda: pre_release._record("source_tree_clean", "pass", "stub"))
    development = {item["id"] for item in pre_release.build_report()["checks"]}
    release = {item["id"] for item in pre_release.build_report(require_clean=True)["checks"]}
    assert "changelog_unreleased" not in development
    assert release - development == {"changelog_unreleased", "source_tree_clean"}


def test_security_contact_helper_rejects_unrelated_contact_tokens():
    pre_release = load_pre_release_check_module()

    assert (
        pre_release._has_monitored_security_reporting_contact(
            "Project homepage: https://example.com\nGeneral contact: hello@example.com"
        )
        is False
    )
    assert (
        pre_release._has_monitored_security_reporting_contact(
            "Report security vulnerabilities to support@toolkit-fixture.dev"
        )
        is True
    )


def test_public_coordinate_gate_rejects_placeholder_urls():
    pre_release = load_pre_release_check_module()
    pyproject = {
        "project": {
            "urls": {
                "Repository": "https://example.com/role_aware_dashboard_toolkit",
                "Issues": "https://github.com/your-org/role_aware_dashboard_toolkit/issues",
                "Documentation": "http://localhost:8000/docs",
                "Homepage": "TODO",
            }
        }
    }

    result = pre_release._check_public_coordinates(pyproject)

    assert result["status"] == "blocked"
    assert "placeholder or invalid project URLs" in result["detail"]
    assert "Repository" in result["detail"]
    assert "Issues" in result["detail"]
    assert "Documentation" in result["detail"]
    assert "Homepage" in result["detail"]


@pytest.mark.parametrize(
    "url",
    [
        "https://192.168.1.1/project",
        "https://192.168.1.1./project",
        "https://0300.0250.0001.0001/project",
        "https://0x7f.0.0.1/project",
        "https://0x0a.0.0.1/project",
        "https://0x7f000001/project",
        "https://toolkit-fixture.dev:invalid/project",
        "https://toolkit-fixture.dev:65536/project",
        "https://10.0.0.1/project",
        "https://127.0.0.2/project",
        "https://169.254.1.1/project",
        "https://100.64.0.1/project",
        "https://224.0.0.1/project",
        "https://[::1]/project",
        "https://[fd00::1]/project",
        "https://[fe80::1]/project",
        "https://toolkit-fixture.dev@intranet/project",
        "https://[broken/project",
    ],
)
def test_public_coordinate_gate_rejects_non_public_or_invalid_hosts(url):
    pre_release = load_pre_release_check_module()
    urls = {key: url for key in ("Repository", "Issues", "Documentation", "Homepage")}

    result = pre_release._check_public_coordinates({"project": {"urls": urls}})

    assert result["status"] == "blocked"
    assert pre_release._has_monitored_security_reporting_contact(
        f"Report security vulnerabilities at {url}/security"
    ) is False


@pytest.mark.parametrize(
    "url",
    ["https://toolkit-fixture.dev/project", "https://toolkit-fixture.dev:443/project", "https://toolkit-fixture.dev./project", "https://8.8.8.8/project", "https://[2606:4700:4700::1111]/project"],
)
def test_public_coordinate_gate_preserves_public_host_syntax(url):
    pre_release = load_pre_release_check_module()
    urls = {key: url for key in ("Repository", "Issues", "Documentation", "Homepage")}

    assert pre_release._check_public_coordinates({"project": {"urls": urls}})["status"] == "pass"


def _source_policy():
    repository = "Maintainer/toolkit-library"
    base = f"https://github.com/{repository}"
    return {
        "project": {
            "name": "TOOLKIT_Library",
            "urls": {"Repository": base, "Issues": base + "/issues", "Documentation": base + "/blob/main/docs/README.md", "Homepage": base + "#readme"},
        },
        "tool": {"role_aware_dashboard_toolkit": {"release": {
            "channel": "github-source", "repository": repository,
            "package-index-publication": False,
            "security-reporting-mode": "github-private-vulnerability-reporting",
            "security-reporting-url": base + "/security/advisories/new",
        }}},
    }


def test_distribution_name_gate_is_source_identity_without_pypi_claim():
    pre_release = load_pre_release_check_module()
    configured = _source_policy()
    result = pre_release._check_distribution_name_ownership(configured)
    assert result["status"] == "pass"
    assert "no PyPI ownership or reservation is verified or claimed" in result["detail"]
    stale = {"project": {"name": "toolkit-library"}, "tool": {"role_aware_dashboard_toolkit": {"release": {"verified-distribution-name": "toolkit-library"}}}}
    assert pre_release._check_distribution_name_ownership(stale)["status"] == "blocked"


@pytest.mark.parametrize("key,value", [
    ("channel", "pypi"), ("repository", "Maintainer/unrelated-name"),
    ("repository", "https://github.com/Maintainer/toolkit-library"),
    ("repository", "Maintainer/toolkit-library/extra"),
    ("package-index-publication", True), ("package-index-publication", 0),
    ("package-index-publication", "false"),
])
def test_source_identity_rejects_mismatches_and_index_publication(key, value):
    pre_release = load_pre_release_check_module()
    configured = _source_policy()
    configured["tool"]["role_aware_dashboard_toolkit"]["release"][key] = value
    assert pre_release._check_distribution_name_ownership(configured)["status"] == "blocked"


@pytest.mark.parametrize("key", ["Repository", "Issues", "Documentation", "Homepage"])
def test_github_coordinates_must_match_the_configured_source_repository(key):
    pre_release = load_pre_release_check_module()
    configured = _source_policy()
    assert pre_release._check_public_coordinates(configured)["status"] == "pass"
    configured["project"]["urls"][key] = "https://github.com/Unrelated/toolkit-library"
    assert pre_release._check_public_coordinates(configured)["status"] == "blocked"


@pytest.mark.parametrize("problem", [None, "mode", "other_repo", "missing_config", "wrong_doc", "placeholder", "missing_doc"])
def test_security_policy_requires_matching_github_configuration_and_document(monkeypatch, tmp_path, problem):
    pre_release = load_pre_release_check_module()
    configured = _source_policy()
    release = configured["tool"]["role_aware_dashboard_toolkit"]["release"]
    text = "Report security vulnerabilities at <" + release["security-reporting-url"] + ">."
    if problem == "mode":
        release["security-reporting-mode"] = "email"
    elif problem == "other_repo":
        release["security-reporting-url"] = "https://github.com/Other/toolkit-library/security/advisories/new"
    elif problem == "missing_config":
        del release["security-reporting-url"]
    elif problem == "wrong_doc":
        text = "Report security vulnerabilities at https://toolkit-fixture.dev/security"
    elif problem == "placeholder":
        text += " Use a private coordination channel."
    if problem != "missing_doc":
        (tmp_path / "SECURITY.md").write_text(text, encoding="utf-8")
    monkeypatch.setattr(pre_release, "REPO_ROOT", tmp_path)
    result = pre_release._check_security_intake_contact(configured)
    assert result["status"] == ("pass" if problem is None else "blocked")
    if problem is None:
        assert "live activation and notification configuration are not verified" in result["detail"]


def test_intake_gate_requires_policy_files_without_permanent_blocked_wording(monkeypatch, tmp_path):
    pre_release = load_pre_release_check_module()
    for name in ("SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"):
        (tmp_path / name).write_bytes((REPO_ROOT / name).read_bytes())
    monkeypatch.setattr(pre_release, "REPO_ROOT", tmp_path)
    assert pre_release._check_oss_intake_files()["status"] == "pass"
    (tmp_path / "CONTRIBUTING.md").write_text("# Incomplete", encoding="utf-8")
    assert pre_release._check_oss_intake_files()["status"] == "fail"
    (tmp_path / "SECURITY.md").unlink()
    assert pre_release._check_oss_intake_files()["status"] == "blocked"


def test_security_contact_helper_rejects_placeholder_contacts():
    pre_release = load_pre_release_check_module()

    for text in [
        "Report security vulnerabilities to security@example.com",
        "Report security vulnerabilities at https://localhost/security",
        "Report security vulnerabilities at https://example.org/security",
    ]:
        assert pre_release._has_monitored_security_reporting_contact(text) is False


@pytest.mark.parametrize(
    "contact",
    [
        "mailto:",
        "mailto:TODO",
        "mailto:security@example.com",
        "mailto:security%40example.com",
        "mailto:security@role_aware_dashboard_toolkit",
        "mailto:security@@toolkit-fixture.dev",
        "mailto://security@toolkit-fixture.dev",
        "mailto:security@toolkit-fixture.dev/invalid",
        "mailto:security@toolkit-fixture.dev%00.invalid",
        "mailto:security@toolkit-fixture.dev%7f.invalid",
        "mailto:security@toolkit-fixture.dev,security@example.com",
        "mailto:security@toolkit-fixture.dev?cc=security%40example.com",
        "mailto:security@toolkit-fixture.dev,",
    ],
)
def test_security_contact_helper_rejects_invalid_mailto_targets(contact):
    pre_release = load_pre_release_check_module()
    assert pre_release._has_monitored_security_reporting_contact(f"Report vulnerabilities to [security]({contact}).") is False


@pytest.mark.parametrize(
    "contact",
    [
        "mailto:security@toolkit-fixture.dev",
        "mailto:support@toolkit-fixture.dev?subject=Security%20report",
        "mailto:security%40toolkit-fixture.dev",
        "mailto:security@toolkit-fixture.dev,psirt@toolkit-fixture.dev",
        "mailto:?to=security%40toolkit-fixture.dev",
    ],
)
def test_security_contact_helper_preserves_valid_mailto_targets(contact):
    pre_release = load_pre_release_check_module()
    assert pre_release._has_monitored_security_reporting_contact(f"Report vulnerabilities to [maintainers]({contact}).") is True
    assert pre_release._has_monitored_security_reporting_contact(
        "General contact: mailto:support@toolkit-fixture.dev"
    ) is False


def test_pre_release_cache_scan_prunes_skipped_directories_before_descent(monkeypatch):
    pre_release = load_pre_release_check_module()
    walk_state = {
        "descended_git": False,
        "descended_cache": False,
        "descended_ruff": False,
        "descended_src": False,
    }

    def fake_walk(root, topdown=True, onerror=None):
        assert topdown is True
        assert callable(onerror)
        outside_root = Path(root) / ".." / "outside"
        dirnames = [".git", "__pycache__", ".ruff_cache", "src"]
        filenames: list[str] = []
        yield str(root), dirnames, filenames
        if ".git" in dirnames:
            walk_state["descended_git"] = True
            yield str(Path(root) / ".git"), [], ["leak.pyc"]
        if "__pycache__" in dirnames:
            walk_state["descended_cache"] = True
            yield str(Path(root) / "__pycache__"), [], ["cache.pyc"]
        if ".ruff_cache" in dirnames:
            walk_state["descended_ruff"] = True
            yield str(Path(root) / ".ruff_cache"), [], ["cache"]
        if "src" in dirnames:
            walk_state["descended_src"] = True
            yield str(Path(root) / "src"), [], ["ok.py"]
        yield str(outside_root), [], ["leak.pyc"]

    monkeypatch.setattr(pre_release.os, "walk", fake_walk)

    found, scan_errors = pre_release._scan_generated_cache_artifacts()
    assert scan_errors == []

    assert walk_state["descended_git"] is False
    assert walk_state["descended_cache"] is False
    assert walk_state["descended_ruff"] is False
    assert walk_state["descended_src"] is True
    assert "__pycache__" in found
    assert "../outside/leak.pyc" not in found
    assert ".ruff_cache" not in found
    assert ".git/leak.pyc" not in found


def test_pre_release_cache_scan_fails_closed_on_walk_errors(monkeypatch, capsys):
    pre_release = load_pre_release_check_module()
    blocked_dir = pre_release.REPO_ROOT / "blocked subtree"
    outside_dir = pre_release.REPO_ROOT.parent / "outside secret"

    def fake_walk(root, topdown=True, onerror=None):
        assert Path(root) == pre_release.REPO_ROOT
        assert topdown is True
        yield str(root), [], ["stale.pyc"]
        if onerror is not None:
            onerror(
                PermissionError(
                    13,
                    f"fixture traversal denied at {blocked_dir}",
                    str(blocked_dir),
                )
            )
            onerror(
                PermissionError(
                    13,
                    f"outside traversal denied at {outside_dir}",
                    str(outside_dir),
                )
            )

    monkeypatch.setattr(pre_release.os, "walk", fake_walk)

    result = pre_release._check_generated_cache_artifacts()

    assert result["status"] == "fail"
    assert "scan incomplete" in result["detail"]
    assert "artifacts also present: stale.pyc" in result["detail"]
    assert result["artifacts"] == ["stale.pyc"]
    assert result["scan_errors"] == [
        {
            "path": "<outside-root>",
            "reason": "walk_error",
            "message": "PermissionError: directory traversal failed (errno 13)",
        },
        {
            "path": "blocked subtree",
            "reason": "walk_error",
            "message": "PermissionError: directory traversal failed (errno 13)",
        },
    ]
    assert all(
        str(pre_release.REPO_ROOT) not in item["message"]
        for item in result["scan_errors"]
    )
    assert all(
        str(outside_dir) not in item["message"] for item in result["scan_errors"]
    )

    assert pre_release.main(["--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    checks = {item["id"]: item for item in payload["checks"]}
    assert payload["status"] == "fail"
    assert payload["blocked"] == []
    assert payload["failures"] == ["generated_cache_artifacts"]
    assert payload["failure_count"] == 1
    assert checks["generated_cache_artifacts"]["scan_errors"] == result["scan_errors"]


def test_clean_source_gate_reports_dirty_state_without_leaking_git_stderr(monkeypatch):
    pre_release = load_pre_release_check_module()
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=" M role_aware_dashboard_toolkit/controls.py\n?? new module.py\n",
            stderr="private local diagnostic",
        )

    monkeypatch.setattr(pre_release.subprocess, "run", fake_run)

    result = pre_release._check_source_tree_clean()

    assert result == {
        "id": "source_tree_clean",
        "status": "fail",
        "detail": (
            "working tree has 2 tracked or untracked changes: "
            " M role_aware_dashboard_toolkit/controls.py, ?? new module.py"
        ),
        "change_count": 2,
    }
    assert "private local diagnostic" not in result["detail"]
    assert calls[0][0] == [
        "git",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ]
    assert calls[0][1]["cwd"] == pre_release.REPO_ROOT


def test_clean_source_gate_fails_closed_when_git_cannot_run(monkeypatch):
    pre_release = load_pre_release_check_module()

    def fail_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("git", 15)

    monkeypatch.setattr(pre_release.subprocess, "run", fail_run)

    result = pre_release._check_source_tree_clean()

    assert result == {
        "id": "source_tree_clean",
        "status": "fail",
        "detail": "unable to verify Git source state (TimeoutExpired)",
    }
