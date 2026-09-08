import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.release_hygiene_helpers import REPO_ROOT, load_pre_release_check_module


def test_pre_release_check_json_entrypoint_reports_known_release_gate():
    script = REPO_ROOT / "tools" / "pre_release_check.py"
    assert script.exists()
    result = subprocess.run(
        [sys.executable, str(script), "--json"],
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    payload = json.loads(result.stdout)
    assert result.returncode == (0 if payload["ok"] else 1)
    checks = {item["id"]: item for item in payload["checks"]}
    assert "release_audit_doc" in checks
    assert checks["oss_public_coordinates"]["status"] == "blocked"
    assert "Homepage" in checks["oss_public_coordinates"]["detail"]
    assert checks["oss_public_coordinates"]["required_inputs"] == [
        "Repository URL",
        "Issues URL",
        "Documentation URL",
        "Homepage URL",
    ]
    assert "pyproject.toml [project.urls]" in checks["oss_public_coordinates"]["remediation"]
    assert checks["distribution_name_ownership"]["status"] == "pass"
    assert checks["security_intake_contact"]["status"] == "blocked"
    assert "monitored" in checks["security_intake_contact"]["detail"]
    assert checks["security_intake_contact"]["required_inputs"] == ["monitored security reporting contact"]
    assert "SECURITY.md" in checks["security_intake_contact"]["remediation"]
    assert payload["status"] == "blocked"
    assert payload["blocked"] == [
        "oss_public_coordinates",
        "security_intake_contact",
    ]
    assert payload["blocked_count"] == 2
    assert payload["failures"] == []
    assert payload["failure_count"] == 0


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


def test_distribution_name_gate_uses_normalized_pypi_names():
    pre_release = load_pre_release_check_module()

    blocked = pre_release._check_distribution_name_ownership(
        {"project": {"name": "ROLE_AWARE_DASHBOARD_TOOLKIT"}}
    )
    unverified = pre_release._check_distribution_name_ownership(
        {"project": {"name": "dash-forge"}}
    )
    available = pre_release._check_distribution_name_ownership(
        {
            "project": {"name": "dash-forge"},
            "tool": {
                "role_aware_dashboard_toolkit": {
                    "release": {"verified-distribution-name": "Dash_Forge"}
                }
            },
        }
    )

    assert blocked["status"] == "blocked"
    assert blocked["id"] == "distribution_name_ownership"
    assert unverified["status"] == "blocked"
    assert unverified["required_inputs"] == [
        "verified availability or ownership for PyPI distribution name 'dash-forge'"
    ]
    assert available == {
        "id": "distribution_name_ownership",
        "status": "pass",
        "detail": (
            "configured distribution name 'dash-forge' matches the recorded "
            "normalized PyPI availability or ownership verification"
        ),
    }


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
def test_security_contact_gate_rejects_invalid_mailto_targets(monkeypatch, contact):
    pre_release = load_pre_release_check_module()
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: f"Report vulnerabilities to [security]({contact}).")

    assert pre_release._check_security_intake_contact()["status"] == "blocked"


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
def test_security_contact_gate_preserves_valid_mailto_targets(monkeypatch, contact):
    pre_release = load_pre_release_check_module()
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: f"Report vulnerabilities to [maintainers]({contact}).")

    assert pre_release._check_security_intake_contact()["status"] == "pass"
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
    assert payload["blocked"] == [
        "oss_public_coordinates",
        "security_intake_contact",
    ]
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
