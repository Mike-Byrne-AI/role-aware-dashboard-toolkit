from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "dependency_audit_under_test",
    Path(__file__).resolve().parents[1] / "tools" / "audit_dependencies.py",
)
audit = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(audit)


def _inventory(*packages):
    return {
        "isolated_venv": True,
        "packages": [
            {"name": "role-aware-dashboard-toolkit", "version": "0.1.0"},
            {"name": "pip", "version": "26.0"},
            *packages,
        ],
    }


def _report(vulns=None):
    return {
        "dependencies": [
            {"name": "example-package", "version": "1.2.3", "vulns": vulns or []}
        ],
        "fixes": [],
    }


def test_resolved_inventory_keeps_all_runtime_versions_and_documents_only_expected_exclusions():
    inventory = _inventory(
        {"name": "Example_Package", "version": "1.2.3"},
        {"name": "Another.Project", "version": "2.0rc1"},
        {"name": "setuptools", "version": "81.0"},
        {"name": "wheel", "version": "0.45"},
    )
    assert audit.resolved_requirements(inventory) == {
        "another-project": "2.0rc1",
        "example-package": "1.2.3",
    }
    assert set(audit.EXCLUSIONS) == {
        "role-aware-dashboard-toolkit",
        "pip",
        "setuptools",
        "wheel",
    }


@pytest.mark.parametrize(
    "inventory",
    [
        {},
        {"isolated_venv": False, "packages": []},
        {
            "isolated_venv": True,
            "packages": [{"name": "example-package", "version": "1"}],
        },
        _inventory(),
        _inventory({"name": "package\n--index-url", "version": "1"}),
        _inventory({"name": "package", "version": "1\nother-package==2"}),
        _inventory({"name": "A_B", "version": "1"}, {"name": "a-b", "version": "2"}),
        _inventory(None),
    ],
)
def test_invalid_incomplete_or_duplicate_inventory_cannot_pass(inventory):
    with pytest.raises(audit.AuditError):
        audit.resolved_requirements(inventory)


def test_complete_clean_report_passes():
    assert audit.assess_report(_report(), {"example-package": "1.2.3"}, 0) == {
        "status": "clean",
        "audited_packages": 1,
        "vulnerabilities": 0,
        "exit_code": 0,
    }


def test_complete_vulnerable_report_is_distinct_from_scanner_failure():
    result = audit.assess_report(
        _report([{"id": "PYSEC-EXAMPLE", "fix_versions": ["1.2.4"]}]),
        {"example-package": "1.2.3"},
        1,
    )
    assert result["status"] == "vulnerabilities_found"
    assert result["vulnerabilities"] == 1
    assert result["exit_code"] == 1


@pytest.mark.parametrize(
    ("report", "expected", "code"),
    [
        ([], {"example-package": "1.2.3"}, 0),
        ({}, {"example-package": "1.2.3"}, 0),
        ({"dependencies": [], "fixes": []}, {"example-package": "1.2.3"}, 0),
        ({"dependencies": [], "fixes": []}, {}, 0),
        (_report(), {"example-package": "1.2.4"}, 0),
        (_report(), {"example-package": "1.2.3", "missing": "1"}, 0),
        (_report(), {"unexpected": "1.2.3"}, 0),
        (_report(), {"example-package": "1.2.3"}, 1),
        (_report(), {"example-package": "1.2.3"}, 2),
        (
            _report([{"id": "PYSEC-EXAMPLE", "fix_versions": []}]),
            {"example-package": "1.2.3"},
            0,
        ),
        (_report([{}]), {"example-package": "1.2.3"}, 1),
        ({"dependencies": [None], "fixes": []}, {"example-package": "1.2.3"}, 0),
        (
            {
                "dependencies": [
                    {"name": "example-package", "skip_reason": "not found"}
                ],
                "fixes": [],
            },
            {"example-package": "1.2.3"},
            0,
        ),
        (
            {
                "dependencies": [{"name": "example-package", "version": "1.2.3"}],
                "fixes": [],
            },
            {"example-package": "1.2.3"},
            0,
        ),
        (
            {"dependencies": _report()["dependencies"] * 2, "fixes": []},
            {"example-package": "1.2.3"},
            0,
        ),
        (
            {"dependencies": _report()["dependencies"], "fixes": [{}]},
            {"example-package": "1.2.3"},
            0,
        ),
    ],
)
def test_partial_skipped_malformed_or_inconsistent_reports_fail(report, expected, code):
    with pytest.raises(audit.AuditError):
        audit.assess_report(report, expected, code)


@pytest.mark.parametrize(
    ("scanner_output", "scanner_code", "expected_code", "status"),
    [
        (json.dumps(_report()), 0, 0, "clean"),
        (
            json.dumps(_report([{"id": "PYSEC-EXAMPLE", "fix_versions": []}])),
            1,
            1,
            "vulnerabilities_found",
        ),
        (None, 1, 2, "audit_failed"),
        ("not json", 0, 2, "audit_failed"),
        (json.dumps(_report()), 1, 2, "audit_failed"),
    ],
)
def test_cli_retains_results_and_never_treats_network_or_scanner_failure_as_clean(
    tmp_path, monkeypatch, scanner_output, scanner_code, expected_code, status
):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "pip_audit" not in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(_inventory({"name": "example-package", "version": "1.2.3"})),
                "",
            )
        if scanner_output is not None:
            Path(command[command.index("--output") + 1]).write_text(
                scanner_output, encoding="utf-8"
            )
        return subprocess.CompletedProcess(
            command, scanner_code, "", "scanner diagnostics"
        )

    monkeypatch.setattr(audit.subprocess, "run", run)
    evidence = tmp_path / "evidence"
    result = audit.main(
        [
            "--python",
            str(tmp_path / "runtime-python"),
            "--audit-python",
            str(tmp_path / "audit-python"),
            "--report-dir",
            str(evidence),
        ]
    )
    assert result == expected_code
    summary = json.loads((evidence / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == status
    assert (evidence / "requirements.txt").read_text(
        encoding="utf-8"
    ) == "example-package==1.2.3\n"
    assert (evidence / "pip-audit.stderr.log").read_text(
        encoding="utf-8"
    ) == "scanner diagnostics"
    assert (
        "--no-deps" in calls[1]
        and "--disable-pip" in calls[1]
        and "--strict" in calls[1]
    )
    assert "--fix" not in calls[1] and "--ignore-vuln" not in calls[1]


def test_cli_preserves_previous_evidence_without_invoking_subprocess(
    tmp_path, monkeypatch
):
    report = tmp_path / "summary.json"
    report.write_text("previous evidence", encoding="utf-8")
    monkeypatch.setattr(
        audit.subprocess, "run", lambda *a, **k: pytest.fail("must not run")
    )
    assert (
        audit.main(
            [
                "--python",
                "runtime",
                "--audit-python",
                "scanner",
                "--report-dir",
                str(tmp_path),
            ]
        )
        == 2
    )
    assert report.read_text(encoding="utf-8") == "previous evidence"


def test_timeout_retains_partial_logs_and_is_an_audit_failure(tmp_path, monkeypatch):
    def run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command,
            kwargs["timeout"],
            output=b"partial output",
            stderr=b"timeout detail",
        )

    monkeypatch.setattr(audit.subprocess, "run", run)
    assert (
        audit.main(
            [
                "--python",
                "runtime",
                "--audit-python",
                "scanner",
                "--report-dir",
                str(tmp_path),
            ]
        )
        == 2
    )
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "audit_failed"
    assert "timed out" in summary["error"]
    assert (tmp_path / "inventory.stdout.log").read_text(
        encoding="utf-8"
    ) == "partial output"


def test_cli_rejects_shared_runtime_and_scanner_environment(tmp_path):
    assert (
        audit.main(
            [
                "--python",
                "same",
                "--audit-python",
                "same",
                "--report-dir",
                str(tmp_path),
            ]
        )
        == 2
    )
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert "separate environments" in summary["error"]


def test_cli_keeps_venv_launcher_paths_when_they_resolve_to_the_same_base_python(
    tmp_path, monkeypatch
):
    runtime = tmp_path / "runtime" / "bin" / "python"
    scanner = tmp_path / "scanner" / "bin" / "python"
    base_python = tmp_path / "base" / "python"
    original_resolve = Path.resolve
    calls = []

    def resolve(path, *args, **kwargs):
        if path in (runtime, scanner):
            return base_python
        return original_resolve(path, *args, **kwargs)

    def run(command, **kwargs):
        calls.append(command[0])
        if "pip_audit" not in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(_inventory({"name": "example-package", "version": "1.2.3"})),
                "",
            )
        Path(command[command.index("--output") + 1]).write_text(
            json.dumps(_report()), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(audit.subprocess, "run", run)
    assert (
        audit.main(
            [
                "--python",
                str(runtime),
                "--audit-python",
                str(scanner),
                "--report-dir",
                str(tmp_path / "evidence"),
            ]
        )
        == 0
    )
    assert calls == [str(runtime), str(scanner)]


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX virtual environment interpreter symlinks"
)
def test_cli_preserves_real_posix_venv_symlinks(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime" / "bin" / "python"
    scanner = tmp_path / "scanner" / "bin" / "python"
    for interpreter in (runtime, scanner):
        interpreter.parent.mkdir(parents=True)
        interpreter.symlink_to(sys.executable)
    assert runtime.resolve() == scanner.resolve()
    calls = []

    def run(command, **kwargs):
        calls.append(command[0])
        if "pip_audit" not in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps(_inventory({"name": "example-package", "version": "1.2.3"})),
                "",
            )
        Path(command[command.index("--output") + 1]).write_text(
            json.dumps(_report()), encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(audit.subprocess, "run", run)
    assert (
        audit.main(
            [
                "--python",
                str(runtime),
                "--audit-python",
                str(scanner),
                "--report-dir",
                str(tmp_path / "evidence"),
            ]
        )
        == 0
    )
    assert calls == [str(runtime), str(scanner)]
