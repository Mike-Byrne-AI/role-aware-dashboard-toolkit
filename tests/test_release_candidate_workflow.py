import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import textwrap
import warnings
import zipfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _packaging_release_job(workflow: str) -> str:
    start = workflow.index("  packaging-release-smoke:")
    end = workflow.index("  release-candidate:")
    return workflow[start:end]


def _publication_hygiene_script(workflow: str) -> str:
    job = _packaging_release_job(workflow)
    marker = "          python - <<'PY'\n"
    start = job.index(marker) + len(marker)
    end = job.index("          PY", start)
    return textwrap.dedent(job[start:end])


def _release_candidate_job(workflow: str) -> str:
    start = workflow.index("  release-candidate:")
    end = workflow.index("  windows-release-smoke:")
    return workflow[start:end]


def _release_candidate_evidence_script(workflow: str) -> str:
    job = _release_candidate_job(workflow)
    marker = "      - name: Build release-candidate evidence\n        run: |\n          python - <<'PY'\n"
    start = job.index(marker) + len(marker)
    end = job.index("          PY", start)
    return textwrap.dedent(job[start:end])


def _windows_artifact_script(workflow: str, step: str) -> str:
    job = workflow.split("  windows-release-smoke:\n", 1)[1]
    body = job.split(f"      - name: {step}\n        shell: python\n        run: |\n", 1)[1]
    return textwrap.dedent(body.split("      - name:", 1)[0])


def test_ci_release_candidate_lane_is_non_publish_and_uploads_evidence():
    workflow = _read(".github/workflows/ci.yml")
    job = _release_candidate_job(workflow)
    packaging_job = _packaging_release_job(workflow)

    assert "workflow_dispatch:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "id-token: write" not in workflow
    assert "packages: write" not in workflow

    assert "\n    if: ${{ github.event_name == 'workflow_dispatch' && vars.XL422_CI_APPROVED_SHA == github.sha && (github.ref == 'refs/heads/candidate' || github.ref == 'refs/heads/main') }}\n" in job
    assert "needs: [test, coverage-gate, packaging-release-smoke, windows-release-smoke]" in job
    assert (
        "python tools/pre_release_check.py --json --require-clean "
        "> pre_release_report.json || true"
    ) in job
    assert "pre_release_check requires all local configuration checks to pass" in job
    assert '("blocked", "blocked_count"), ("failures", "failure_count"), ("warnings", "warning_count")' in job
    assert "allowed_blocked" not in workflow
    assert "live_validation_required" in job
    assert 'source_sha = os.environ.get("GITHUB_SHA", "").strip()' in job
    assert '"source_sha": source_sha' in job
    assert "GITHUB_SHA is required for release-candidate evidence" in job
    assert '["git", "rev-parse", "HEAD"]' in job
    assert "does not match checked-out commit" in job
    assert '"artifact_sha256": artifact_sha256' in job
    assert "hashlib.sha256(path.read_bytes()).hexdigest()" in job
    assert "python -m build" not in job
    assert "python -m twine check dist/*" in job
    assert "uses: actions/download-artifact@" in job
    assert "name: role_aware_dashboard_toolkit-validated-dist" in job
    assert "path: dist" in job
    assert "digest-mismatch: error" in job
    assert "name: role_aware_dashboard_toolkit-windows-artifact-evidence" in job
    assert "Windows smoke evidence must match this run, source, and exact artifact bytes" in job
    assert "uses: actions/upload-artifact@" in job
    assert "name: role_aware_dashboard_toolkit-release-candidate-dist" in job
    assert "name: role_aware_dashboard_toolkit-release-candidate-evidence" in job
    assert "pre_release_report.json" in job
    assert "release_candidate_evidence.json" in job
    assert "twine upload" not in job

    assert "name: Upload validated distribution artifacts" in packaging_job
    assert "        if:" not in packaging_job
    assert "name: role_aware_dashboard_toolkit-validated-dist" in packaging_job
    assert "path: dist/*" in packaging_job
    upload_index = packaging_job.index("name: Upload validated distribution artifacts")
    assert packaging_job.index("name: Wheel install smoke") < upload_index
    assert packaging_job.index("name: Sdist install smoke") < upload_index


@pytest.mark.parametrize("branch", ["candidate", "main"])
def test_release_candidate_evidence_hashes_exact_artifacts_and_checks_commit(tmp_path, branch):
    script = _release_candidate_evidence_script(_read(".github/workflows/ci.yml"))
    dist = tmp_path / "dist"
    dist.mkdir()
    artifacts = {
        "role_aware_dashboard_toolkit-1.0.0-py3-none-any.whl": b"wheel-bytes",
        "role_aware_dashboard_toolkit-1.0.0.tar.gz": b"sdist-bytes",
    }
    for name, content in artifacts.items():
        (dist / name).write_bytes(content)
    (tmp_path / "pre_release_report.json").write_text(
        json.dumps(_passing_local_report()),
        encoding="utf-8",
    )
    workspace = tmp_path / "source"
    workspace.mkdir()
    fixture_env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    subprocess.run(
        ["git", "init", "--quiet", "--template="],
        cwd=workspace,
        env=fixture_env,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "git",
            "-c", "user.name=Release Evidence Test",
            "-c", "user.email=release-evidence@example.invalid",
            "-c", "commit.gpgsign=false",
            "-c", f"core.hooksPath={workspace / '.git' / 'hooks'}",
            "commit", "--allow-empty", "--quiet", "-m", "Fixture commit",
        ],
        cwd=workspace,
        env=fixture_env,
        check=True,
        capture_output=True,
        text=True,
    )
    source_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=workspace,
        env=fixture_env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    runner_temp = tmp_path / "runner"
    windows_evidence_dir = runner_temp / "windows-evidence"
    windows_evidence_dir.mkdir(parents=True)
    windows_evidence_path = windows_evidence_dir / "windows_artifact_evidence.json"
    windows_evidence = {
        "source_sha": source_sha, "run_id": 123456, "run_attempt": 2,
        "artifact_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in artifacts.items()},
    }
    windows_evidence_path.write_text(json.dumps(windows_evidence), encoding="utf-8")

    env = {
        **fixture_env,
        "GITHUB_SHA": source_sha,
        "GITHUB_REF": f"refs/heads/{branch}",
        "GITHUB_RUN_ID": "123456",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_WORKSPACE": str(workspace),
        "RUNNER_TEMP": str(runner_temp),
        "PYTHONPATH": str(REPO_ROOT),
    }
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    evidence = json.loads((tmp_path / "release_candidate_evidence.json").read_text(encoding="utf-8"))
    assert evidence["source_sha"] == source_sha
    assert evidence["run_id"] == 123456
    assert evidence["run_attempt"] == 2
    assert evidence["head_branch"] == branch
    assert evidence["validation_scope"] == "local-configuration"
    assert evidence["release_channel"] == "github-source"
    assert evidence["live_validation_required"] == _passing_local_report()["live_validation_required"]
    assert evidence["workflow_path"] == ".github/workflows/ci.yml"
    assert evidence["artifact_sha256"] == {
        name: hashlib.sha256(content).hexdigest() for name, content in artifacts.items()
    }
    assert evidence["windows_artifact_sha256"] == evidence["artifact_sha256"]

    for overrides in [
        {"source_sha": "0" * 40}, {"run_id": 123457}, {"run_attempt": 3},
        {"artifact_sha256": {name: "0" * 64 for name in artifacts}},
    ]:
        windows_evidence_path.write_text(json.dumps({**windows_evidence, **overrides}), encoding="utf-8")
        rejected = subprocess.run(
            [sys.executable, "-c", script], cwd=tmp_path, env=env,
            capture_output=True, text=True, check=False,
        )
        assert rejected.returncode != 0, overrides
        assert "Windows smoke evidence must match" in rejected.stderr
    windows_evidence_path.unlink()
    missing_receipt = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )
    assert missing_receipt.returncode != 0
    assert "windows_artifact_evidence.json" in missing_receipt.stderr
    windows_evidence_path.write_text(json.dumps(windows_evidence), encoding="utf-8")

    mismatch = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env={**env, "GITHUB_SHA": "0" * 40},
        capture_output=True,
        text=True,
        check=False,
    )
    assert mismatch.returncode != 0
    assert "does not match checked-out commit" in mismatch.stderr

    for overrides in [
        {"GITHUB_REF": "refs/heads/feature"},
        {"GITHUB_REF": "refs/tags/v1.0.0"},
        {"GITHUB_RUN_ID": ""},
        {"GITHUB_RUN_ID": "0"},
        {"GITHUB_RUN_ATTEMPT": "invalid"},
        {"GITHUB_RUN_ATTEMPT": "0"},
    ]:
        rejected = subprocess.run(
            [sys.executable, "-c", script], cwd=tmp_path,
            env={**env, **overrides}, capture_output=True, text=True, check=False,
        )
        assert rejected.returncode != 0, overrides

    (dist / "unexpected.txt").write_text("not a distribution artifact", encoding="utf-8")
    rejected = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )
    assert rejected.returncode != 0
    assert "exactly two distribution artifacts" in rejected.stderr


def test_windows_lane_installs_downloaded_artifacts_and_retains_verified_receipt():
    workflow = _read(".github/workflows/ci.yml")
    job = workflow.split("  windows-release-smoke:\n", 1)[1]
    assert "needs: [packaging-release-smoke]" in job
    assert "python -m build" not in job
    assert "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in job
    assert "name: role_aware_dashboard_toolkit-validated-dist" in job
    assert "path: dist\n          digest-mismatch: error" in job
    assert "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in job
    assert "name: role_aware_dashboard_toolkit-windows-artifact-evidence" in job
    assert "path: ${{ runner.temp }}/windows_artifact_evidence.json" in job
    ordered_steps = [
        "Download validated distribution artifacts", "Record Windows artifact hashes",
        "Wheel install smoke (Windows)", "Auth wheel install smoke (Windows)",
        "Verify Windows artifacts stayed unchanged", "Upload Windows artifact evidence",
    ]
    positions = [job.index("name: " + step) for step in ordered_steps]
    assert positions == sorted(positions)


@pytest.mark.parametrize("problem", [None, "missing_wheel", "missing_sdist", "extra_file", "directory"])
def test_actual_windows_hash_receipt_requires_exact_pair_and_detects_changed_bytes(tmp_path, problem):
    workflow = _read(".github/workflows/ci.yml")
    record = _windows_artifact_script(workflow, "Record Windows artifact hashes")
    verify = _windows_artifact_script(workflow, "Verify Windows artifacts stayed unchanged")
    dist, runner = tmp_path / "dist", tmp_path / "runner"
    dist.mkdir()
    runner.mkdir()
    names = {"fixture.whl": b"wheel bytes", "fixture.tar.gz": b"sdist bytes"}
    for name, content in names.items():
        (dist / name).write_bytes(content)
    if problem == "missing_wheel":
        (dist / "fixture.whl").unlink()
    elif problem == "missing_sdist":
        (dist / "fixture.tar.gz").unlink()
    elif problem == "extra_file":
        (dist / "extra.txt").write_text("extra", encoding="utf-8")
    elif problem == "directory":
        (dist / "fixture.whl").unlink()
        (dist / "fixture.whl").mkdir()
    env = {**os.environ, "RUNNER_TEMP": str(runner), "GITHUB_SHA": "a" * 40,
           "GITHUB_RUN_ID": "123456", "GITHUB_RUN_ATTEMPT": "2"}
    result = subprocess.run([sys.executable, "-c", record], cwd=tmp_path, env=env,
                            capture_output=True, text=True, check=False)
    assert (result.returncode == 0) is (problem is None), result.stderr
    receipt_path = runner / "windows_artifact_evidence.json"
    if problem is not None:
        assert "exactly one downloaded wheel and one sdist" in result.stderr
        assert not receipt_path.exists()
        return
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt == {
        "source_sha": "a" * 40, "run_id": 123456, "run_attempt": 2,
        "artifact_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in names.items()},
    }
    success = subprocess.run([sys.executable, "-c", verify], cwd=tmp_path, env=env,
                             capture_output=True, text=True, check=False)
    assert success.returncode == 0, success.stderr
    (dist / "fixture.whl").write_bytes(b"different wheel bytes")
    changed = subprocess.run([sys.executable, "-c", verify], cwd=tmp_path, env=env,
                             capture_output=True, text=True, check=False)
    assert changed.returncode != 0
    assert "changed during install smokes" in changed.stderr


def _passing_local_report():
    check_ids = [
        "runtime_version", "changelog_version", "release_audit_doc", "release_checklist_commands",
        "oss_public_coordinates", "distribution_name_ownership", "oss_intake_files",
        "security_intake_contact", "generated_cache_artifacts", "source_tree_clean",
    ]
    return {
        "ok": True, "status": "pass", "checks": [{"id": name, "status": "pass"} for name in check_ids],
        "blocked": [], "failures": [], "warnings": [],
        "blocked_count": 0, "failure_count": 0, "warning_count": 0,
        "validation_scope": "local-configuration", "release_channel": "github-source",
        "live_validation_required": ["repository_reachability", "security_reporting_activation", "security_notification_configuration", "branch_protection", "hosted_ci_same_commit", "public_visibility"],
    }


@pytest.mark.parametrize("problem", [None, "blocked", "failures", "warnings", "missing", "duplicate", "skipped", "false_ok", "bad_status", "nonzero_count", "missing_count", "live_claim", "wrong_channel", "no_live_requirements"])
def test_both_hygiene_lanes_require_complete_passing_local_configuration(tmp_path, problem):
    workflow = _read(".github/workflows/ci.yml")
    script = _publication_hygiene_script(workflow)
    assert textwrap.indent(script, "          ") in _release_candidate_job(workflow)
    report = _passing_local_report()
    if problem in {"blocked", "failures", "warnings"}:
        report[problem] = ["security_intake_contact"]
    elif problem == "missing":
        report["checks"].pop()
    elif problem == "duplicate":
        report["checks"][-1] = report["checks"][0]
    elif problem == "skipped":
        report["checks"][0]["status"] = "skipped"
    elif problem == "false_ok":
        report["ok"] = False
    elif problem == "bad_status":
        report["status"] = "blocked"
    elif problem == "nonzero_count":
        report["warning_count"] = 1
    elif problem == "missing_count":
        del report["failure_count"]
    elif problem == "live_claim":
        report["validation_scope"] = "live-readiness"
    elif problem == "wrong_channel":
        report["release_channel"] = "pypi"
    elif problem == "no_live_requirements":
        report["live_validation_required"] = []
    (tmp_path / "pre_release_report.json").write_text(json.dumps(report), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=tmp_path,
        text=True, capture_output=True, check=False,
    )
    assert (result.returncode == 0) is (problem is None), result.stderr


def test_release_docs_cover_non_publish_release_candidate_lane():
    checklist = _read("docs/release_checklist.md")
    runbook = _read("docs/release_runbook.md")

    assert "`coverage-gate`" in checklist
    assert "release candidate reuses the exact audited artifacts" in checklist
    assert "SHA-256 digests" in checklist
    assert "`oss_public_coordinates`" in checklist
    assert "`distribution_name_ownership`" in checklist
    assert "`security_intake_contact`" in checklist
    assert "`failure_count` must remain `0`" in checklist

    assert "## Freeze the source identity" in runbook
    assert "## Build once" in runbook
    assert "## Verify source did not move" in runbook
    assert "All later lanes must reuse these exact bytes." in runbook
    assert "digests against the release candidate evidence" in runbook
    assert "$releaseCommit = (git rev-parse HEAD).Trim()" in runbook
    assert "git status --porcelain" in runbook
    assert "Push the prepared local candidate commit to remote `main` only." in runbook
    assert "public without changing `main` or adding a metadata commit" in runbook
    assert "No PyPI name ownership, reservation, or publishing authority is claimed." in runbook
    assert "live_validation_required" in runbook
    assert "twine upload" not in runbook
    assert "--no-build-isolation" not in runbook
    assert "A pre-publication smoke must use local artifacts" in runbook
    assert "`workbench`, `auth`, `api`, and `pandas` independently" in checklist
    assert "on Linux and Windows" in checklist
    assert "`auth` wheel on Linux and Windows" in runbook
    assert "authentication checks in the `full` smoke too" in runbook

    checklist = _read("docs/release_checklist.md")
    assert "pre_release_check.py --json --require-clean" in checklist
    assert "tracked and untracked files" in checklist

    gitignore = _read(".gitignore")
    assert "/pre_release_report.json" in gitignore
    assert "/release_candidate_evidence.json" in gitignore


def _artifact_audit_script(workflow: str) -> str:
    marker = "          python - <<'PY'\n"
    job = _release_candidate_job(workflow).split("      - name: Artifact hygiene audit\n", 1)[1]
    start = job.index(marker) + len(marker)
    end = job.index("          PY", start)
    script = textwrap.dedent(job[start:end])
    assert textwrap.indent(script, "          ") in _packaging_release_job(workflow)
    return script


@pytest.mark.parametrize("kind,problem", [(None, None), ("wheel", "missing"), ("sdist", "missing"), ("wheel", "duplicate"), ("sdist", "duplicate"), ("wheel", "special"), ("sdist", "special")])
def test_each_archive_audit_requires_complete_unique_regular_members(tmp_path, kind, problem):
    from role_aware_dashboard_toolkit import release_audit

    dist = tmp_path / "dist"
    dist.mkdir()
    expected = {
        "wheel": sorted(set(release_audit._PUBLIC_PACKAGE_MEMBERS) | {
            release_audit._WHEEL_METADATA_ROOT + "/" + name for name in release_audit._WHEEL_METADATA_MEMBERS
        }),
        "sdist": sorted(release_audit._SDIST_ROOT + "/" + name for name in set(release_audit._PUBLIC_PACKAGE_MEMBERS) | set(release_audit._PUBLIC_SDIST_MEMBERS)),
    }
    for artifact_kind, members in expected.items():
        names = list(members)
        if artifact_kind == kind and problem == "missing":
            names.pop()
        if artifact_kind == kind and problem == "duplicate":
            names.append(names[0])
        if artifact_kind == "wheel":
            with warnings.catch_warnings(), zipfile.ZipFile(dist / "fixture.whl", "w") as archive:
                warnings.simplefilter("ignore", UserWarning)
                for index, name in enumerate(names):
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (0o120777 if kind == "wheel" and problem == "special" and index == 0 else 0o100644) << 16
                    archive.writestr(info, b"fixture")
        else:
            with tarfile.open(dist / "fixture.tar.gz", "w:gz") as archive:
                for index, name in enumerate(names):
                    info = tarfile.TarInfo(name)
                    if kind == "sdist" and problem == "special" and index == 0:
                        info.type = tarfile.SYMTYPE
                        info.linkname = "untrusted-target"
                        archive.addfile(info)
                    else:
                        info.size = len(b"fixture")
                        archive.addfile(info, io.BytesIO(b"fixture"))
    result = subprocess.run(
        [sys.executable, "-c", _artifact_audit_script(_read(".github/workflows/ci.yml"))],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
        text=True, capture_output=True, check=False,
    )
    assert (result.returncode == 0) is (problem is None), result.stderr
    if problem is not None:
        assert ("missing" if problem == "missing" else problem) in result.stderr
