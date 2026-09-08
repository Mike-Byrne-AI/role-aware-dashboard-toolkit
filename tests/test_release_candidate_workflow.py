import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path


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


def test_ci_release_candidate_lane_is_non_publish_and_uploads_evidence():
    workflow = _read(".github/workflows/ci.yml")
    job = _release_candidate_job(workflow)
    packaging_job = _packaging_release_job(workflow)

    assert "workflow_dispatch:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "id-token: write" not in workflow
    assert "packages: write" not in workflow

    assert "\n    if: ${{ false }}\n" in job
    assert "needs: [test, coverage-gate, packaging-release-smoke, windows-release-smoke]" in job
    assert (
        "python tools/pre_release_check.py --json --require-clean "
        "> pre_release_report.json || true"
    ) in job
    assert "Pre-OSS release state remains intentionally blocked only on these gates." in job
    assert (
        'allowed_blocked = {"distribution_name_ownership", '
        '"oss_public_coordinates", "security_intake_contact"}'
    ) in job
    assert "pre_release_check unexpected blocked checks" in job
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
    assert "uses: actions/upload-artifact@" in job
    assert "name: role_aware_dashboard_toolkit-release-candidate-dist" in job
    assert "name: role_aware_dashboard_toolkit-release-candidate-evidence" in job
    assert "pre_release_report.json" in job
    assert "release_candidate_evidence.json" in job
    assert "twine upload" not in job

    assert "name: Upload validated distribution artifacts" in packaging_job
    assert "if: github.event_name == 'workflow_dispatch'" in packaging_job
    assert "name: role_aware_dashboard_toolkit-validated-dist" in packaging_job
    assert "path: dist/*" in packaging_job
    upload_index = packaging_job.index("name: Upload validated distribution artifacts")
    assert packaging_job.index("name: Wheel install smoke") < upload_index
    assert packaging_job.index("name: Sdist install smoke") < upload_index


def test_release_candidate_evidence_hashes_exact_artifacts_and_checks_commit(tmp_path):
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
        json.dumps({"status": "blocked", "blocked": ["oss_public_coordinates"], "failures": []}),
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

    env = {
        **fixture_env,
        "GITHUB_SHA": source_sha,
        "GITHUB_WORKSPACE": str(workspace),
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
    assert evidence["artifact_sha256"] == {
        name: hashlib.sha256(content).hexdigest() for name, content in artifacts.items()
    }

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


def test_packaging_hygiene_distinguishes_non_publish_dispatch(tmp_path):
    workflow = _read(".github/workflows/ci.yml")
    script = _publication_hygiene_script(workflow)
    report_path = tmp_path / "pre_release_report.json"
    report_path.write_text(
        json.dumps(
            {
                "blocked": ["oss_public_coordinates", "security_intake_contact"],
                "failures": [],
            }
        ),
        encoding="utf-8",
    )

    base_env = dict(os.environ)
    cases = [
        ("workflow_dispatch", "refs/heads/main", True),
        ("push", "refs/heads/main", False),
        ("workflow_dispatch", "refs/tags/v1.0.0", False),
        ("push", "refs/heads/feature", True),
    ]
    for event_name, ref, should_pass in cases:
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env={**base_env, "GITHUB_EVENT_NAME": event_name, "GITHUB_REF": ref},
            text=True,
            capture_output=True,
            check=False,
        )
        assert (result.returncode == 0) is should_pass, (event_name, ref, result.stderr)


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
    assert "Verify artifact digests against the release" in runbook
    assert "$releaseCommit = (git rev-parse HEAD).Trim()" in runbook
    assert "git status --porcelain" in runbook
    assert 'git tag "v$version" $releaseCommit' in runbook
    assert "configured PyPI distribution name is available" in runbook
    assert "project metadata contains real public coordinates" in runbook
    assert "monitored reporting path" in runbook
    assert "A pre-publication smoke must use local artifacts" in runbook

    checklist = _read("docs/release_checklist.md")
    assert "pre_release_check.py --json --require-clean" in checklist
    assert "tracked and untracked files" in checklist

    gitignore = _read(".gitignore")
    assert "/pre_release_report.json" in gitignore
    assert "/release_candidate_evidence.json" in gitignore
