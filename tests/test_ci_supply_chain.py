from __future__ import annotations

import ast
import json
import re
import sys
import textwrap
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
CONTRIBUTOR_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "contributor-ci.yml"
DEPENDENCY_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "dependency-audit.yml"
ACTION_PINS = {
    "actions/checkout": (
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
        "v7.0.0",
        5,
    ),
    "actions/setup-python": (
        "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "v7.0.0",
        5,
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "v7.0.1",
        5,
    ),
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "v8.0.1",
        3,
    ),
}


def test_ci_actions_are_pinned_to_reviewed_full_revisions():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    action_uses = Counter(
        re.findall(
            (
                r"^\s*-?\s*uses:\s+(actions/[^@\s]+)"
                r"@([0-9a-f]{40})\s+#\s+(v\d+\.\d+\.\d+)\s*$"
            ),
            workflow,
            flags=re.MULTILINE,
        )
    )
    candidate_uses = [
        line
        for line in workflow.splitlines()
        if re.search(r"\buses\b", line.split("#", 1)[0])
    ]
    all_uses = Counter(
        re.findall(
            r"^\s*-?\s*uses:\s+([^\s#]+)",
            workflow,
            flags=re.MULTILINE,
        )
    )
    expected_uses = Counter(
        {
            (action, sha, version): count
            for action, (sha, version, count) in ACTION_PINS.items()
        }
    )
    expected_refs = Counter(
        {
            f"{action}@{sha}": count
            for action, (sha, _version, count) in ACTION_PINS.items()
        }
    )

    assert action_uses == expected_uses
    assert len(candidate_uses) == sum(expected_uses.values())
    assert all_uses == expected_refs
    assert not re.search(r"uses\s*:\s+actions/[^@\s]+@v\d", workflow)
    downloads = [
        step for step in re.split(r"\n      - ", workflow)
        if "uses: actions/download-artifact@" in step
    ]
    assert len(downloads) == ACTION_PINS["actions/download-artifact"][2]
    assert all("digest-mismatch: error" in step for step in downloads)


def test_ci_checkouts_do_not_persist_credentials():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    checkout_sha, checkout_version, checkout_count = ACTION_PINS[
        "actions/checkout"
    ]
    checkout_line = (
        f"- uses: actions/checkout@{checkout_sha} # {checkout_version}"
    )
    pattern = (
        re.escape(checkout_line)
        + r"\n\s+with:\n\s+persist-credentials: false"
    )

    assert len(re.findall(pattern, workflow)) == checkout_count


def test_contributor_ci_runs_unprivileged_without_release_authorization():
    workflow = CONTRIBUTOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    triggers = workflow.split("on:\n", 1)[1].split("permissions:\n", 1)[0]
    assert re.findall(r"^  ([A-Za-z_]+):", triggers, flags=re.MULTILINE) == [
        "pull_request", "push", "workflow_dispatch",
    ]
    assert 'branches: [main, "integrate/**"]' in triggers
    assert "paths:" not in triggers and "paths-ignore:" not in triggers
    assert "permissions:\n  contents: read\n" in workflow
    assert "    permissions: {}\n" in workflow
    for forbidden in (
        "pull_request_target", "secrets.", "vars.", "RELEASE_CI_APPROVED_SHA", "contents: write",
        "id-token:", "continue-on-error", "twine upload", "actions/cache@",
    ):
        assert forbidden not in workflow
    refs = re.findall(r"^\s*-?\s*uses:\s+([^\s]+)", workflow, flags=re.MULTILINE)
    assert Counter(refs) == Counter({
        f"actions/checkout@{ACTION_PINS['actions/checkout'][0]}": 4,
        f"actions/setup-python@{ACTION_PINS['actions/setup-python'][0]}": 4,
        f"actions/upload-artifact@{ACTION_PINS['actions/upload-artifact'][0]}": 3,
    })
    assert workflow.count("persist-credentials: false") == 4
    assert workflow.count("timeout-minutes:") == 5
    assert 'python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]' in workflow
    assert "python -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache" in workflow
    assert "python -m pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75" in workflow
    assert "python -m build\n          python -m twine check dist/*" in workflow


@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped", ""])
@pytest.mark.parametrize("job", ["tests", "quality", "browser", "landscaping"])
def test_actual_contributor_required_check_rejects_unsuccessful_jobs(monkeypatch, result, job):
    workflow = CONTRIBUTOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    gate = workflow.split("  required:\n", 1)[1]
    assert "    name: contributor-checks\n" in gate
    assert "    if: ${{ always() }}\n" in gate
    assert "    needs: [tests, quality, browser, landscaping]\n" in gate
    body = re.search(r"python - <<'PY'\n(.*?)^          PY$", gate, flags=re.MULTILINE | re.DOTALL).group(1)
    checks = compile(textwrap.dedent(body), "contributor-required-check", "exec")
    results = {name: {"result": "success"} for name in ("tests", "quality", "browser", "landscaping")}
    results[job]["result"] = result
    monkeypatch.setenv("NEEDS_JSON", json.dumps(results))
    if result == "success":
        exec(checks, {})
    else:
        with pytest.raises(SystemExit, match="All contributor jobs must succeed"):
            exec(checks, {})
    monkeypatch.setenv("NEEDS_JSON", json.dumps({name: data for name, data in results.items() if name != job}))
    with pytest.raises(SystemExit, match="All contributor jobs must succeed"):
        exec(checks, {})


def test_contributor_ci_exercises_landscaping_with_its_required_dependencies():
    workflow = CONTRIBUTOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    demo = workflow.split("  landscaping:\n", 1)[1].split("  required:\n", 1)[0]
    assert "    runs-on: ubuntu-latest\n" in demo
    assert 'python -m pip install ".[api]" -r examples/landscaping/requirements-dev.txt' in demo
    assert "python -m pip check" in demo
    assert "python -m pytest -c examples/landscaping/pyproject.toml examples/landscaping/tests --import-mode=importlib -q" in demo
    assert "python examples/landscaping/scripts/browser_check.py --output-dir" in demo
    assert "python examples/landscaping/scripts/operational_check.py --output-dir" in demo
    assert 'python -m build --sdist --outdir "$RUNNER_TEMP/landscaping-dist"' in demo
    assert 'python tools/landscaping_artifact_smoke.py --sdist "${sdists[0]}" --output-dir' in demo
    assert '${{ runner.temp }}/landscaping-operations/summary.json' in demo
    assert '${{ runner.temp }}/landscaping-artifact/summary.json' in demo
    assert "python -m playwright install --with-deps chromium" in demo
    assert "if: ${{ always() }}" in demo
    assert "path: ${{ runner.temp }}/landscaping-browser" in demo


def test_contributor_ci_runs_full_suite_on_windows_and_macos_and_keeps_browser_evidence():
    workflow = CONTRIBUTOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    tests = workflow.split("  tests:\n", 1)[1].split("  quality:\n", 1)[0]
    assert "    runs-on: ${{ matrix.os }}\n" in tests
    assert "        os: [ubuntu-latest]\n" in tests
    assert re.search(
        r"include:\n\s+- os: windows-latest\n\s+python-version: [\"']3\.11[\"']",
        tests,
    )
    # macOS keeps the system temp directory under the /var symlink; the full
    # suite must pass there from a clean checkout.
    assert re.search(
        r"\n\s+- os: macos-latest\n\s+python-version: [\"']3\.12[\"']",
        tests,
    )
    assert "      fail-fast: false\n" in tests
    assert '        run: python -m pytest -q --junitxml="${{ runner.temp }}/contributor-tests.xml"\n' in tests

    browser = workflow.split("  browser:\n", 1)[1].split("  required:\n", 1)[0]
    assert "    runs-on: ubuntu-latest\n" in browser
    assert "python -m playwright install --with-deps chromium" in browser
    assert "python tools/browser_smoke.py" in browser
    assert "${{ runner.temp }}" in browser or "$RUNNER_TEMP" in browser
    upload = browser.split("uses: actions/upload-artifact@", 1)[1]
    assert "retention-days: 7" in upload
    assert "if: ${{ always() }}" in browser or "if: ${{ !cancelled() }}" in browser


def _failure_annotation_script():
    workflow = CONTRIBUTOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    tests = workflow.split("  tests:\n", 1)[1].split("  quality:\n", 1)[0]
    step = tests.split("      - name: Annotate failing test names\n", 1)[1]
    assert "        if: ${{ failure() }}\n" in step
    assert "        shell: python\n" in step
    assert "continue-on-error" not in tests
    script = textwrap.dedent(step.split("        run: |\n", 1)[1])
    return compile(script, "workflow-failing-test-annotations", "exec")


@pytest.mark.parametrize("kind", ["failure", "error"])
def test_actual_failure_annotations_escape_commands_without_reporting_private_bodies(tmp_path, monkeypatch, capsys, kind):
    report = ET.Element("testsuites")
    suite = ET.SubElement(report, "testsuite")
    case = ET.SubElement(suite, "testcase", {
        "classname": "tests.synthetic%\r\n::error::injected",
        "name": "test_probe%0A\r\n::warning::injected",
    })
    ET.SubElement(case, kind, {"message": "synthetic-private-password"}).text = "private response body"
    ET.SubElement(case, "system-out").text = "private captured stdout"
    ET.SubElement(case, "system-err").text = "private captured stderr"
    (tmp_path / "contributor-tests.xml").write_bytes(ET.tostring(report))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    exec(_failure_annotation_script(), {})
    output = capsys.readouterr().out
    assert output == (
        "::error::Failed test: tests.synthetic%25%0D%0A::error::injected::"
        "test_probe%250A%0D%0A::warning::injected\n"
    )
    assert len(output.splitlines()) == 1
    assert "private" not in output


@pytest.mark.parametrize("kind", ["failure", "error"])
@pytest.mark.parametrize("style", ["relative", "backslashes", "absolute"])
def test_actual_failure_annotations_report_only_safe_final_location(tmp_path, monkeypatch, capsys, kind, style):
    checkout = tmp_path / "checkout"
    source = checkout / "tools" / "worker.py"
    source.parent.mkdir(parents=True)
    source.write_text("# synthetic source\n", encoding="utf-8")
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    path = {"relative": "tools/worker.py", "backslashes": r"tools\worker.py", "absolute": str(source)}[style]
    report = ET.Element("testsuites")
    case = ET.SubElement(report, "testcase", {"classname": "tests.synthetic", "name": "test_probe"})
    ET.SubElement(case, kind, {"message": "private exception message"}).text = (
        "tools/worker.py:7: ValueError\n"
        "private assertion text and source line\n"
        f"{path}:142: PermissionError\n"
    )
    ET.SubElement(case, "system-out").text = "private captured stdout"
    (tmp_path / "contributor-tests.xml").write_bytes(ET.tostring(report))
    exec(_failure_annotation_script(), {})
    assert capsys.readouterr().out == (
        "::error::Failed test: tests.synthetic::test_probe; "
        "failure at tools/worker.py:142 (PermissionError)\n"
    )


@pytest.mark.parametrize("summary", [
    "private assertion text without a traceback summary",
    "tools/missing.py:142: PermissionError",
    "docs/private.py:142: PermissionError",
    "tools/directory.py:142: PermissionError",
    "tools/worker.txt:142: PermissionError",
    "tools/../private.py:142: PermissionError",
    "tools/worker.py:0: PermissionError",
    "tools/worker.py:-1: PermissionError",
    "tools/worker.py:10000000: PermissionError",
    "tools/worker.py:142: PermissionError: private message",
    "tools/worker.py:142: ::warning::private message",
    "tools/worker.py:142: PermissionError%0A::error::private message",
    "tools/worker.py:142: " + "E" * 81,
    "tools/" + "a" * 101 + ".py:142: PermissionError",
    "tools/worker%0A.py:142: PermissionError",
    "tools/worker.py:142: private_password",
])
def test_actual_failure_annotations_omit_untrusted_location_details(tmp_path, monkeypatch, capsys, summary):
    checkout = tmp_path / "checkout"
    (checkout / "tools" / "directory.py").mkdir(parents=True)
    (checkout / "docs").mkdir()
    for path in ("tools/worker.py", "tools/worker.txt", "docs/private.py", "private.py", "tools/worker%0A.py"):
        (checkout / path).write_text("# synthetic source\n", encoding="utf-8")
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    report = ET.Element("testsuites")
    case = ET.SubElement(report, "testcase", {"classname": "tests.synthetic", "name": "test_probe"})
    ET.SubElement(case, "failure").text = summary
    (tmp_path / "contributor-tests.xml").write_bytes(ET.tostring(report))
    exec(_failure_annotation_script(), {})
    assert capsys.readouterr().out == "::error::Failed test: tests.synthetic::test_probe\n"


@pytest.mark.parametrize("location", ["outside", "file_symlink", "directory_symlink"])
def test_actual_failure_annotations_reject_outside_and_linked_sources(tmp_path, monkeypatch, capsys, location):
    checkout = tmp_path / "checkout"
    tools = checkout / "tools"
    tools.mkdir(parents=True)
    outside = tmp_path / "outside.py"
    outside.write_text("# synthetic source\n", encoding="utf-8")
    source = tools / "worker.py"
    source.write_text("# synthetic source\n", encoding="utf-8")
    try:
        if location == "file_symlink":
            (tools / "linked.py").symlink_to(source)
            summary_path = "tools/linked.py"
        elif location == "directory_symlink":
            (tools / "linked").symlink_to(tools, target_is_directory=True)
            summary_path = "tools/linked/worker.py"
        else:
            summary_path = str(outside)
    except OSError:
        pytest.skip("This runner does not permit creating symlinks")
    monkeypatch.chdir(checkout)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    report = ET.Element("testsuites")
    case = ET.SubElement(report, "testcase", {"classname": "tests.synthetic", "name": "test_probe"})
    ET.SubElement(case, "failure").text = f"{summary_path}:142: PermissionError"
    (tmp_path / "contributor-tests.xml").write_bytes(ET.tostring(report))
    exec(_failure_annotation_script(), {})
    assert capsys.readouterr().out == "::error::Failed test: tests.synthetic::test_probe\n"


def test_actual_failure_annotations_limit_names_and_total_annotations(tmp_path, monkeypatch, capsys):
    report = ET.Element("testsuite")
    for _ in range(30):
        case = ET.SubElement(report, "testcase", {"classname": "%" * 500, "name": "\r" * 500})
        ET.SubElement(case, "failure").text = "synthetic-private-password"
    (tmp_path / "contributor-tests.xml").write_bytes(ET.tostring(report))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    exec(_failure_annotation_script(), {})
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 26
    assert lines[:25] == ["::error::Failed test: " + "%25" * 240 + "::" + "%0D" * 240] * 25
    assert lines[-1] == "::warning::Additional failing test names omitted; inspect the job logs."
    assert all(len(line) < 1600 for line in lines)
    assert not any("synthetic-private-password" in line for line in lines)


def test_actual_failure_annotations_name_unknown_collection_errors_and_ignore_passes(tmp_path, monkeypatch, capsys):
    report = ET.Element("testsuite")
    failed = ET.SubElement(report, "testcase")
    ET.SubElement(failed, "error", {"message": "private collection error"})
    ET.SubElement(report, "testcase", {"name": "passing_test"})
    skipped = ET.SubElement(report, "testcase", {"name": "skipped_test"})
    ET.SubElement(skipped, "skipped")
    (tmp_path / "contributor-tests.xml").write_bytes(ET.tostring(report))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    exec(_failure_annotation_script(), {})
    assert capsys.readouterr().out == "::error::Failed test: <unknown class>::<unknown test>\n"


@pytest.mark.parametrize("problem", ["missing", "unreadable", "malformed", "too-large", "missing-runner-temp", "no-failed-cases"])
def test_actual_failure_annotations_explain_unavailable_diagnostics_safely(tmp_path, monkeypatch, capsys, problem):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    report = tmp_path / "contributor-tests.xml"
    if problem == "unreadable":
        report.mkdir()
    elif problem == "malformed":
        report.write_text("private malformed report <", encoding="utf-8")
    elif problem == "too-large":
        report.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
    elif problem == "missing-runner-temp":
        monkeypatch.delenv("RUNNER_TEMP")
    elif problem == "no-failed-cases":
        report.write_text('<testsuite><testcase name="passed" /></testsuite>', encoding="utf-8")
    exec(_failure_annotation_script(), {})
    output = capsys.readouterr().out
    if problem == "no-failed-cases":
        assert output == "::error::JUnit report lists no failed test cases; inspect the original job failure.\n"
    else:
        assert output == "::error::JUnit report unavailable, invalid, or too large; inspect the original job failure.\n"
    assert str(tmp_path) not in output
    assert "private" not in output


def test_dependency_audit_is_scheduled_and_unprivileged_on_every_pull_request():
    workflow = DEPENDENCY_WORKFLOW_PATH.read_text(encoding="utf-8")
    triggers = workflow.split("on:\n", 1)[1].split("permissions:\n", 1)[0]
    assert set(re.findall(r"^  ([A-Za-z_]+):", triggers, flags=re.MULTILINE)) == {
        "pull_request", "push", "workflow_dispatch", "schedule",
    }
    assert 'branches: [main, "integrate/**"]' in triggers
    assert "17 9 * * 1" in triggers
    assert "paths:" not in triggers and "paths-ignore:" not in triggers
    assert "permissions:\n  contents: read\n" in workflow
    assert "    permissions: {}\n" in workflow
    for forbidden in (
        "pull_request_target", "secrets.", "vars.", "RELEASE_CI_APPROVED_SHA", "contents: write",
        "id-token:", "continue-on-error", "twine upload", "actions/cache@",
    ):
        assert forbidden not in workflow
    refs = re.findall(r"^\s*-?\s*uses:\s+([^\s]+)", workflow, flags=re.MULTILINE)
    assert Counter(refs) == Counter({
        f"{action}@{ACTION_PINS[action][0]}": 1
        for action in ("actions/checkout", "actions/setup-python", "actions/upload-artifact")
    })
    assert workflow.count("persist-credentials: false") == 1
    assert workflow.count("timeout-minutes:") == 2
    assert re.search(r"extra: \[[\"']?api[\"']?, [\"']?full[\"']?, [\"']?landscaping[\"']?\]", workflow)
    assert "pip-audit==2.10.1" in workflow
    assert "--python" in workflow
    assert "--audit-python" in workflow
    assert "--report-dir" in workflow
    assert "retention-days: 7" in workflow
    assert "if: ${{ always() }}" in workflow or "if: ${{ !cancelled() }}" in workflow


@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped", ""])
def test_actual_dependency_required_check_rejects_unsuccessful_or_missing_audits(monkeypatch, result):
    workflow = DEPENDENCY_WORKFLOW_PATH.read_text(encoding="utf-8")
    gate = workflow.split("  required:\n", 1)[1]
    assert "    name: dependency-checks\n" in gate
    assert "    if: ${{ always() }}\n" in gate
    assert "    needs: [audit]\n" in gate
    body = re.search(r"python - <<'PY'\n(.*?)^          PY$", gate, flags=re.MULTILINE | re.DOTALL).group(1)
    checks = compile(textwrap.dedent(body), "dependency-required-check", "exec")
    monkeypatch.setenv("NEEDS_JSON", json.dumps({"audit": {"result": result}}))
    if result == "success":
        exec(checks, {})
    else:
        with pytest.raises(SystemExit):
            exec(checks, {})
    for incomplete in ({}, {"unexpected": {"result": "success"}}):
        monkeypatch.setenv("NEEDS_JSON", json.dumps(incomplete))
        with pytest.raises(SystemExit):
            exec(checks, {})


def test_ci_smokes_each_supported_optional_extra_without_product_adapters():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    for extra_name in ("workbench", "auth", "api", "pandas", "full"):
        assert (
            f'pip install "${{wheel}}[{extra_name}]"'
            in workflow
        )
        assert f".wheel-{extra_name}-smoke" in workflow

    lowered = workflow.lower()
    for forbidden in (
        "pack-builder",
        "pack-harness",
        "pack-repoos",
        "pack-sdk",
        "codex_builder",
        "repoos",
        "dashboard_stub",
        "standalone_demo",
        "semantic_snapshot",
    ):
        assert forbidden not in lowered


def test_hosted_ci_requires_manual_dispatch_and_exact_commit_authorization():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    triggers = workflow.split("on:\n", 1)[1].split("permissions:\n", 1)[0]
    assert re.findall(r"^  ([A-Za-z_]+):", triggers, flags=re.MULTILINE) == ["workflow_dispatch"]
    job_blocks = re.findall(r"^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)", workflow.split("jobs:\n", 1)[1], flags=re.MULTILINE | re.DOTALL)
    expected_timeouts = {"test": 15, "coverage-gate": 15, "packaging-release-smoke": 25, "release-candidate": 10, "windows-release-smoke": 20}
    assert {name for name, _block in job_blocks} == set(expected_timeouts)
    for name, block in job_blocks:
        guards = re.findall(r"^    if:\s*(.+)$", block, flags=re.MULTILINE)
        assert guards == ["${{ github.event_name == 'workflow_dispatch' && vars.RELEASE_CI_APPROVED_SHA == github.sha && (github.ref == 'refs/heads/candidate' || github.ref == 'refs/heads/main') }}"], name
        assert re.findall(r"^    timeout-minutes: (\d+)$", block, flags=re.MULTILINE) == [str(expected_timeouts[name])]
    assert "permissions:\n  contents: read\n" in workflow
    assert len(re.findall(r"^\s*permissions:", workflow, flags=re.MULTILINE)) == 1
    assert "concurrency:\n  group: release-candidate-validation\n  cancel-in-progress: false\n" in workflow
    assert "continue-on-error" not in workflow
    assert not re.search(r"^        if:", workflow, flags=re.MULTILINE)
    # Release notes cite these artifacts; keep them for GitHub's 90-day maximum.
    assert workflow.count("          retention-days: 90\n") == ACTION_PINS["actions/upload-artifact"][2]
    assert "retention-days: 1\n" not in workflow
    assert "twine upload" not in workflow


def test_installed_smokes_keep_environments_outside_the_checkout():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    venv_targets = re.findall(r"python -m venv ([^\n]+)", workflow)
    assert len(venv_targets) == 9
    assert all(target.startswith('"$RUNNER_TEMP/') or target in {"$venv", "$authVenv"} for target in venv_targets)
    assert '$venv = Join-Path $env:RUNNER_TEMP ".wheel-smoke-win"' in workflow
    assert '$authVenv = Join-Path $env:RUNNER_TEMP ".wheel-auth-smoke-win"' in workflow
    assert workflow.count(" -I ") == 9
    assert workflow.count("assert environment.is_relative_to(") == 9
    assert workflow.count(".resolve().is_relative_to(environment)") == 9
    assert "sys.path[:] =" not in workflow
    assert "sys.path=[" not in workflow
    assert '--no-build-isolation' not in workflow
    assert '"$RUNNER_TEMP/.sdist-smoke/bin/python" -m pip install --use-pep517 "$sdist"' in workflow


def test_windows_focused_lane_runs_identifier_regressions():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    job = workflow.split("  windows-release-smoke:\n", 1)[1]
    step = job.split("      - name: Windows focused tests\n", 1)[1].split("      - name:", 1)[0]
    command = re.search(r"^        run: (.+)$", step, flags=re.MULTILINE).group(1)
    assert command.startswith("python -m pytest ")
    required_tests = {
        "tests/test_path_redaction.py", "tests/test_permission_boundaries.py",
        "tests/test_review_identifier_regressions.py", "tests/test_store_identifier_contract.py",
    }
    assert required_tests <= set(command.split())
    assert all((REPO_ROOT / path).is_file() for path in required_tests)


def _installed_smoke_script(workflow: str, lane: str) -> str:
    if lane == "windows-auth":
        job = workflow.split("      - name: Auth wheel install smoke (Windows)\n", 1)[1]
        body = re.search(r"\$authSmoke = @'\n(.*?)^          '@$", job, flags=re.MULTILINE | re.DOTALL).group(1)
    else:
        marker = "      - name: Wheel install smoke\n" if lane == "core" else f'          python -m venv "$RUNNER_TEMP/.wheel-{lane}-smoke"\n'
        job = workflow.split(marker, 1)[1]
        body = re.search(r"-I - <<'PY'\n(.*?)^          PY$", job, flags=re.MULTILINE | re.DOTALL).group(1)
    return textwrap.dedent(body)


def test_api_smoke_builds_the_installed_app_without_streamlit():
    script = _installed_smoke_script(WORKFLOW_PATH.read_text(encoding="utf-8"), "api")
    compile(script, "workflow-api-smoke", "exec")
    assert 'assert importlib.util.find_spec("streamlit") is None' in script
    assert "app = create_app(role_aware_dashboard_toolkit.ControlRegistry())" in script
    assert 'assert {"/health", "/controls"} <= {route.path for route in app.routes}' in script


@pytest.mark.parametrize("problem", [None, "wrong_dependency", "missing_help", "wrong_diagnostic", "missing_diagnostic", "render_succeeds"])
def test_actual_core_smoke_checks_missing_streamlit_diagnostic(monkeypatch, problem):
    import role_aware_dashboard_toolkit as radt
    from role_aware_dashboard_toolkit import dashboard

    parsed = ast.parse(_installed_smoke_script(WORKFLOW_PATH.read_text(encoding="utf-8"), "core"))
    imports = [node for node in ast.walk(parsed) if isinstance(node, ast.ImportFrom)]
    render_check = next(
        node for node in ast.walk(parsed)
        if isinstance(node, ast.Try) and any(
            isinstance(handler.type, ast.Name) and handler.type.id == "ModuleNotFoundError"
            for handler in node.handlers
        )
    )
    checks = compile(ast.Module(body=[*imports, render_check], type_ignores=[]), "workflow-core-diagnostic", "exec")
    monkeypatch.setattr(dashboard, "st", None)
    monkeypatch.setitem(sys.modules, "streamlit", None)
    original_render = radt.render

    def render(config):
        if problem == "render_succeeds":
            return None
        try:
            return original_render(config)
        except ModuleNotFoundError as exc:
            if problem == "wrong_dependency":
                exc.name = "other_dependency"
            elif problem == "missing_help":
                exc.msg = exc.msg.split(" [RADT-STREAMLIT]", 1)[0]
            elif problem == "wrong_diagnostic":
                exc.diagnostic["operation"] = "unrelated_operation"
            elif problem == "missing_diagnostic":
                del exc.diagnostic
            raise

    monkeypatch.setattr(radt, "render", render)
    namespace = {"radt": radt, "config": radt.DashboardConfig(auth_mode="demo")}
    if problem is None:
        exec(checks, namespace)
    else:
        expected_error = AttributeError if problem == "missing_diagnostic" else AssertionError
        with pytest.raises(expected_error):
            exec(checks, namespace)


@pytest.mark.parametrize("lane", ["core", "auth", "full", "windows-auth"])
@pytest.mark.parametrize("source_on_path,venv_inside_checkout", [(False, False), (True, False), (False, True)])
def test_actual_smoke_import_guard_preserves_external_install_and_rejects_checkout(monkeypatch, tmp_path, source_on_path, venv_inside_checkout, lane):
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    parsed = ast.parse(_installed_smoke_script(workflow, lane))
    import_boundary = next(
        index for index, statement in enumerate(parsed.body)
        if isinstance(statement, ast.With)
        or isinstance(statement, ast.Import) and any(alias.name == "role_aware_dashboard_toolkit" for alias in statement.names)
    )
    prefix = compile(ast.Module(body=parsed.body[:import_boundary], type_ignores=[]), "workflow-import-guard", "exec")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    environment = (checkout if venv_inside_checkout else runner_temp) / "installed"
    installed_path = str(environment / "lib" / "site-packages")
    paths = [installed_path, *([str(checkout)] if source_on_path else [])]
    with monkeypatch.context() as patch:
        patch.chdir(checkout)
        patch.setenv("GITHUB_WORKSPACE", str(checkout))
        patch.setenv("RUNNER_TEMP", str(runner_temp))
        patch.setattr(sys, "prefix", str(environment))
        patch.setattr(sys, "path", list(paths))
        if source_on_path or venv_inside_checkout:
            with pytest.raises(AssertionError):
                exec(prefix, {})
        else:
            exec(prefix, {})
        assert sys.path == paths


@pytest.mark.parametrize("lane", ["auth", "full", "windows-auth"])
def test_auth_smokes_check_runtime_and_resources_from_installed_wheel(lane):
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    script = _installed_smoke_script(workflow, lane)
    compile(script, f"workflow-{lane}", "exec")
    for required in (
        "import authlib", "import streamlit", "streamlit.login", "streamlit.logout",
        "from role_aware_dashboard_toolkit.access import AccessPolicy, InMemoryAccessStore, SQLiteAccessStore",
        "from role_aware_dashboard_toolkit.access_cli import initialize_access",
        "from role_aware_dashboard_toolkit.streamlit_auth import StreamlitIdentityResolver",
        "assert pathlib.Path(role_aware_dashboard_toolkit.__file__).resolve().is_relative_to(environment)",
    ):
        assert required in script
    if lane == "windows-auth":
        step = workflow.split("      - name: Auth wheel install smoke (Windows)\n", 1)[1]
        for command in (
            "python -m venv $authVenv", '& $authPython -m pip install "$($wheels[0].FullName)[auth]"',
            "& $authPython -m pip check", "$authSmoke | & $authPython -I -",
        ):
            assert command + "\n          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" in step
        assert '$wheels.Count -ne 1' in step
    else:
        assert f'"$RUNNER_TEMP/.wheel-{lane}-smoke/bin/python" -m pip check' in workflow


@pytest.mark.parametrize("lane", ["auth", "full", "windows-auth"])
@pytest.mark.parametrize("problem", [None, "missing_file", "extra_file", "demo_mode", "bad_python", "missing_guide"])
def test_actual_auth_smoke_rejects_incomplete_or_invalid_installed_resources(lane, problem):
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    body = ast.parse(_installed_smoke_script(workflow, lane)).body
    if lane == "windows-auth":
        body = next(statement for statement in body if isinstance(statement, ast.With)).body[0].body
    first_check = next(
        index for index, statement in enumerate(body)
        if isinstance(statement, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "starter" for target in statement.targets)
    )
    checks = compile(ast.Module(body=body[first_check:], type_ignores=[]), "workflow-auth-resources", "exec")
    starter = dict.fromkeys(["app.py", ".streamlit/config.toml", "AGENTS.md", "README.md", ".gitignore"], "")
    starter["app.py"] = 'auth_mode="authenticated"\n'
    guide = "Use access_cli grant to provision explicitly."
    if problem == "missing_file":
        del starter[".gitignore"]
    elif problem == "extra_file":
        starter["secrets.toml"] = ""
    elif problem == "demo_mode":
        starter["app.py"] = 'auth_mode="demo"\n'
    elif problem == "bad_python":
        starter["app.py"] += "if\n"
    elif problem == "missing_guide":
        guide = ""

    def read_starter(*, authenticated):
        assert authenticated is True
        return starter

    def read_guide(topic):
        assert topic == "authentication"
        return {"content": guide}

    namespace = {"read_starter": read_starter, "read_guide": read_guide}
    if problem is None:
        exec(checks, namespace)
    else:
        with pytest.raises(SyntaxError if problem == "bad_python" else AssertionError):
            exec(checks, namespace)


def test_workflow_dashboard_configs_construct_under_current_rules():
    """The installed-wheel smokes build a DashboardConfig the local suite never runs.

    A config rule change (such as requiring an explicit auth_mode) breaks the
    release workflow without failing any local test, so construct each one here.
    """
    import role_aware_dashboard_toolkit as radt

    workflows = (WORKFLOW_PATH, CONTRIBUTOR_WORKFLOW_PATH, DEPENDENCY_WORKFLOW_PATH)
    texts = [path.read_text(encoding="utf-8") for path in workflows]
    calls = [call for text in texts for call in re.findall(r"radt\.DashboardConfig\([^()\n]*\)", text)]
    # Every call must be one this test can parse; a new multi-line call fails here.
    assert len(calls) == sum(text.count("DashboardConfig(") for text in texts)
    assert len(calls) == 3
    for call in calls:
        node = ast.parse(call, mode="eval").body
        assert isinstance(node, ast.Call) and not node.args
        kwargs = {keyword.arg: ast.literal_eval(keyword.value) for keyword in node.keywords}
        config = radt.DashboardConfig(**kwargs)
        assert config.icon == "Core"
