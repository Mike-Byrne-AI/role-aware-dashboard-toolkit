from __future__ import annotations

import ast
import re
import sys
import textwrap
from collections import Counter
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
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
        3,
    ),
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "v8.0.1",
        1,
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
    assert "digest-mismatch: error" in workflow


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


def test_ci_smokes_each_supported_optional_extra_without_product_adapters():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    for extra_name in ("workbench", "api", "pandas", "full"):
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
        assert guards == ["${{ github.event_name == 'workflow_dispatch' && vars.XL422_CI_APPROVED_SHA == github.sha && (github.ref == 'refs/heads/candidate' || github.ref == 'refs/heads/main') }}"], name
        assert re.findall(r"^    timeout-minutes: (\d+)$", block, flags=re.MULTILINE) == [str(expected_timeouts[name])]
    assert "permissions:\n  contents: read\n" in workflow
    assert len(re.findall(r"^\s*permissions:", workflow, flags=re.MULTILINE)) == 1
    assert "concurrency:\n  group: xl422-candidate-validation\n  cancel-in-progress: false\n" in workflow
    assert "continue-on-error" not in workflow
    assert not re.search(r"^        if:", workflow, flags=re.MULTILINE)
    assert workflow.count("          retention-days: 1\n") == ACTION_PINS["actions/upload-artifact"][2]
    assert "twine upload" not in workflow


def test_installed_smokes_keep_environments_outside_the_checkout():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    venv_targets = re.findall(r"python -m venv ([^\n]+)", workflow)
    assert len(venv_targets) == 7
    assert all(target.startswith('"$RUNNER_TEMP/') or target == "$venv" for target in venv_targets)
    assert '$venv = Join-Path $env:RUNNER_TEMP ".wheel-smoke-win"' in workflow
    assert workflow.count(" -I ") == 7
    assert workflow.count("assert environment.is_relative_to(") == 7
    assert workflow.count(".resolve().is_relative_to(environment)") == 7
    assert "sys.path[:] =" not in workflow
    assert "sys.path=[" not in workflow
    assert '--no-build-isolation' not in workflow
    assert '"$RUNNER_TEMP/.sdist-smoke/bin/python" -m pip install --use-pep517 "$sdist"' in workflow


@pytest.mark.parametrize("source_on_path,venv_inside_checkout", [(False, False), (True, False), (False, True)])
def test_actual_smoke_import_guard_preserves_external_install_and_rejects_checkout(monkeypatch, tmp_path, source_on_path, venv_inside_checkout):
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    job = workflow.split("      - name: Wheel install smoke\n", 1)[1].split("      - name: Wheel optional-extra smokes", 1)[0]
    body = re.search(r"-I - <<'PY'\n(.*?)^          PY$", job, flags=re.MULTILINE | re.DOTALL).group(1)
    parsed = ast.parse(textwrap.dedent(body))
    first_with = next(index for index, statement in enumerate(parsed.body) if isinstance(statement, ast.With))
    prefix = compile(ast.Module(body=parsed.body[:first_with], type_ignores=[]), "workflow-import-guard", "exec")
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
