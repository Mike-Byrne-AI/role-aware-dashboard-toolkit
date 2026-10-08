from __future__ import annotations

import ast
import json
import re
import sys
import textwrap
from collections import Counter
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
CONTRIBUTOR_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "contributor-ci.yml"
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


def test_contributor_ci_runs_unprivileged_without_release_authorization():
    workflow = CONTRIBUTOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    triggers = workflow.split("on:\n", 1)[1].split("permissions:\n", 1)[0]
    assert re.findall(r"^  ([A-Za-z_]+):", triggers, flags=re.MULTILINE) == [
        "pull_request", "push", "workflow_dispatch",
    ]
    assert "branches: [main]" in triggers
    assert "paths:" not in triggers and "paths-ignore:" not in triggers
    assert "permissions:\n  contents: read\n" in workflow
    assert "    permissions: {}\n" in workflow
    for forbidden in (
        "pull_request_target", "secrets.", "vars.", "XL422", "contents: write",
        "id-token:", "continue-on-error", "twine upload", "actions/cache@",
    ):
        assert forbidden not in workflow
    refs = re.findall(r"^\s*- uses:\s+([^\s]+)", workflow, flags=re.MULTILINE)
    assert Counter(refs) == Counter({
        f"{action}@{ACTION_PINS[action][0]}": 2
        for action in ("actions/checkout", "actions/setup-python")
    })
    assert workflow.count("persist-credentials: false") == 2
    assert workflow.count("timeout-minutes:") == 3
    assert 'python-version: ["3.10", "3.11", "3.12"]' in workflow
    assert "python -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache" in workflow
    assert "python -m pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75" in workflow
    assert "python -m build\n          python -m twine check dist/*" in workflow


@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped", ""])
@pytest.mark.parametrize("job", ["tests", "quality"])
def test_actual_contributor_required_check_rejects_unsuccessful_jobs(monkeypatch, result, job):
    workflow = CONTRIBUTOR_WORKFLOW_PATH.read_text(encoding="utf-8")
    gate = workflow.split("  required:\n", 1)[1]
    assert "    name: contributor-checks\n" in gate
    assert "    if: ${{ always() }}\n" in gate
    assert "    needs: [tests, quality]\n" in gate
    body = re.search(r"python - <<'PY'\n(.*?)^          PY$", gate, flags=re.MULTILINE | re.DOTALL).group(1)
    checks = compile(textwrap.dedent(body), "contributor-required-check", "exec")
    results = {name: {"result": "success"} for name in ("tests", "quality")}
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
    namespace = {"radt": radt, "config": radt.DashboardConfig()}
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
