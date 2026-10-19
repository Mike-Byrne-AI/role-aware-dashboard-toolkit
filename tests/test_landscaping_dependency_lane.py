"""Execute the workflow's installation branches without network or real installs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import textwrap

import pytest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/dependency-audit.yml"
pytestmark = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="The dependency audit's Ubuntu installation step requires POSIX bash.",
)


def _installation_script() -> str:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    step = workflow.split("      - name: Install isolated runtime and audit tool\n", 1)[1]
    return textwrap.dedent(step.split("        run: |\n", 1)[1].split("      - name:", 1)[0])


def _run_installation(tmp_path, lane, *, wheel_count=1, fail=""):
    runner = tmp_path / "runner with spaces"
    distributions = runner / "audit-dist"
    distributions.mkdir(parents=True)
    wheels = [distributions / f"toolkit-{index}.whl" for index in range(wheel_count)]
    for wheel in wheels:
        wheel.touch()
    commands = tmp_path / "commands.jsonl"
    binaries = tmp_path / "bin"
    binaries.mkdir()
    python = binaries / "python"
    python.write_text(
        f"#!{sys.executable}\n" + textwrap.dedent("""\
        import json
        import os
        from pathlib import Path
        import sys

        executable = Path(__file__)
        lane = executable.parent.parent.name if executable.parent.name == "bin" else "builder"
        arguments = sys.argv[1:]
        with Path(os.environ["COMMAND_LOG"]).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"executable": str(executable), "arguments": arguments}) + "\\n")
        if arguments[:2] == ["-m", "venv"]:
            target = Path(arguments[2]) / "bin" / "python"
            target.parent.mkdir(parents=True)
            target.write_text(executable.read_text(encoding="utf-8"), encoding="utf-8")
            target.chmod(0o700)
        elif arguments[:2] == ["-m", "pip"]:
            if os.environ.get("FAIL_OPERATION") == lane + ":" + arguments[2]:
                raise SystemExit(7)
        else:
            raise SystemExit("Unexpected command in workflow installation step")
        """),
        encoding="utf-8",
    )
    python.chmod(0o700)
    env = {
        **os.environ,
        "PATH": str(binaries) + os.pathsep + os.defpath,
        "RUNNER_TEMP": str(runner),
        "AUDIT_EXTRA": lane,
        "COMMAND_LOG": str(commands),
        "FAIL_OPERATION": fail,
    }
    result = subprocess.run(
        [shutil.which("bash"), "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", _installation_script()],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    logged = [json.loads(line) for line in commands.read_text(encoding="utf-8").splitlines()]
    return result, logged, runner, wheels


@pytest.mark.parametrize("lane", ["api", "full", "landscaping", "business"])
def test_actual_dependency_lane_installs_only_its_runtime_and_separate_scanner(tmp_path, lane):
    workflow = WORKFLOW.read_text(encoding="utf-8")
    matrix = re.search(r"^        extra: \[([^\]]+)\]$", workflow, flags=re.MULTILINE)
    assert matrix is not None
    assert [value.strip() for value in matrix.group(1).split(",")] == ["api", "full", "landscaping", "business"]
    result, commands, runner, wheels = _run_installation(tmp_path, lane)
    assert result.returncode == 0, result.stderr
    selected_extra = "api" if lane in {"landscaping", "business"} else lane
    runtime_install = ["-m", "pip", "install", f"{wheels[0]}[{selected_extra}]"]
    if lane == "landscaping":
        runtime_install.extend(["-r", "examples/landscaping/requirements.txt"])
    elif lane == "business":
        runtime_install.extend(["-r", "examples/business_dashboard/requirements.txt"])
    assert commands[0]["arguments"] == ["-m", "venv", str(runner / "audit-runtime")]
    assert commands[1]["arguments"] == ["-m", "venv", str(runner / "audit-tool")]
    assert commands[2:] == [
        {"executable": str(runner / "audit-runtime/bin/python"), "arguments": runtime_install},
        {"executable": str(runner / "audit-runtime/bin/python"), "arguments": ["-m", "pip", "check"]},
        {"executable": str(runner / "audit-tool/bin/python"), "arguments": ["-m", "pip", "install", "pip-audit==2.10.1"]},
        {"executable": str(runner / "audit-tool/bin/python"), "arguments": ["-m", "pip", "check"]},
    ]


@pytest.mark.parametrize("lane,wheel_count", [
    ("unknown", 1), ("landscaping", 0), ("landscaping", 2), ("business", 0), ("business", 2),
])
def test_actual_dependency_lane_refuses_unknown_scope_or_ambiguous_artifact(tmp_path, lane, wheel_count):
    result, commands, _runner, _wheels = _run_installation(tmp_path, lane, wheel_count=wheel_count)
    assert result.returncode != 0
    assert all(command["arguments"][:2] == ["-m", "venv"] for command in commands)


@pytest.mark.parametrize(
    "failure,expected_commands",
    [("audit-runtime:install", 3), ("audit-runtime:check", 4), ("audit-tool:install", 5), ("audit-tool:check", 6)],
)
@pytest.mark.parametrize("lane", ["landscaping", "business"])
def test_actual_dependency_lane_stops_on_installation_or_consistency_failure(tmp_path, failure, expected_commands, lane):
    result, commands, _runner, _wheels = _run_installation(tmp_path, lane, fail=failure)
    assert result.returncode == 7
    assert len(commands) == expected_commands
