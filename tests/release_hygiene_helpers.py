import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 CI
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]
DEMOTED_CI_ROOT_SYMBOLS = (
    "audit_release_artifact_members",
    "create_codex_builder_plugin",
    "create_harness_plugin",
    "create_repoos_plugin",
    "build_pack_scaffold_spec",
    "build_install_target",
)


def load_pre_release_check_module():
    script = REPO_ROOT / "tools" / "pre_release_check.py"
    spec = importlib.util.spec_from_file_location("pre_release_check_under_test", script)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def read_ci_workflow() -> str:
    return (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def extract_python_matrix_versions(workflow: str) -> list[str]:
    lines = workflow.splitlines()
    for index, line in enumerate(lines):
        if "python-version:" not in line:
            continue
        _prefix, body = line.split("python-version:", 1)
        body = body.strip()
        if body.startswith("["):
            while "]" not in body and index + 1 < len(lines):
                index += 1
                body += " " + lines[index].strip()
            return re.findall(r'["\']([^"\']+)["\']', body)
        if body:
            return [body.strip().strip('"\'')]

        versions: list[str] = []
        cursor = index + 1
        base_indent = indent_width(line)
        while cursor < len(lines):
            candidate = lines[cursor]
            if candidate.strip() and indent_width(candidate) <= base_indent:
                break
            stripped = candidate.strip()
            if stripped.startswith("-"):
                versions.append(stripped.lstrip("-").strip().strip('"\''))
            cursor += 1
        return [version for version in versions if version]
    return []


def extract_permissions_blocks(workflow: str) -> list[tuple[int, dict[str, str]]]:
    lines = workflow.splitlines()
    blocks: list[tuple[int, dict[str, str]]] = []
    for index, line in enumerate(lines):
        if line.strip() != "permissions:":
            continue
        base_indent = indent_width(line)
        permissions: dict[str, str] = {}
        cursor = index + 1
        while cursor < len(lines):
            candidate = lines[cursor]
            if candidate.strip() and indent_width(candidate) <= base_indent:
                break
            if ":" in candidate:
                key, value = candidate.strip().split(":", 1)
                permissions[key.strip()] = value.strip()
            cursor += 1
        blocks.append((base_indent, permissions))
    return blocks


def extract_top_level_permissions(workflow: str) -> dict[str, str]:
    for indent, permissions in extract_permissions_blocks(workflow):
        if indent == 0:
            return permissions
    return {}


def load_pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def read_json_text(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def built_release_artifacts(tmp_path_factory):
    artifact_dir = tmp_path_factory.mktemp("release-artifacts")
    base_build_args = [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(artifact_dir), str(REPO_ROOT)]
    build_result = subprocess.run(
        base_build_args,
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    build_mode = "isolated"
    isolated_build_error = ""
    if build_result.returncode != 0:
        isolated_build_error = build_result.stderr
        build_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--sdist",
                "--no-isolation",
                "--outdir",
                str(artifact_dir),
                str(REPO_ROOT),
            ],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        build_mode = "no-isolation-diagnostic"
    assert build_result.returncode == 0, build_result.stderr
    wheels = sorted(artifact_dir.glob("role_aware_dashboard_toolkit-*.whl"))
    sdists = sorted(artifact_dir.glob("role_aware_dashboard_toolkit-*.tar.gz"))
    assert len(wheels) == 1
    assert len(sdists) == 1
    return {
        "dist_dir": artifact_dir,
        "wheel": wheels[0],
        "sdist": sdists[0],
        "build_mode": build_mode,
        "isolated_build_error": isolated_build_error,
    }


__all__ = [
    "DEMOTED_CI_ROOT_SYMBOLS",
    "REPO_ROOT",
    "built_release_artifacts",
    "extract_permissions_blocks",
    "extract_python_matrix_versions",
    "extract_top_level_permissions",
    "load_pre_release_check_module",
    "load_pyproject",
    "read_ci_workflow",
    "read_json_text",
    "tomllib",
]
