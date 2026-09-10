"""Installed command contracts, offline resources and explicit scaffold boundaries."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from role_aware_dashboard_toolkit import __version__
from role_aware_dashboard_toolkit import cli
from role_aware_dashboard_toolkit.guidance import list_guide_topics, read_guide, read_starter

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "role_aware_dashboard_toolkit"
EXPECTED_FILES = {"app.py", ".streamlit/config.toml", "AGENTS.md", "README.md"}


def _command(*arguments, cwd, import_root=ROOT, no_site=False):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(import_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    command = [sys.executable, "-B", *( ["-S"] if no_site else []),
               "-m", "role_aware_dashboard_toolkit", *arguments, "--format", "json"]
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True,
                            encoding="utf-8", check=False)
    assert result.stderr == "", result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["toolkit_version"] == __version__
    assert payload["ok"] is (result.returncode == 0)
    return result.returncode, payload


def test_catalog_and_every_topic_are_available_from_unrelated_directory(tmp_path):
    code, catalog = _command("guide", cwd=tmp_path)
    assert code == 0
    topics = catalog["result"]["topics"]
    assert [item["id"] for item in topics] == [
        "start", "controls", "appearance", "sections", "plugins", "permissions",
        "profiles", "runs", "telemetry", "api", "troubleshooting",
    ]
    for item in topics:
        code, response = _command("guide", item["id"], cwd=tmp_path)
        assert code == 0
        assert response["result"] == read_guide(item["id"])
        assert response["result"]["content"].strip()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("arguments,code", [
    (("guide", "../../version.py"), "UNKNOWN_GUIDE"),
    (("guide", "missing"), "UNKNOWN_GUIDE"),
    (("example", "../../version.py"), "UNKNOWN_EXAMPLE"),
    (("example", "starter", "--file", "../version.py"), "UNKNOWN_EXAMPLE_FILE"),
    (("inspect", "--unknown-option"), "USAGE_ERROR"),
    (("unknown-command",), "USAGE_ERROR"),
    (("init",), "USAGE_ERROR"),
])
def test_invalid_commands_return_one_json_error_without_writes(tmp_path, arguments, code):
    status, payload = _command(*arguments, cwd=tmp_path)
    assert status == 2
    assert payload["error"]["code"] == code
    assert payload["error"]["message"]
    assert list(tmp_path.iterdir()) == []


def test_json_help_is_json_even_before_or_after_subcommand(tmp_path):
    for args in [("--help",), ("guide", "--help"), ("--format=json", "inspect", "--help")]:
        status, result = _command(*args, cwd=tmp_path)
        assert status == 0
        assert "python -m role_aware_dashboard_toolkit" in result["result"]["help"]


def test_example_contains_the_exact_project_files(tmp_path):
    status, result = _command("example", "starter", cwd=tmp_path)
    assert status == 0
    files = result["result"]["files"]
    assert set(files) == EXPECTED_FILES
    assert files == read_starter()
    status, selected = _command("example", "starter", "--file", "app.py", cwd=tmp_path)
    assert status == 0
    assert selected["result"]["content"] == files["app.py"]
    assert not list(tmp_path.iterdir())


def test_init_dry_run_and_creation_match_readonly_example(tmp_path):
    destination = tmp_path / "New dashboard"
    status, preview = _command("init", str(destination), "--dry-run", cwd=tmp_path)
    assert status == 0
    assert preview["result"]["dry_run"] is True
    assert set(preview["result"]["files"]) == EXPECTED_FILES
    assert preview["result"]["created_files"] == []
    assert not destination.exists()
    status, created = _command("init", str(destination), cwd=tmp_path)
    assert status == 0
    assert set(created["result"]["created_files"]) == EXPECTED_FILES
    for name, source in read_starter().items():
        assert (destination / name).read_bytes() == source.encode("utf-8")
    before = {item.relative_to(destination).as_posix(): item.read_bytes()
              for item in destination.rglob("*") if item.is_file()}
    status, refused = _command("init", str(destination), cwd=tmp_path)
    assert status == 2
    assert refused["error"]["code"] == "DESTINATION_EXISTS"
    assert before == {item.relative_to(destination).as_posix(): item.read_bytes()
                      for item in destination.rglob("*") if item.is_file()}


@pytest.mark.parametrize("kind", ["empty_directory", "project", "file"])
def test_existing_destinations_are_preserved_even_for_dry_run(tmp_path, kind):
    target = tmp_path / "keep"
    if kind == "file":
        target.write_text("existing content", encoding="utf-8")
    else:
        target.mkdir()
        if kind == "project":
            (target / "AGENTS.md").write_text("existing project authority", encoding="utf-8")
    for dry_run in [(), ("--dry-run",)]:
        status, response = _command("init", str(target), *dry_run, cwd=tmp_path)
        assert status == 2
        assert response["error"]["code"] == "DESTINATION_EXISTS"
    if kind == "file":
        assert target.read_text() == "existing content"
    elif kind == "project":
        assert (target / "AGENTS.md").read_text() == "existing project authority"
        assert len(list(target.iterdir())) == 1
    else:
        assert not list(target.iterdir())


def test_init_rejects_traversal_missing_parent_and_nonprintable_paths(tmp_path):
    for value, expected in [(str(tmp_path / ".." / "escape"), "INVALID_DESTINATION"),
                            (str(tmp_path / "missing" / "child"), "MISSING_PARENT"),
                            ("bad\nname", "INVALID_DESTINATION")]:
        status, response = _command("init", value, cwd=tmp_path)
        assert status == 2
        assert response["error"]["code"] == expected
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("use_parent", [False, True])
def test_init_refuses_symlink_destinations_and_parents(tmp_path, use_parent):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"This host cannot create the test symlink: {type(exc).__name__}")
    destination = link / "new" if use_parent else link
    status, response = _command("init", str(destination), cwd=tmp_path)
    assert status == 2
    assert response["error"]["code"] == "UNSAFE_DESTINATION"
    assert not list(real.iterdir())


def test_init_failure_reports_created_files_without_claiming_atomicity(tmp_path, monkeypatch, capsys):
    destination = tmp_path / "partial"
    original_open = Path.open

    def fail_second_file(path, *args, **kwargs):
        if path == destination / ".streamlit" / "config.toml" and args and args[0] == "x":
            raise PermissionError("private path should not be copied into the error")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_second_file)
    status = cli.main(["init", str(destination), "--format", "json"])
    response = json.loads(capsys.readouterr().out)
    assert status == 1
    assert response["error"]["code"] == "INIT_FAILED"
    assert response["error"]["destination_created"] is True
    assert response["error"]["created_files"] == ["app.py"]
    assert (destination / "app.py").exists()
    assert not (destination / "AGENTS.md").exists()
    assert "private path" not in response["error"]["message"]


def test_core_only_zip_resources_inspection_and_imports_have_no_side_effects(tmp_path):
    bundle = tmp_path / "package.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        for path in PACKAGE.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                archive.write(path, path.relative_to(ROOT).as_posix())
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    for args in [("guide", "start"), ("inspect",), ("example", "starter")]:
        status, response = _command(*args, cwd=consumer, import_root=bundle, no_site=True)
        assert status == 0
        if args[0] == "inspect":
            result = response["result"]
            assert result["control_kinds"] == ["slider", "toggle", "number", "select", "text", "color"]
            assert len(result["section_defaults"]) == 14
            assert "ControlRegistry.unregister" in result["signatures"]
            assert all(not item["installed"] and not item["compatibility_tested"]
                       for item in result["optional_dependencies"].values())
    env = {**os.environ, "PYTHONPATH": str(bundle), "PYTHONDONTWRITEBYTECODE": "1"}
    code = "import sys; import role_aware_dashboard_toolkit; import role_aware_dashboard_toolkit.guidance; import role_aware_dashboard_toolkit.cli; assert not any(name in sys.modules for name in ('streamlit', 'fastapi', 'pandas', 'pydantic'))"
    result = subprocess.run([sys.executable, "-B", "-S", "-c", code], cwd=consumer,
                            env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
    assert list(consumer.iterdir()) == []


def test_module_helpers_do_not_expand_root_exports():
    import role_aware_dashboard_toolkit as radt
    assert "read_guide" not in radt.__all__
    assert {topic["id"] for topic in list_guide_topics()} == {
        "start", "controls", "appearance", "sections", "plugins", "permissions",
        "profiles", "runs", "telemetry", "api", "troubleshooting",
    }


def test_text_commands_identify_version_and_keep_raw_python_valid_under_ascii_environment(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONIOENCODING": "ascii"}
    destination = tmp_path / "\u65b0\u5efa-dashboard"
    for args in [("guide", "start"), ("inspect",), ("example", "starter"),
                 ("example", "starter", "--file", "app.py"),
                 ("init", str(destination), "--dry-run")]:
        result = subprocess.run([sys.executable, "-B", "-m", "role_aware_dashboard_toolkit",
                                 *args, "--format", "text"], cwd=tmp_path, env=env,
                                capture_output=True, text=True, encoding="utf-8", check=False)
        assert result.returncode == 0, result.stderr
        assert result.stderr == ""
        assert f"Role-Aware Dashboard Toolkit {__version__}" in result.stdout
        if "--file" in args:
            compile(result.stdout, "printed_starter.py", "exec")
        if args[0] == "init":
            assert str(destination) in result.stdout
    assert not destination.exists()
