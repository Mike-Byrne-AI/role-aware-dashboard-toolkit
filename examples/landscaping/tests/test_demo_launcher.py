"""The source demo never seeds on import or stores credentials in a checkout."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from .conftest import EXAMPLE_ROOT


def test_import_is_inert_even_when_environment_points_at_uninitialized_storage(tmp_path):
    data_dir = tmp_path / "must-not-exist"
    result = subprocess.run(
        [sys.executable, "-c", "import landscape.app, landscape.launcher; assert not hasattr(landscape.app, 'app')"],
        cwd=tmp_path,
        env=dict(os.environ, PYTHONPATH=str(EXAMPLE_ROOT), PYTHONDONTWRITEBYTECODE="1", LANDSCAPE_DATA_DIR=str(data_dir)),
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert not data_dir.exists()
    assert result.stdout == ""


@pytest.mark.parametrize("already_empty", [False, True])
def test_first_launch_creates_six_private_accounts_without_printing_passwords(tmp_path, capsys, already_empty):
    from landscape.launcher import prepare_demo

    directory = tmp_path / "private"
    if already_empty:
        directory.mkdir(mode=0o700)
    database, seeded = prepare_demo(directory)
    assert seeded is True
    with database.transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 6
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 12
        assert connection.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 10
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for name in ("identity.key", "landscape.sqlite3", "TRIAL_ACCOUNTS.md"):
        assert stat.S_IMODE((directory / name).stat().st_mode) == 0o600
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("remove_handoff", [False, True])
def test_restart_preserves_accounts_saved_work_and_missing_handoff(tmp_path, seeded_template, remove_handoff):
    from landscape.db import Database
    from landscape.launcher import prepare_demo

    template, _ = seeded_template
    directory = tmp_path / "private"
    shutil.copytree(template, directory)
    database = Database(directory)
    with database.transaction() as connection:
        connection.execute("UPDATE settings SET frozen=1, freeze_revision=9")
        connection.execute("UPDATE users SET active=0 WHERE username='ellis'")
        connection.execute("UPDATE customers SET notes='Keep this saved customer note'")
        before = tuple(connection.iterdump())
    key = (directory / "identity.key").read_bytes()
    sheet = directory / "TRIAL_ACCOUNTS.md"
    original_sheet = sheet.read_bytes()
    if remove_handoff:
        sheet.unlink()
    database, seeded = prepare_demo(directory)
    assert seeded is False
    with database.transaction() as connection:
        assert tuple(connection.iterdump()) == before
    assert (directory / "identity.key").read_bytes() == key
    if remove_handoff:
        assert not sheet.exists()
    else:
        assert sheet.read_bytes() == original_sheet


def test_existing_nonempty_directory_is_never_adopted_or_seeded(tmp_path):
    from landscape.launcher import prepare_demo

    directory = tmp_path / "private"
    directory.mkdir()
    marker = directory / "keep.txt"
    marker.write_text("Existing unrelated data")
    with pytest.raises(ValueError, match="incomplete"):
        prepare_demo(directory)
    assert tuple(directory.iterdir()) == (marker,)
    assert marker.read_text() == "Existing unrelated data"


def test_existing_database_without_accounts_is_never_reseeded(tmp_path):
    from landscape.db import Database
    from landscape.launcher import prepare_demo

    directory = tmp_path / "private"
    database = Database(directory)
    with database.transaction() as connection:
        connection.execute("UPDATE settings SET frozen=1, freeze_revision=4")
        before = tuple(connection.iterdump())
    key = (directory / "identity.key").read_bytes()
    with pytest.raises(ValueError, match="refusing to reseed"):
        prepare_demo(directory)
    with database.transaction() as connection:
        assert tuple(connection.iterdump()) == before
    assert (directory / "identity.key").read_bytes() == key
    assert not (directory / "TRIAL_ACCOUNTS.md").exists()


@pytest.mark.parametrize("kind", ["direct", "normalized", "outside_alias", "inside_alias", "final_symlink"])
def test_storage_rejects_source_paths_and_symlink_aliases_before_writes(tmp_path, monkeypatch, kind):
    from landscape import paths
    from landscape.db import Database

    source = tmp_path / "checkout"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(paths, "SOURCE_ROOTS", frozenset({source}))
    if kind == "direct":
        requested = source / "private"
    elif kind == "normalized":
        requested = outside / ".." / "checkout" / "private"
    elif kind == "outside_alias":
        alias = outside / "source-link"
        alias.symlink_to(source, target_is_directory=True)
        requested = alias / "private"
    elif kind == "inside_alias":
        alias = source / "outside-link"
        alias.symlink_to(outside, target_is_directory=True)
        requested = alias / "private"
    else:
        requested = tmp_path / "data-link"
        requested.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="outside|symbolic link"):
        Database(requested)
    assert not (source / "private").exists()
    assert not (outside / "private").exists()
    assert not (outside / "landscape.sqlite3").exists()


def test_factory_uses_explicit_storage_without_automatically_seeding(tmp_path, monkeypatch):
    from landscape.app import create_default_app

    data_dir = tmp_path / "private"
    monkeypatch.setenv("LANDSCAPE_DATA_DIR", str(data_dir))
    app = create_default_app()
    assert Path(app.state.db_path) == data_dir / "landscape.sqlite3"
    assert not (data_dir / "TRIAL_ACCOUNTS.md").exists()


@pytest.fixture
def browser_runner():
    spec = importlib.util.spec_from_file_location("landscaping_browser_check", EXAMPLE_ROOT / "scripts" / "browser_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_browser_evidence_rejects_checkout_aliases_and_nonempty_directories(tmp_path, monkeypatch, browser_runner):
    source = tmp_path / "checkout"
    source.mkdir()
    monkeypatch.setattr(browser_runner, "CHECKOUT_ROOT", source)
    alias = tmp_path / "source-alias"
    alias.symlink_to(source, target_is_directory=True)
    for requested in (source / "out", alias / "out"):
        with pytest.raises(ValueError, match="outside"):
            browser_runner.evidence_directory(str(requested))
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "keep.txt").write_text("Previous proof")
    with pytest.raises(ValueError, match="empty"):
        browser_runner.evidence_directory(str(existing))
    assert (existing / "keep.txt").read_text() == "Previous proof"
    output = browser_runner.evidence_directory(str(tmp_path / "new-proof"))
    assert output.is_dir() and not tuple(output.iterdir())


@pytest.mark.parametrize("missing_file", ["identity.key", "landscape.sqlite3"])
def test_restart_refuses_incomplete_storage_without_replacing_files(tmp_path, seeded_template, missing_file):
    from landscape.launcher import prepare_demo

    template, _ = seeded_template
    directory = tmp_path / "private"
    shutil.copytree(template, directory)
    missing_path = directory / missing_file
    missing_path.unlink()
    before = {file.name: file.read_bytes() for file in directory.iterdir() if file.is_file()}
    with pytest.raises(ValueError, match="incomplete"):
        prepare_demo(directory)
    assert not missing_path.exists()
    assert {file.name: file.read_bytes() for file in directory.iterdir() if file.is_file()} == before
