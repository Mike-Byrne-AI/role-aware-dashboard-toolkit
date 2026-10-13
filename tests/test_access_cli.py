"""Trusted provisioning never requires real provider data in tests."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import tempfile
import warnings

import pytest

from role_aware_dashboard_toolkit import access_cli
from role_aware_dashboard_toolkit.access import Identity, principal_id
from role_aware_dashboard_toolkit.access_store import SQLiteAccessStore


@pytest.fixture
def private_directory():
    # Repository tests deliberately redirect tmp_path inside the checkout.
    # Provisioning must keep its real no-repository contract in these tests.
    # Resolve the system temp root: on macOS it sits under the /var symlink,
    # and these tests exercise provisioning, not the link policy.
    with tempfile.TemporaryDirectory(prefix="radt-access-cli-test-") as root:
        directory = Path(root).resolve(strict=True) / "private"
        directory.mkdir(mode=0o700)
        yield directory


def test_initialization_is_empty_frozen_private_and_never_overwrites(private_directory, capsys):
    args = ["init", "--directory", str(private_directory)]
    assert access_cli.main(args) == 0
    key = access_cli.read_identity_key(private_directory)
    assert len(key) == 32
    store = SQLiteAccessStore(private_directory / "access.sqlite3")
    assert store.read_freeze().frozen is True
    assert store.read_grants("a" * 64) == ()
    before = {item.name: item.read_bytes() for item in private_directory.iterdir()}
    assert access_cli.main(args) == 1
    assert before == {item.name: item.read_bytes() for item in private_directory.iterdir()}
    output = capsys.readouterr()
    assert key.hex() not in output.out + output.err
    if os.name == "posix":
        assert not (private_directory / "identity.key").stat().st_mode & 0o077


def test_subject_is_prompted_and_only_opaque_principal_persists(private_directory, monkeypatch, capsys):
    access_cli.initialize_access(private_directory)
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "synthetic-sensitive-subject")
    identity = Identity("https://issuer.example.test", "synthetic-sensitive-subject", 2000)
    principal = principal_id(identity, access_cli.read_identity_key(private_directory))
    base = ["--directory", str(private_directory), "--issuer", identity.issuer]
    assert access_cli.main(["grant", *base, "--role", "Admin", "--role", "Viewer"]) == 0
    store = SQLiteAccessStore(private_directory / "access.sqlite3")
    assert store.read_grants(principal) == ("Admin", "Viewer")
    assert access_cli.main(["grant", *base, "--role", "Viewer"]) == 0
    assert store.read_grants(principal) == ("Viewer",)
    database = (private_directory / "access.sqlite3").read_bytes()
    assert identity.subject.encode() not in database
    assert identity.issuer.encode() not in database
    assert access_cli.read_identity_key(private_directory) not in database
    assert access_cli.main(["revoke", *base]) == 0
    assert store.read_grants(principal) == ()
    output = capsys.readouterr()
    assert identity.subject not in output.out + output.err
    assert principal not in output.out + output.err


def test_opaque_principal_provisioning_does_not_prompt(private_directory, monkeypatch):
    access_cli.initialize_access(private_directory)

    def forbidden_prompt(prompt):
        raise AssertionError("Opaque provisioning must not prompt")

    monkeypatch.setattr(getpass, "getpass", forbidden_prompt)
    principal = "b" * 64
    base = ["--directory", str(private_directory), "--principal", principal]
    assert access_cli.main(["grant", *base, "--role", "Admin"]) == 0
    assert SQLiteAccessStore(private_directory / "access.sqlite3").read_grants(principal) == ("Admin",)
    assert access_cli.main(["revoke", *base]) == 0


def test_visible_input_fallback_is_refused(private_directory, monkeypatch, capsys):
    access_cli.initialize_access(private_directory)

    def unsupported_prompt(prompt):
        warnings.warn("Cannot disable echo", getpass.GetPassWarning)
        raise AssertionError("Must stop before reading visible input")

    monkeypatch.setattr(getpass, "getpass", unsupported_prompt)
    assert access_cli.main([
        "grant", "--directory", str(private_directory),
        "--issuer", "https://issuer.example.test", "--role", "Admin",
    ]) == 1
    assert "Cannot disable echo" not in capsys.readouterr().err


@pytest.mark.parametrize("key", [b"", b"a" * 31, b"a" * 4097])
def test_invalid_identity_key_fails_without_exposing_content(private_directory, key):
    path = private_directory / "identity.key"
    path.write_bytes(key)
    path.chmod(0o600)
    with pytest.raises(access_cli.ProvisioningError, match="^Provisioning failed"):
        access_cli.read_identity_key(private_directory)


def test_existing_database_does_not_get_a_new_key(private_directory):
    database = private_directory / "access.sqlite3"
    database.write_bytes(b"existing synthetic policy")
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.initialize_access(private_directory)
    assert not (private_directory / "identity.key").exists()
    assert database.read_bytes() == b"existing synthetic policy"


def test_repository_storage_is_refused(tmp_path):
    (tmp_path / ".git").mkdir()
    directory = tmp_path / "data"
    directory.mkdir(mode=0o700)
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.initialize_access(directory)
    assert not list(directory.iterdir())


def test_symlink_storage_is_refused(private_directory):
    link = private_directory.parent / "link"
    try:
        link.symlink_to(private_directory, target_is_directory=True)
    except OSError:
        pytest.skip("This host does not allow symlink creation")
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.initialize_access(link)


def test_errors_never_echo_unrecognized_arguments_or_provider_details(private_directory, monkeypatch, capsys):
    assert access_cli.main(["grant", "--subject", "synthetic-private-command-value"]) == 1
    output = capsys.readouterr()
    assert "synthetic-private-command-value" not in output.out + output.err
    access_cli.initialize_access(private_directory)

    def broken_prompt(prompt):
        raise RuntimeError("synthetic-private-provider-detail")

    monkeypatch.setattr(getpass, "getpass", broken_prompt)
    assert access_cli.main([
        "grant", "--directory", str(private_directory), "--role", "Admin",
        "--issuer", "https://issuer.example.test",
    ]) == 1
    output = capsys.readouterr()
    assert "synthetic-private-provider-detail" not in output.out + output.err


@pytest.mark.parametrize("principal", ["Admin", "synthetic@example.test", "A" * 64, "a" * 63])
def test_invalid_principal_does_not_create_grants(private_directory, principal):
    access_cli.initialize_access(private_directory)
    assert access_cli.main([
        "grant", "--directory", str(private_directory), "--principal", principal, "--role", "Admin",
    ]) == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission contract")
def test_broad_posix_permissions_are_refused(private_directory):
    access_cli.initialize_access(private_directory)
    key = private_directory / "identity.key"
    key.chmod(0o644)
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.read_identity_key(private_directory)
    key.chmod(0o600)
    private_directory.chmod(0o755)
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.read_identity_key(private_directory)


def test_partial_creation_does_not_overwrite_on_retry(private_directory, monkeypatch):
    def failed_create(path):
        raise OSError("synthetic private path")

    monkeypatch.setattr(SQLiteAccessStore, "create", failed_create)
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.initialize_access(private_directory)
    original = (private_directory / "identity.key").read_bytes()
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.initialize_access(private_directory)
    assert (private_directory / "identity.key").read_bytes() == original


def test_module_is_quiet_and_imports_no_optional_hosts(tmp_path):
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-c", "import sys; import role_aware_dashboard_toolkit.access_cli; "
         "assert 'streamlit' not in sys.modules; assert 'authlib' not in sys.modules"],
        cwd=tmp_path, env={**os.environ, "PYTHONPATH": str(root)}, capture_output=True,
        text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
    assert not list(tmp_path.iterdir())
