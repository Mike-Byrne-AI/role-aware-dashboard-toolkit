"""Trusted provisioning never requires real provider data in tests."""

from __future__ import annotations

import getpass
import os
from pathlib import Path
import stat
import sys
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


_ARGUMENT_MESSAGE = "Provisioning failed: invalid or incomplete command-line arguments"


@pytest.mark.parametrize("argv", [
    ["grant", "--directory", "{directory}", "--principal", "b" * 64, "--role", "synthetic-private-typo"],
    ["grant", "--directory", "{directory}", "--principal", "b" * 64],
    ["grant", "--directory", "{directory}", "--role", "Admin"],
    ["init"],
    ["grant", "--subject", "synthetic-private-typo"],
])
def test_argument_errors_have_their_own_message_and_change_nothing(private_directory, capsys, argv):
    access_cli.initialize_access(private_directory)
    store = SQLiteAccessStore(private_directory / "access.sqlite3")
    store.replace_grants("b" * 64, ("Viewer",))
    capsys.readouterr()
    argv = [value.replace("{directory}", str(private_directory)) for value in argv]
    assert access_cli.main(argv) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith(_ARGUMENT_MESSAGE)
    assert "--help" in output.err
    assert "protected directory" not in output.err
    assert "synthetic-private-typo" not in output.err
    assert store.read_grants("b" * 64) == ("Viewer",)


def _symlink_or_skip(link, target):
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("This host does not allow symlink creation")


def _skip_as_root():
    if os.name == "posix" and os.geteuid() == 0:
        pytest.skip("Root-owned links in root-only directories are trusted")


@pytest.mark.parametrize("where", ["directory", "ancestor"])
def test_untrusted_link_is_refused_and_named(private_directory, capsys, where):
    _skip_as_root()
    base = private_directory.parent
    link = base / ("link" if where == "directory" else "alias")
    _symlink_or_skip(link, private_directory if where == "directory" else base)
    requested = link if where == "directory" else link / "private"
    assert access_cli.main(["init", "--directory", str(requested)]) == 1
    output = capsys.readouterr()
    assert output.err.startswith("Provisioning failed:")
    assert str(link) in output.err
    assert "symbolic link" in output.err
    assert not (private_directory / "identity.key").exists()
    with pytest.raises(access_cli.ProvisioningError, match="symbolic link"):
        access_cli.read_identity_key(requested)


@pytest.mark.parametrize("problem,message", [
    ("missing", "must already exist"),
    ("repository", "inside a Git repository"),
    ("permissions", "group or other access"),
    ("initialized", "already contains"),
])
def test_directory_refusals_name_their_cause(private_directory, capsys, problem, message):
    requested = private_directory
    if problem == "missing":
        requested = private_directory / "absent"
    elif problem == "repository":
        (private_directory / ".git").mkdir()
        requested = private_directory / "data"
        requested.mkdir(mode=0o700)
    elif problem == "permissions":
        if os.name != "posix":
            pytest.skip("POSIX permission contract")
        private_directory.chmod(0o750)
    elif problem == "initialized":
        access_cli.initialize_access(private_directory)
        capsys.readouterr()
    assert access_cli.main(["init", "--directory", str(requested)]) == 1
    output = capsys.readouterr()
    assert output.err.startswith("Provisioning failed:")
    assert message in output.err
    assert str(requested) not in output.err


def _system_link_root():
    """Return the unresolved temp root when a root-owned system link precedes it."""
    root = Path(tempfile.gettempdir()).absolute()
    if os.name != "posix" or sys.platform != "darwin" or root.resolve() == root:
        return None
    system_link = Path("/", root.parts[1])
    info, top = os.lstat(system_link), os.lstat("/")
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or top.st_uid != 0 or top.st_mode & 0o022:
        return None
    return root


def test_root_owned_system_link_such_as_macos_var_is_accepted():
    root = _system_link_root()
    if root is None:
        pytest.skip("Needs the system temp root under a root-owned link (macOS /var)")
    with tempfile.TemporaryDirectory(prefix="radt-access-cli-system-", dir=root) as raw:
        directory = Path(raw) / "private"
        directory.mkdir(mode=0o700)
        assert directory.resolve() != directory
        assert access_cli.main(["init", "--directory", str(directory)]) == 0
        assert len(access_cli.read_identity_key(directory)) == 32
        assert (directory.resolve() / "access.sqlite3").is_file()


@pytest.fixture
def simulated_ownership(monkeypatch):
    """Report chosen paths as root-owned with chosen modes; everything else is real."""
    if os.name != "posix":
        pytest.skip("Root-owned link trust applies only to POSIX")
    _skip_as_root()
    real_lstat = os.lstat
    overrides = {}

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) not in overrides:
            return info
        uid, mode = overrides[os.fspath(path)]
        values = list(info)
        values[stat.ST_UID] = uid
        if mode is not None:
            values[stat.ST_MODE] = stat.S_IFMT(info.st_mode) | mode
        return os.stat_result(values)

    monkeypatch.setattr(os, "lstat", lstat)
    return overrides


def _system_layout(private_directory, overrides, *, target):
    """Create base/system/alias -> target and mark system and its ancestors root-only."""
    base = private_directory.parent
    system = base / "system"
    system.mkdir()
    link = system / "alias"
    _symlink_or_skip(link, target)
    for directory in (system, *system.parents):
        overrides[os.fspath(directory)] = (0, 0o755)
    overrides[os.fspath(link)] = (0, None)
    return base, system, link


@pytest.mark.parametrize("problem", [None, "user_link", "group_writable_parent", "user_owned_parent", "writable_ancestor", "sticky_ancestor"])
def test_root_owned_link_is_trusted_only_when_only_root_can_change_it(private_directory, simulated_ownership, capsys, problem):
    base, system, link = _system_layout(private_directory, simulated_ownership, target=private_directory.parent)
    if problem == "user_link":
        del simulated_ownership[os.fspath(link)]
    elif problem == "group_writable_parent":
        simulated_ownership[os.fspath(system)] = (0, 0o775)
    elif problem == "user_owned_parent":
        simulated_ownership[os.fspath(system)] = (os.getuid(), 0o755)
    elif problem == "writable_ancestor":
        simulated_ownership[os.fspath(base)] = (0, 0o777)
    elif problem == "sticky_ancestor":
        simulated_ownership[os.fspath(base)] = (0, 0o1777)
    requested = link / "private"
    status = access_cli.main(["init", "--directory", str(requested)])
    output = capsys.readouterr()
    if problem is None:
        assert status == 0, output.err
        assert (private_directory / "identity.key").is_file()
        assert len(access_cli.read_identity_key(requested)) == 32
    else:
        assert status == 1
        assert str(link) in output.err
        assert not (private_directory / "identity.key").exists()


def test_trusted_link_into_a_repository_is_refused(private_directory, simulated_ownership, capsys):
    checkout = private_directory.parent / "checkout"
    (checkout / ".git").mkdir(parents=True)
    data = checkout / "data"
    data.mkdir(mode=0o700)
    _base, _system, link = _system_layout(private_directory, simulated_ownership, target=data)
    assert not any((parent / ".git").exists() for parent in (link.parent, *link.parent.parents))
    assert access_cli.main(["init", "--directory", str(link)]) == 1
    assert "inside a Git repository" in capsys.readouterr().err
    assert not (data / "identity.key").exists()


def test_untrusted_link_inside_a_trusted_link_target_is_refused(private_directory, simulated_ownership, capsys):
    base = private_directory.parent
    hop = base / "hop"
    _symlink_or_skip(hop, private_directory)
    _base, _system, link = _system_layout(private_directory, simulated_ownership, target=base)
    assert access_cli.main(["init", "--directory", str(link / "hop")]) == 1
    output = capsys.readouterr()
    assert str(hop) in output.err
    assert str(link) not in output.err
    assert not (private_directory / "identity.key").exists()
