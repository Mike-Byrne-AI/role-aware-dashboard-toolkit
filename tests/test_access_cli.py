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
    _skip_as_root()
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

    real_stat = os.stat

    def simulated(info, key):
        if key not in overrides:
            return info
        uid, mode = overrides[key]
        values = list(info)
        values[stat.ST_UID] = uid
        if mode is not None:
            values[stat.ST_MODE] = stat.S_IFMT(info.st_mode) | mode
        return os.stat_result(values)

    def lstat(path, *args, **kwargs):
        return simulated(real_lstat(path, *args, **kwargs), os.fspath(path))

    def stat_(path, *args, **kwargs):
        return simulated(real_stat(path, *args, **kwargs), os.fspath(path) if isinstance(path, (str, os.PathLike)) else None)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "stat", stat_)
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


@pytest.mark.parametrize("target", ["relative", "dotted", "chained"])
def test_trusted_links_resolve_like_the_kernel(private_directory, simulated_ownership, target):
    base = private_directory.parent
    if target == "relative":
        link_target = Path("..") / "private"
    elif target == "dotted":
        link_target = Path("..") / "system" / ".." / "private"
    else:
        # An absolute target that passes through a second trusted link.
        link_target = base / "system" / "inner"
    _base, system, link = _system_layout(private_directory, simulated_ownership, target=link_target)
    if target == "chained":
        inner = system / "inner"
        _symlink_or_skip(inner, private_directory)
        simulated_ownership[os.fspath(inner)] = (0, None)
    assert access_cli._ordinary_path(link) == Path(os.path.realpath(link)) == private_directory
    assert access_cli.main(["init", "--directory", str(link)]) == 0
    assert (private_directory / "identity.key").is_file()


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows resolves '..' in text before the file system sees the path, so "
           "'regular\\..\\private' opens 'private' there; accepting it matches the kernel",
)
def test_path_through_a_file_is_refused_like_the_kernel(private_directory, capsys):
    regular = private_directory.parent / "regular"
    regular.write_text("not a directory", encoding="utf-8")
    requested = Path(f"{regular}{os.sep}..{os.sep}private")
    assert access_cli.main(["init", "--directory", str(requested)]) == 1
    assert capsys.readouterr().err.startswith("Provisioning failed")
    assert not (private_directory / "identity.key").exists()


@pytest.mark.parametrize("owner", ["caller", "root", "other"])
def test_protected_directory_must_belong_to_the_caller_or_root(private_directory, simulated_ownership, capsys, owner):
    if owner != "caller":
        uid = 0 if owner == "root" else os.geteuid() + 1
        simulated_ownership[os.fspath(private_directory)] = (uid, None)
    status = access_cli.main(["init", "--directory", str(private_directory)])
    output = capsys.readouterr()
    if owner == "other":
        assert status == 1
        assert "belongs to another account" in output.err
        assert not (private_directory / "identity.key").exists()
    else:
        assert status == 0, output.err


def test_identity_key_owned_by_another_account_is_refused(private_directory, simulated_ownership):
    access_cli.initialize_access(private_directory)
    assert len(access_cli.read_identity_key(private_directory)) == 32
    simulated_ownership[os.fspath(private_directory / "identity.key")] = (os.geteuid() + 1, None)
    with pytest.raises(access_cli.ProvisioningError, match="identity.key"):
        access_cli.read_identity_key(private_directory)


def test_walk_and_kernel_disagreement_is_refused(private_directory, monkeypatch):
    # Stands in for a component swapped between the walk and its use.
    decoy = private_directory.parent / "decoy"
    decoy.mkdir(mode=0o700)
    monkeypatch.setattr(access_cli, "_ordinary_path", lambda path: decoy)
    with pytest.raises(access_cli.ProvisioningError):
        access_cli.initialize_access(private_directory)
    assert not (decoy / "identity.key").exists()
    assert not (private_directory / "identity.key").exists()


# Every directory above the protected directory follows OpenSSH's rule: it
# belongs to the caller or root, and only a root-owned sticky directory (such
# as /tmp) may be group- or world-writable. Otherwise another account could
# rename the protected directory away and put its own in its place.

def _writable_parent(private_directory, mode):
    shared = private_directory.parent / "shared"
    shared.mkdir()
    shared.chmod(mode)
    protected = shared / "protected"
    protected.mkdir(mode=0o700)
    return shared, protected


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership contract")
@pytest.mark.parametrize("mode", [0o777, 0o775, 0o757, 0o1777])
def test_a_parent_another_account_could_change_is_refused_and_named(private_directory, capsys, mode):
    # A caller-owned parent is writable by others whatever its sticky bit:
    # only root's sticky directories are trusted.
    shared, protected = _writable_parent(private_directory, mode)
    assert access_cli.main(["init", "--directory", str(protected)]) == 1
    output = capsys.readouterr()
    assert output.err.startswith("Provisioning failed:")
    assert "another account" in output.err
    assert str(shared) in output.err
    assert not (protected / "identity.key").exists()
    with pytest.raises(access_cli.ProvisioningError, match="another account"):
        access_cli.read_identity_key(protected)


def test_a_writable_parent_below_a_root_owned_system_link_is_refused(capsys):
    # The review's repro: /tmp/<0777 dir>/prot on macOS was accepted after
    # following the root-owned /tmp link, and refused by 0.1.0.
    root = _system_link_root()
    if root is None:
        pytest.skip("Needs the system temp root under a root-owned link (macOS /var)")
    with tempfile.TemporaryDirectory(prefix="radt-access-cli-system-", dir=root) as raw:
        shared = Path(raw) / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        protected = shared / "protected"
        protected.mkdir(mode=0o700)
        assert access_cli.main(["init", "--directory", str(protected)]) == 1
        assert "another account" in capsys.readouterr().err
        assert not (protected / "identity.key").exists()


@pytest.mark.parametrize("problem", [
    None, "other_owner", "root_writable", "caller_sticky", "root_sticky",
])
def test_every_parent_follows_the_openssh_rule(private_directory, simulated_ownership, capsys, problem):
    parent = private_directory.parent
    if problem == "other_owner":
        simulated_ownership[os.fspath(parent)] = (os.geteuid() + 1, 0o755)
    elif problem == "root_writable":
        simulated_ownership[os.fspath(parent)] = (0, 0o777)
    elif problem == "caller_sticky":
        simulated_ownership[os.fspath(parent)] = (os.geteuid(), 0o1777)
    elif problem == "root_sticky":
        # /tmp: root-owned, world-writable and sticky, with the caller's own
        # private directory inside it.
        simulated_ownership[os.fspath(parent)] = (0, 0o1777)
    status = access_cli.main(["init", "--directory", str(private_directory)])
    output = capsys.readouterr()
    if problem in (None, "root_sticky"):
        assert status == 0, output.err
        assert len(access_cli.read_identity_key(private_directory)) == 32
    else:
        assert status == 1
        assert "another account" in output.err
        assert str(parent) in output.err
        assert not (private_directory / "identity.key").exists()


def test_a_writable_directory_after_a_trusted_link_is_refused(private_directory, simulated_ownership, capsys):
    # The link and everything above it are root's; the directory the link
    # leads into is not, so the walk must keep checking past the link.
    base = private_directory.parent
    shared, protected = _writable_parent(private_directory, 0o777)
    _base, _system, link = _system_layout(private_directory, simulated_ownership, target=base)
    assert access_cli.main(["init", "--directory", str(link / "shared" / "protected")]) == 1
    output = capsys.readouterr()
    assert "another account" in output.err
    assert str(shared) in output.err
    assert not (protected / "identity.key").exists()


# Extended access control lists are not visible in POSIX mode bits. macOS ACLs
# grant other accounts access whatever the mode, and an inheritable entry on a
# parent flows into a directory created later, then into its key and database.

def _add_acl_or_skip(path, *, inheritable=False, allow=True):
    import shutil
    import subprocess

    if sys.platform == "darwin":
        flags = ",file_inherit,directory_inherit" if inheritable else ""
        entry = (
            f"everyone allow list,search,add_file,add_subdirectory,delete_child,read,write{flags}"
            if allow else f"everyone deny delete{flags}"
        )
        command = ["chmod", "+a", entry, str(path)]
    elif sys.platform.startswith("linux") and shutil.which("setfacl") and allow:
        command = ["setfacl", *(["-d"] if inheritable else []), "-m", "u:65534:rwx", str(path)]
    else:
        pytest.skip("Needs macOS ACLs or Linux POSIX ACLs (setfacl)")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.skip(f"This file system does not take ACLs: {result.stderr.strip()[:80]}")


def _remove_acls(*paths):
    import subprocess

    for path in paths:
        if sys.platform == "darwin":
            subprocess.run(["chmod", "-N", str(path)], capture_output=True, check=False)
        else:
            subprocess.run(["setfacl", "-b", str(path)], capture_output=True, check=False)


def test_a_protected_directory_with_an_acl_is_refused(private_directory, capsys):
    _add_acl_or_skip(private_directory)
    try:
        assert access_cli.main(["init", "--directory", str(private_directory)]) == 1
        output = capsys.readouterr()
        assert output.err.startswith("Provisioning failed:")
        assert "access control list" in output.err
        assert "protected directory" in output.err
        assert not (private_directory / "identity.key").exists()
    finally:
        _remove_acls(private_directory)


def test_an_acl_inherited_from_a_parent_is_refused(private_directory, capsys):
    # The review's repro: the operator runs mkdir and chmod 700 on a directory
    # whose parent passes an "everyone" entry down; the mode looks private.
    parent = private_directory.parent / "parent"
    parent.mkdir(mode=0o755)
    _add_acl_or_skip(parent, inheritable=True)
    protected = parent / "protected"
    try:
        protected.mkdir()
        protected.chmod(0o700)
        assert access_cli.main(["init", "--directory", str(protected)]) == 1
        assert "access control list" in capsys.readouterr().err
        assert not (protected / "identity.key").exists()
    finally:
        _remove_acls(protected, parent)


@pytest.mark.parametrize("name", ["identity.key", "access.sqlite3"])
def test_a_key_or_database_with_an_acl_is_refused(private_directory, capsys, name):
    access_cli.initialize_access(private_directory)
    target = private_directory / name
    _add_acl_or_skip(target)
    try:
        assert access_cli.main([
            "grant", "--directory", str(private_directory), "--principal", "b" * 64, "--role", "Viewer",
        ]) == 1
        output = capsys.readouterr()
        assert "access control list" in output.err
        assert name in output.err
        if name == "identity.key":
            with pytest.raises(access_cli.ProvisioningError, match="access control list"):
                access_cli.read_identity_key(private_directory)
        else:
            from role_aware_dashboard_toolkit.access_store import AccessStoreError

            with pytest.raises(AccessStoreError):
                SQLiteAccessStore(target)
    finally:
        _remove_acls(target)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS ACLs on parent directories")
@pytest.mark.parametrize("allow", [True, False])
def test_a_parent_acl_may_deny_but_not_allow(private_directory, capsys, allow):
    # macOS home directories carry "everyone deny delete"; an allow entry on a
    # parent would let another account replace the protected directory.
    parent = private_directory.parent / "home"
    parent.mkdir(mode=0o755)
    protected = parent / "protected"
    protected.mkdir(mode=0o700)
    _add_acl_or_skip(parent, allow=allow)
    try:
        status = access_cli.main(["init", "--directory", str(protected)])
        output = capsys.readouterr()
        if allow:
            assert status == 1
            assert "another account" in output.err
            assert str(parent) in output.err
        else:
            assert status == 0, output.err
    finally:
        _remove_acls(parent)


# On Linux, setfacl also widens the group bits of the mode to the ACL mask,
# so the mode check would fire first and blame "group or other access". These
# tests emulate that shape on any POSIX host: the ACL is reported and the
# mode carries the mask, as `setfacl -m u:<id>:rwx` leaves it.

def _emulate_linux_acl(monkeypatch, path, mask_mode):
    target = os.fspath(path)
    real_check = access_cli._has_extended_acl

    def has_acl(candidate, *, allow_entries_only=False):
        if os.fspath(candidate) == target:
            return not allow_entries_only  # POSIX ACLs have no allow-only reading
        return real_check(candidate, allow_entries_only=allow_entries_only)

    monkeypatch.setattr(access_cli, "_has_extended_acl", has_acl)
    os.chmod(path, mask_mode)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ACL shape")
def test_a_directory_acl_is_named_even_when_it_widens_the_mode(private_directory, monkeypatch, capsys):
    _emulate_linux_acl(monkeypatch, private_directory, 0o770)

    assert access_cli.main(["init", "--directory", str(private_directory)]) == 1

    output = capsys.readouterr()
    assert "access control list" in output.err
    assert "group or other access" not in output.err
    assert not (private_directory / "identity.key").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ACL shape")
def test_a_key_acl_is_named_even_when_it_widens_the_mode(private_directory, monkeypatch, capsys):
    access_cli.initialize_access(private_directory)
    _emulate_linux_acl(monkeypatch, private_directory / "identity.key", 0o660)

    with pytest.raises(access_cli.ProvisioningError, match="identity.key carries an extended access control list"):
        access_cli.read_identity_key(private_directory)
    assert access_cli.main([
        "grant", "--directory", str(private_directory), "--principal", "b" * 64, "--role", "Viewer",
    ]) == 1
    assert "identity.key carries an extended access control list" in capsys.readouterr().err
