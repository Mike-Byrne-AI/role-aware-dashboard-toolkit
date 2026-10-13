"""Trusted local provisioning; never expose this module as a browser endpoint.

Run ``python -m role_aware_dashboard_toolkit.access_cli --help``. Stable provider
subjects are read through a no-echo terminal prompt and never printed or stored.
The access database contains only keyed opaque IDs and role/freeze metadata.
"""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import secrets
import stat
import sys
import time
from typing import Sequence
import warnings

from .access import Identity, principal_id
from .access_store import SQLiteAccessStore

_ROLES = ("Admin", "Operator", "Approver", "Auditor", "Viewer")
_FAILED = "Provisioning failed"
_GENERIC_MESSAGE = f"{_FAILED}. Check the protected directory and configuration."
_ARGUMENT_MESSAGE = (
    f"{_FAILED}: invalid or incomplete command-line arguments; nothing was changed. "
    "Argument values are not repeated here. "
    "Run python -m role_aware_dashboard_toolkit.access_cli --help for usage."
)
_LINK_MESSAGE = (
    f"{_FAILED}: the path passes through a symbolic link or reparse point at {{link}}. "
    "Choose a protected directory whose path contains no links that a non-root "
    "account could change."
)
_MISSING_MESSAGE = f"{_FAILED}: the protected directory must already exist and be a directory."
_REPOSITORY_MESSAGE = (
    f"{_FAILED}: the protected directory is inside a Git repository. "
    "Choose a directory outside every repository."
)
_OWNER_MESSAGE = (
    f"{_FAILED}: the protected directory belongs to another account. Use a directory "
    "owned by the account that runs provisioning and the dashboard."
)
_PERMISSIONS_MESSAGE = (
    f"{_FAILED}: the protected directory allows group or other access. "
    "Restrict it to its owner (for example chmod 700)."
)
_INITIALIZED_MESSAGE = (
    f"{_FAILED}: the protected directory already contains identity.key or access.sqlite3; "
    "nothing was overwritten. Inspect it before trying again."
)
_KEY_MESSAGE = (
    f"{_FAILED}: identity.key is missing, is not a private regular file owned by this "
    "account, or does not hold a valid key. Restore it, or initialize a new protected "
    "directory."
)
_MAX_LINKS = 40


class ProvisioningError(RuntimeError):
    """Fixed messages never include subjects, keys, provider data or argument values.

    The only path a message may contain is a refused link on the operator's own
    protected-directory path, so the operator can see which component to change.
    """

    def __init__(self, message: str = _GENERIC_MESSAGE) -> None:
        super().__init__(message)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's normal message may echo a mistakenly supplied secret.
        raise ProvisioningError(_ARGUMENT_MESSAGE)


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _root_only(info: os.stat_result) -> bool:
    # Owned by root and writable by nobody else: only root can replace entries.
    return info.st_uid == 0 and not info.st_mode & 0o022


def _ordinary_path(path: Path) -> Path:
    """Return the link-free path, refusing every link a non-root account could change.

    POSIX systems may route standard locations through root-owned links (macOS
    /var and /tmp). Such a link is followed only when it is owned by root and
    every directory above it is owned by root and is not group- or
    world-writable. Every other link, and every Windows reparse point, is
    refused; ordinary directories are accepted as before.
    """
    posix = os.name == "posix"
    current = Path(path.anchor)
    trusted = posix and _root_only(os.lstat(current))
    pending = list(path.parts[1:])
    followed = 0
    while pending:
        name = pending.pop(0)
        if name in ("", "."):
            continue
        if name == "..":
            current = current.parent
            continue
        candidate = current / name
        info = os.lstat(candidate)
        if not _is_link(info):
            current = candidate
            trusted = trusted and _root_only(info)
            continue
        followed += 1
        if not (posix and stat.S_ISLNK(info.st_mode) and trusted and info.st_uid == 0) or followed > _MAX_LINKS:
            raise ProvisioningError(_LINK_MESSAGE.format(link=candidate))
        target = Path(os.readlink(candidate))
        if target.is_absolute():
            current = Path(target.anchor)
            trusted = _root_only(os.lstat(current))
            pending[:0] = target.parts[1:]
        else:
            pending[:0] = target.parts
    return current


def _owned_by_caller(info: os.stat_result) -> bool:
    # Another account that owns the directory or key could replace its contents.
    return os.name != "posix" or info.st_uid in {os.geteuid(), 0}


def _directory(value: str | Path) -> Path:
    directory = Path(value).expanduser().absolute()
    try:
        real = _ordinary_path(directory)
        requested_info, real_info = os.stat(directory), os.stat(real)
    except OSError:
        raise ProvisioningError(_MISSING_MESSAGE) from None
    if not stat.S_ISDIR(real_info.st_mode):
        raise ProvisioningError(_MISSING_MESSAGE)
    # The kernel must reach the same directory the walk validated.
    if (requested_info.st_dev, requested_info.st_ino) != (real_info.st_dev, real_info.st_ino):
        raise ProvisioningError()
    # Repositories are unsuitable for either the key or pseudonymous policy.
    # Check the requested path and, past any trusted system link, the real one.
    for parent in (directory, *directory.parents, real, *real.parents):
        if (parent / ".git").exists():
            raise ProvisioningError(_REPOSITORY_MESSAGE)
    if not _owned_by_caller(real_info):
        raise ProvisioningError(_OWNER_MESSAGE)
    if os.name == "posix" and real_info.st_mode & 0o077:
        raise ProvisioningError(_PERMISSIONS_MESSAGE)
    return real


def read_identity_key(directory: str | Path) -> bytes:
    """Read the host-only binary key from a directory checked like provisioning.

    Links a non-root account could change, broad POSIX permissions and a key or
    directory owned by another account (other than root) are refused.

    Windows operators must restrict the directory ACL themselves. This helper
    does not claim that chmod provides equivalent Windows access control.
    """
    try:
        path = _directory(directory) / "identity.key"
        try:
            path = _ordinary_path(path)
        except OSError:
            raise ProvisioningError(_KEY_MESSAGE) from None
        info = os.stat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or not _owned_by_caller(info)
            or (os.name == "posix" and info.st_mode & 0o077)
        ):
            raise ProvisioningError(_KEY_MESSAGE)
        with path.open("rb") as handle:
            key = handle.read(4097)
        if not 32 <= len(key) <= 4096:
            raise ProvisioningError(_KEY_MESSAGE)
        return key
    except ProvisioningError:
        raise
    except Exception:
        raise ProvisioningError() from None


def initialize_access(directory: str | Path) -> None:
    """Create a new random key and frozen empty store without overwriting.

    A filesystem failure can leave partial initialization. No rollback deletes
    files; operators must inspect the protected directory before trying again.
    """
    try:
        target = _directory(directory)
        key_path = target / "identity.key"
        database_path = target / "access.sqlite3"
        if os.path.lexists(key_path) or os.path.lexists(database_path):
            raise ProvisioningError(_INITIALIZED_MESSAGE)
        descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(secrets.token_bytes(32))
        SQLiteAccessStore.create(database_path)
    except ProvisioningError:
        raise
    except Exception:
        raise ProvisioningError() from None


def _subject_principal(directory: str | Path, issuer: str) -> str:
    # GetPassWarning means the host cannot disable echo. Treat it as a failure;
    # never fall back to stdin where input may be displayed or piped/logged.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        subject = getpass.getpass("Verified provider subject (input hidden): ")
    if (
        not isinstance(subject, str)
        or not subject
        or subject != subject.strip()
        or not subject.isascii()
        or len(subject) > 255
    ):
        raise ProvisioningError()
    identity = Identity(issuer=issuer, subject=subject, expires_at=time.time() + 60)
    return principal_id(identity, read_identity_key(directory))


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m role_aware_dashboard_toolkit.access_cli",
        description="Provision a host-owned access store; requires trusted local filesystem access.",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    for command in ("init", "grant", "revoke"):
        child = commands.add_parser(command, allow_abbrev=False)
        child.add_argument("--directory", required=True, help="Existing protected directory outside every repository.")
        if command != "init":
            identity = child.add_mutually_exclusive_group(required=True)
            identity.add_argument("--issuer", help="Exact trusted issuer; prompts privately for its verified subject.")
            identity.add_argument("--principal", help="Previously derived opaque principal ID (never an email or subject).")
        if command == "grant":
            child.add_argument("--role", action="append", required=True, choices=_ROLES,
                               help="Replace assignments with exactly these roles; repeat to allow role selection.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Provision without printing identifiers or original exception details."""
    try:
        args = _parser().parse_args(argv)
        if args.command == "init":
            initialize_access(args.directory)
            print("Created an empty, frozen access store and a private identity key. No users were granted access.")
            return 0
        directory = _directory(args.directory)
        store = SQLiteAccessStore(directory / "access.sqlite3")
        principal = args.principal or _subject_principal(directory, args.issuer)
        store.replace_grants(principal, args.role if args.command == "grant" else ())
        print("Role assignments updated." if args.command == "grant" else "All role assignments revoked.")
        return 0
    except ProvisioningError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        print(_GENERIC_MESSAGE, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
