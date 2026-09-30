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


class ProvisioningError(RuntimeError):
    """A fixed message avoids exposing paths, subjects, keys, or provider data."""

    def __init__(self) -> None:
        super().__init__("Provisioning failed. Check the protected directory and configuration.")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's normal message may echo a mistakenly supplied secret.
        raise ProvisioningError()


def _ordinary_path(path: Path) -> None:
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise ProvisioningError()


def _directory(value: str | Path) -> Path:
    directory = Path(value).expanduser().absolute()
    _ordinary_path(directory)
    if not directory.is_dir():
        raise ProvisioningError()
    # Repositories are unsuitable for either the key or pseudonymous policy.
    for parent in (directory, *directory.parents):
        if (parent / ".git").exists():
            raise ProvisioningError()
    if os.name == "posix" and directory.stat().st_mode & 0o077:
        raise ProvisioningError()
    return directory


def read_identity_key(directory: str | Path) -> bytes:
    """Read the host-only binary key; reject links and broad POSIX permissions.

    Windows operators must restrict the directory ACL themselves. This helper
    does not claim that chmod provides equivalent Windows access control.
    """
    try:
        path = _directory(directory) / "identity.key"
        _ordinary_path(path)
        if not path.is_file() or (os.name == "posix" and path.stat().st_mode & 0o077):
            raise ProvisioningError()
        with path.open("rb") as handle:
            key = handle.read(4097)
        if not 32 <= len(key) <= 4096:
            raise ProvisioningError()
        return key
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
            raise ProvisioningError()
        descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(secrets.token_bytes(32))
        SQLiteAccessStore.create(database_path)
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
    except (Exception, KeyboardInterrupt):
        print(str(ProvisioningError()), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
