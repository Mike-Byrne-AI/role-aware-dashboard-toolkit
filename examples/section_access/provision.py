"""Trusted local operator commands for this example's custom access roles.

Never expose this module through a browser callback or web endpoint. Initialize
the protected directory with the toolkit's access_cli before using this module.
Only the provider's verified subject is prompted. The subject, issuer and key
are never printed; a refusal names its cause, such as a link in the path.
"""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import sys
import time
from typing import Sequence
import warnings

from role_aware_dashboard_toolkit.access import Identity, principal_id
from role_aware_dashboard_toolkit.access_cli import ProvisioningError, read_identity_key
from role_aware_dashboard_toolkit.access_store import SQLiteAccessStore

from .policy import ROLE_SECTIONS


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Normal argparse errors can echo secrets mistakenly entered as flags.
        raise ProvisioningError()


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="python -m examples.section_access.provision",
        description=(
            "Assign this example's roles from a trusted local terminal. "
            "Set RADT_ACCESS_DIRECTORY and RADT_OIDC_ISSUER first."
        ),
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    grant = commands.add_parser("grant", allow_abbrev=False)
    grant.add_argument(
        "--role", action="append", required=True, choices=tuple(ROLE_SECTIONS),
        help="Replace all assignments with these roles; repeat for a choice of roles.",
    )
    commands.add_parser("revoke", allow_abbrev=False)
    return parser


def _principal(issuer: str, identity_key: bytes) -> str:
    # Match the OIDC adapter's exact strings, including rejection of DEL.
    if (
        not issuer
        or issuer != issuer.strip()
        or len(issuer) > 2048
        or any(ord(char) < 32 or ord(char) == 127 for char in issuer)
    ):
        raise ProvisioningError()
    with warnings.catch_warnings():
        # getpass may warn before falling back to visible stdin. Stop there.
        warnings.simplefilter("error", getpass.GetPassWarning)
        subject = getpass.getpass("Verified provider subject (input hidden): ")
    if (
        not isinstance(subject, str)
        or not subject
        or subject != subject.strip()
        or not subject.isascii()
        or len(subject) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in subject)
    ):
        raise ProvisioningError()
    identity = Identity(issuer, subject, time.time() + 60)
    return principal_id(identity, identity_key)


def main(argv: Sequence[str] | None = None) -> int:
    """Replace or revoke grants without disclosing sensitive failure details."""
    try:
        args = _parser().parse_args(argv)
        directory_value = os.environ["RADT_ACCESS_DIRECTORY"]
        issuer = os.environ["RADT_OIDC_ISSUER"]
        if not directory_value:
            raise ProvisioningError()
        # This public helper checks repository/ancestor-link/permission rules.
        identity_key = read_identity_key(directory_value)
        directory = Path(directory_value).expanduser().absolute()
        store = SQLiteAccessStore(
            directory / "access.sqlite3", allowed_roles=tuple(ROLE_SECTIONS)
        )
        principal = _principal(issuer, identity_key)
        store.replace_grants(principal, args.role if args.command == "grant" else ())
        print("Role assignments updated." if args.command == "grant" else "All role assignments revoked.")
        return 0
    except ProvisioningError as exc:
        # Toolkit refusals name the cause (a link, the owner, permissions)
        # and never the subject, issuer or key.
        print(str(exc), file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt):
        print(str(ProvisioningError()), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
