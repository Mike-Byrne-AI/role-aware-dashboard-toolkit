"""Trusted local operator commands. Never expose these functions as HTTP routes."""
from __future__ import annotations

import argparse
import sqlite3
import sys

from host.service import WorkItems
from host.storage import StorageUnavailable, initialize


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "issue-token", "grant", "revoke"):
        command = commands.add_parser(name)
        command.add_argument("--data-dir", required=True)
        if name != "init":
            command.add_argument("--subject", required=True)
        if name in {"issue-token", "grant"}:
            command.add_argument("--role", choices=("Viewer", "Operator", "Manager"), required=True)
        if name == "issue-token":
            command.add_argument("--lifetime", type=int, default=3600,
                                 help="Token lifetime in seconds (60 to 86400; default 3600).")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize(args.data_dir)
            print("Initialized empty private storage. Writes are frozen until a manager enables them.")
        else:
            service = WorkItems(args.data_dir)
            if args.command == "issue-token":
                # Intentional operator-only credential output; never log or check in this token.
                print(service.issue_token(args.subject, args.role, lifetime=args.lifetime))
            elif args.command == "grant":
                service.grant(args.subject, args.role)
                print("Updated current account permissions.")
            elif args.command == "revoke":
                service.revoke(args.subject)
                print("Revoked account tokens and permissions.")
    except (ValueError, OSError, sqlite3.Error, StorageUnavailable) as error:
        print(f"Operator command failed ({type(error).__name__}). Check private storage and arguments; "
              "inspect any partially initialized directory before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
