"""Offline recovery for bounded local security-event delivery; never serves HTTP."""

import argparse
import sqlite3
import sys

from business.db import Database
from business.security_events import dispatch_pending


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--mfa-key-file")
    parser.add_argument("--maintenance-confirmed", action="store_true",
                        help="Assert that service ingress and writers are stopped; the tool cannot prove this.")
    parser.add_argument("--limit", type=int, default=100)
    options = parser.parse_args(argv)
    if not options.maintenance_confirmed:
        parser.error("Stop service ingress and writers, then pass --maintenance-confirmed.")
    if not 1 <= options.limit <= 100:
        parser.error("--limit must be between 1 and 100")
    try:
        database = Database(options.data_dir, mfa_key_file=options.mfa_key_file)
        result = dispatch_pending(database, limit=options.limit)
    except (OSError, ValueError, sqlite3.Error):
        print("Local security-event delivery failed; preserve storage and inspect protected diagnostics.", file=sys.stderr)
        return 1
    print(f"Local receipts delivered: {result['delivered']}; failed: {result['failed']}; pending: {result['pending']}.")
    return 1 if result["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
