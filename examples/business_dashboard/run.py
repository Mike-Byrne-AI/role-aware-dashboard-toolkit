"""Provision privately or run the Westbridge demonstration on loopback."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


def default_data_dir():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "radt-business-demo"
    return Path.home() / ".local" / "share" / "radt-business-demo"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Westbridge business dashboard demonstration")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir(), help="Private runtime directory outside the source checkout")
    parser.add_argument("--port", type=int, default=8091, help="Loopback HTTP port (default: 8091)")
    parser.add_argument("--hostname", choices=("127.0.0.1", "localhost"), default="127.0.0.1", help="Canonical loopback hostname; use localhost for local passkeys")
    parser.add_argument("--mfa-key-file", type=Path, help="Independent MFA encryption key outside runtime storage (or BUSINESS_MFA_KEY_FILE)")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--provision", action="store_true", help="Create fictional data and private account/authenticator sheets, then exit; directory must be empty")
    actions.add_argument("--migrate-storage", action="store_true", help="Validate and upgrade existing private storage, then exit without starting a listener")
    actions.add_argument("--create-mfa-key", action="store_true", help="Exclusively create an external MFA encryption key; never replace an existing key")
    actions.add_argument("--setup-admin-mfa", action="store_true", help="Enroll administrators missing an authenticator, then exit")
    actions.add_argument("--reset-admin-mfa", action="store_true", help="Replace all administrator authenticators and revoke their sessions, then exit")
    options = parser.parse_args(argv)
    if not 1 <= options.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    # Import only after argument parsing; --help performs no provisioning/import work.
    try:
        if options.create_mfa_key:
            from business.secret_store import create_key_file
            path = create_key_file(options.data_dir, options.mfa_key_file)
            print(f"External MFA encryption key created: {path}. Preserve it separately from database backups.")
            return 0
        if options.migrate_storage:
            from business.db import Database
            Database(options.data_dir, mfa_key_file=options.mfa_key_file, migrate=True)
            print("Existing storage validated and upgraded to schema five. Old backups and SQLite remnants may still contain plaintext MFA seeds.")
            return 0
        if options.provision:
            from business.seed import provision
            provision(options.data_dir, mfa_key_file=options.mfa_key_file)
            print(f"Private account sheet: {(options.data_dir / 'ACCOUNTS.md').absolute()}")
            print(f"Private authenticator setup: {(options.data_dir / 'ADMIN_MFA_SETUP.md').absolute()}")
            return 0
        if options.setup_admin_mfa or options.reset_admin_mfa:
            from business.mfa import setup_admin_mfa
            sheet = setup_admin_mfa(options.data_dir, reset=options.reset_admin_mfa, mfa_key_file=options.mfa_key_file)
            print(f"Private authenticator setup: {sheet}" if sheet else "All administrators already have an authenticator.")
            return 0
        import uvicorn
        from business.app import create_app
        application = create_app(options.data_dir, public_origin=f"http://{options.hostname}:{options.port}", mfa_key_file=options.mfa_key_file)
    except (ValueError, OSError) as error:
        print(f"Cannot start: {error}", file=sys.stderr)
        return 1
    uvicorn.run(application, host="127.0.0.1", port=options.port, proxy_headers=False, access_log=False, workers=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
