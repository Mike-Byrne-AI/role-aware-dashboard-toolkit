"""Provision privately or run the Westbridge demonstration on loopback."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys


def default_data_dir():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "radt-business-demo"
    return Path.home() / ".local" / "share" / "radt-business-demo"


def issue_enrollment_sheet(data_dir, username, *, purpose, case_reference=None, mfa_key_file=None):
    """Publish one private grant sheet before its transaction commits."""
    from business.db import Database, create_private_file
    from business.enrollment import issue_grant

    database = Database(data_dir, mfa_key_file=mfa_key_file)
    with database.transaction() as connection:
        user = connection.execute("SELECT id,username,active FROM users WHERE username=?",
                                  (username.casefold(),)).fetchone()
        if user is None or user["active"] != 1:
            raise ValueError("Choose an existing active account for enrollment.")
        grant = issue_grant(connection, user["id"], purpose=purpose, case_reference=case_reference)
        expires = connection.execute("SELECT expires_at FROM enrollment_grants WHERE user_id=?", (user["id"],)).fetchone()[0]
        content = (
            "# Westbridge private account enrollment\n\n"
            "Keep this file private and deliver it only after the operator's identity check.\n"
            "Use this single-use grant only if the issuing command completed successfully.\n"
            "Open the configured Westbridge site directly and choose account enrollment.\n"
            "The grant cannot sign in; choose your password and prove your authenticator to activate access.\n\n"
            f"Username: {user['username']}\n\nPurpose: {purpose}\n\nEnrollment grant: `{grant}`\n\n"
            f"Expires at: {datetime.fromtimestamp(expires, timezone.utc).isoformat()}\n"
        )
        output = database.directory / f"ENROLLMENT-{secrets.token_hex(8)}.md"
        create_private_file(output, content.encode())
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description="Westbridge business dashboard demonstration")
    parser.add_argument("--data-dir", type=Path, default=default_data_dir(), help="Private runtime directory outside the source checkout")
    parser.add_argument("--port", type=int, default=8091, help="Loopback HTTP port (default: 8091)")
    parser.add_argument("--hostname", choices=("127.0.0.1", "localhost"), default="127.0.0.1", help="Canonical loopback hostname; use localhost for local passkeys")
    parser.add_argument("--mfa-key-file", type=Path, help="Independent MFA encryption key outside runtime storage (or BUSINESS_MFA_KEY_FILE)")
    parser.add_argument("--security-delivery-config", type=Path, help="Private configuration for an explicitly activated remote security destination")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--provision", action="store_true", help="Create fictional data and a private expiring account enrollment sheet, then exit; directory must be empty")
    actions.add_argument("--migrate-storage", action="store_true", help="Validate and upgrade existing private storage, then exit without starting a listener")
    actions.add_argument("--create-mfa-key", action="store_true", help="Exclusively create an external MFA encryption key; never replace an existing key")
    actions.add_argument("--setup-admin-mfa", action="store_true", help="Issue migration enrollment to legacy administrators missing a factor, then exit")
    actions.add_argument("--reset-admin-mfa", action="store_true", help="Issue recovery enrollment for ALL active administrators, revoking their credentials and sessions; requires --case-ref. Prefer --issue-enrollment for one account")
    actions.add_argument("--issue-enrollment", metavar="USERNAME", help="Issue one private expiring enrollment grant, then exit")
    actions.add_argument("--auth-readiness", action="store_true", help="Read authentication policy and remaining enrollment work without changes")
    actions.add_argument("--activate-auth-policy", action="store_true", help="Explicitly activate strict authentication only after every active account is enrolled; revokes existing sessions")
    parser.add_argument("--purpose", choices=("initial", "migration", "recovery"), help="Purpose for --issue-enrollment")
    parser.add_argument("--case-ref", help="Opaque operator proofing case reference; required for recovery, never personal evidence")
    options = parser.parse_args(argv)
    if not 1 <= options.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if bool(options.issue_enrollment) != bool(options.purpose):
        parser.error("--issue-enrollment and --purpose must be supplied together")
    if (options.reset_admin_mfa or options.purpose == "recovery") and not options.case_ref:
        parser.error("Recovery requires --case-ref after the operator's identity-proofing review")
    if options.case_ref and not (options.issue_enrollment or options.setup_admin_mfa or options.reset_admin_mfa):
        parser.error("--case-ref is only used when issuing enrollment")
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
            print("Existing storage validated and upgraded to schema ten. Keep all older writers stopped; mixed schema versions are unsupported. Existing sessions remain usable, but reverification requires browser-flow bootstrap. Legacy access remains in transition until reviewed enrollment and explicit strict activation. Old backups and SQLite remnants may still contain plaintext MFA seeds. Remote security-event delivery requires separate explicit activation.")
            return 0
        if options.provision:
            from business.seed import provision
            provision(options.data_dir, mfa_key_file=options.mfa_key_file)
            print(f"Private account enrollment sheet: {(options.data_dir / 'ACCOUNTS.md').absolute()}")
            print("Enrollment secrets expire after 24 hours. Ordinary account sign-in remains unavailable until enrollment completes.")
            return 0
        if options.issue_enrollment:
            sheet = issue_enrollment_sheet(options.data_dir, options.issue_enrollment, purpose=options.purpose,
                                           case_reference=options.case_ref, mfa_key_file=options.mfa_key_file)
            print(f"Private {options.purpose} enrollment sheet: {sheet}")
            print("Complete enrollment to activate the account; the grant itself cannot sign in.")
            return 0
        if options.auth_readiness or options.activate_auth_policy:
            from business.db import Database
            from business.enrollment import activate_strict, readiness
            database = Database(options.data_dir, mfa_key_file=options.mfa_key_file)
            transaction = database.transaction if options.activate_auth_policy else database.readonly_snapshot
            with transaction() as connection:
                status = activate_strict(connection) if options.activate_auth_policy else readiness(connection)
            print(json.dumps(status, sort_keys=True))
            return 0
        if options.setup_admin_mfa or options.reset_admin_mfa:
            from business.mfa import setup_admin_mfa
            sheet = setup_admin_mfa(options.data_dir, reset=options.reset_admin_mfa,
                                    mfa_key_file=options.mfa_key_file, case_reference=options.case_ref)
            print(f"Private administrator enrollment sheet: {sheet}" if sheet else "No legacy administrator needs a migration enrollment.")
            if options.reset_admin_mfa and sheet:
                print("All active administrators now require reenrollment; previous credentials and sessions were revoked. Prefer single-account --issue-enrollment for bounded recovery.")
            return 0
        import uvicorn
        from business.app import create_app
        application = create_app(options.data_dir, public_origin=f"http://{options.hostname}:{options.port}",
                                 mfa_key_file=options.mfa_key_file, security_delivery_config=options.security_delivery_config)
    except ValueError as error:
        print(f"Cannot start: {error}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error):
        print("Operation refused: private storage could not be accessed. Preserve any incomplete output and inspect it privately.", file=sys.stderr)
        return 1
    uvicorn.run(application, host="127.0.0.1", port=options.port, proxy_headers=False, access_log=False, workers=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
