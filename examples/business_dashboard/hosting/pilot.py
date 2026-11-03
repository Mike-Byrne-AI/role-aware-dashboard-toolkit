"""Operate Westbridge behind a verified HTTPS-only, isolated managed ingress.

Only ``provision`` creates fictional accounts. Normal startup validates existing
state without migrating or repairing it. The platform must terminate HTTPS,
redirect/reject public HTTP and isolate the plain HTTP backend. Forwarded headers
are not trusted; verify the real host before distributing accounts.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
import hmac
import ipaddress
import math
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
SOURCE_ROOTS = frozenset({Path(__file__).absolute().parents[3], Path(__file__).resolve().parents[3]})
APPLICATION_ROOT = Path(__file__).resolve().parents[1]
if str(APPLICATION_ROOT) not in sys.path:
    sys.path.insert(0, str(APPLICATION_ROOT))

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


@dataclass(frozen=True)
class Configuration:
    public_origin: str
    hostname: str
    data_dir: Path
    port: int
    mfa_key_file: Path | None = None
    security_delivery_config: Path | None = None


def _require_posix() -> None:
    if os.name != "posix":
        raise ValueError("The hosted pilot requires a POSIX host with private file permissions.")


def load_configuration(environ: Mapping[str, str] | None = None) -> Configuration:
    """Validate deployment settings before touching private storage."""
    _require_posix()
    values = os.environ if environ is None else environ
    origin = values.get("PUBLIC_ORIGIN", "")
    try:
        parsed = urlsplit(origin)
        hostname = parsed.hostname or ""
        valid = (
            origin == f"https://{hostname}"
            and parsed.scheme == "https"
            and 1 < len(hostname) <= 253
            and "." in hostname
            and all(_DNS_LABEL.fullmatch(label) for label in hostname.split("."))
            and not hostname.endswith(".localhost")
        )
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            valid = False
    except ValueError:
        valid = False
    if not valid:
        raise ValueError(
            "Set PUBLIC_ORIGIN to one canonical HTTPS DNS origin, such as "
            "https://example-dashboard.example.com; no path, port, wildcard or credentials."
        )

    raw_directory = values.get("BUSINESS_DATA_DIR", "")
    directory = Path(raw_directory)
    if not raw_directory or not directory.is_absolute():
        raise ValueError("BUSINESS_DATA_DIR must be an absolute private persistent directory.")
    for candidate in (directory, directory.resolve()):
        if candidate == Path(candidate.anchor) or any(
            candidate == root or root in candidate.parents for root in SOURCE_ROOTS
        ):
            raise ValueError("BUSINESS_DATA_DIR must stay outside the entire repository/source directory.")
    for item in (directory, *directory.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("BUSINESS_DATA_DIR must not use symbolic links or junctions.")
    raw_port = values.get("PORT", "10000")
    if not re.fullmatch(r"[0-9]{1,5}", raw_port) or not 1 <= int(raw_port) <= 65535:
        raise ValueError("PORT must be an integer from 1 through 65535.")
    raw_mfa_key = values.get("BUSINESS_MFA_KEY_FILE", "")
    if raw_mfa_key and not Path(raw_mfa_key).is_absolute():
        raise ValueError("BUSINESS_MFA_KEY_FILE must be an absolute external private key path.")
    raw_delivery = values.get("BUSINESS_SECURITY_DELIVERY_CONFIG", "")
    if raw_delivery and not Path(raw_delivery).is_absolute():
        raise ValueError("BUSINESS_SECURITY_DELIVERY_CONFIG must be an absolute private configuration path.")
    return Configuration(origin, hostname, directory, int(raw_port), Path(raw_mfa_key) if raw_mfa_key else None,
                         Path(raw_delivery) if raw_delivery else None)


def _pending_enrollment_available(connection, user, security, now):
    """Diagnostic only: either an unused grant or its current setup can proceed."""
    from business.enrollment import ENROLLMENT_SECONDS, GRANT_SECONDS

    def current_window(row, lifetime):
        return row is not None and all(
            type(row[key]) in (int, float) and math.isfinite(row[key]) and row[key] >= 0
            for key in ("created_at", "expires_at")
        ) and row["created_at"] <= now < row["expires_at"] <= row["created_at"] + lifetime

    grant = connection.execute("SELECT * FROM enrollment_grants WHERE user_id=?", (user["id"],)).fetchone()
    if (not current_window(grant, GRANT_SECONDS) or grant["purpose"] not in {"initial", "recovery"}
            or grant["user_revision"] != user["revision"] or grant["security_revision"] != security["revision"]):
        return False
    if grant["claimed_at"] is None:
        return True
    pending = connection.execute("SELECT * FROM enrollment_sessions WHERE user_id=?", (user["id"],)).fetchone()
    return (current_window(pending, ENROLLMENT_SECONDS)
            and type(grant["claimed_at"]) in (int, float) and math.isfinite(grant["claimed_at"])
            and grant["claimed_at"] == pending["created_at"] and pending["grant_hash"] == grant["secret_hash"]
            and pending["user_revision"] == user["revision"] and pending["security_revision"] == security["revision"]
            and pending["expires_at"] <= grant["expires_at"])


def inspect_existing_storage(configuration: Configuration) -> dict:
    """Read-only validation; incomplete/old storage is never initialized."""
    from business.db import _require_schema, check_private_file, validate_data_dir
    from business.security import TransactionAccessStore, principal_for_user
    from business.secret_store import SecretStore
    from business.enrollment import account_can_authenticate, readiness
    from business.event_destinations import validate_delivery_state
    from business.browser_flow import clock_valid, validate_state
    from role_aware_dashboard_toolkit.access_store import AccessStoreError

    directory = validate_data_dir(configuration.data_dir)
    if os.path.lexists(directory / "RESTORE_QUARANTINE"):
        raise ValueError("Restored storage is quarantined; reconcile current security state before hosting.")
    if configuration.mfa_key_file is None:
        raise ValueError("Set BUSINESS_MFA_KEY_FILE to an independent key outside runtime storage before hosting.")
    database_path = directory / "business.sqlite3"
    key_path = directory / "identity.key"
    try:
        check_private_file(database_path)
        check_private_file(key_path)
        for path in (directory / "ACCOUNTS.md", *directory.glob("ADMIN_MFA_SETUP*.md"),
                     *directory.glob("ADMIN_ENROLLMENT*.md"), *directory.glob("ENROLLMENT*.md"),
                     *(Path(str(database_path) + suffix) for suffix in ("-journal", "-wal", "-shm"))):
            if path.exists() or path.is_symlink():
                check_private_file(path)
        identity_key = key_path.read_bytes()
    except OSError:
        raise ValueError("Pilot storage is missing or incomplete; preserve it and investigate.") from None
    if len(identity_key) != 32:
        raise ValueError("The existing identity key is invalid; preserve the existing state.")
    secret_store = SecretStore(directory, identity_key, configuration.mfa_key_file)
    try:
        with closing(sqlite3.connect(database_path.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
                raise ValueError("The existing database failed its integrity check.")
            if connection.execute("PRAGMA user_version").fetchone()[0] != 10:
                raise ValueError("The existing schema needs an explicit reviewed migration before hosting.")
            _require_schema(connection, 10)
            validate_delivery_state(connection)
            validate_state(connection)
            now = time.time()
            if not clock_valid(connection, now=now):
                raise ValueError("The browser login clock is invalid or behind its durable rejection boundary; preserve state.")
            secret_store.validate_database(connection)
            TransactionAccessStore(connection).read_freeze()
            users = connection.execute("SELECT * FROM users").fetchall()
            if not users:
                raise ValueError("The existing database has no accounts; refusing to initialize it.")
            for row in users:
                if not (
                    isinstance(row["id"], str) and isinstance(row["principal"], str)
                    and row["principal"].isascii()
                    and hmac.compare_digest(row["principal"], principal_for_user(row["id"], identity_key))
                ):
                    raise ValueError("The database and identity key do not match every saved account.")
            admins = [user for user in users if user["role"] == "admin" and user["active"] == 1]
            if not admins:
                raise ValueError("The existing database has no active administrator; repair it explicitly.")
            status = readiness(connection)
            policy = connection.execute("SELECT * FROM authentication_policy WHERE id=1").fetchone()
            if type(policy["revision"]) is not int or policy["revision"] < 0:
                raise ValueError("Authentication policy revision is invalid.")
            enrollments = {row["user_id"]: row for row in connection.execute("SELECT * FROM account_mfa")}
            active, pending, usable, unavailable_grants = 0, 0, 0, 0
            for user in users:
                security = connection.execute("SELECT * FROM account_security WHERE user_id=?", (user["id"],)).fetchone()
                if (security is None or type(security["revision"]) is not int or security["revision"] < 0
                        or security["lifecycle"] not in {"legacy", "pending", "active"}):
                    raise ValueError("An account lifecycle record is missing or invalid.")
                completed = security["completed_at"]
                if (security["lifecycle"] == "active" and
                        (type(completed) not in (int, float) or not math.isfinite(completed) or completed < 0)):
                    raise ValueError("An active account has no valid enrollment completion.")
                if user["active"] != 1:
                    continue
                active += 1
                if security["lifecycle"] == "pending":
                    pending += 1
                    unavailable_grants += int(not _pending_enrollment_available(connection, user, security, now))
                    continue
                if status["mode"] == "strict" and security["lifecycle"] != "active":
                    raise ValueError("Strict authentication cannot serve unresolved legacy accounts; finish the reviewed migration.")
                factor = enrollments.get(user["id"])
                passkey = connection.execute("SELECT 1 FROM passkey_credentials WHERE user_id=?", (user["id"],)).fetchone()
                if security["lifecycle"] == "active":
                    if not (passkey or factor is not None and factor["last_counter"] >= 0):
                        raise ValueError("An active enrolled account has no confirmed authenticator.")
                elif user["role"] == "admin" and factor is None and passkey is None:
                    raise ValueError("A legacy administrator has no authenticator; issue reviewed migration enrollment.")
                usable += int(account_can_authenticate(connection, user))
            if status["mode"] == "transition":
                deployment = "transition"
            elif pending == active:
                deployment = "enrollment_only"
            elif pending:
                deployment = "enrollment_incomplete"
            else:
                deployment = "ready"
            return {"deployment_state": deployment, "mode": status["mode"], "ready": status["ready"],
                    "active_accounts": active, "ordinary_sign_in_accounts": usable,
                    "pending_enrollments": pending, "pending_grants_unavailable": unavailable_grants,
                    "ready_administrators": status["ready_administrators"]}
    except (sqlite3.Error, AccessStoreError):
        raise ValueError("The existing database could not be validated; preserve it and investigate.") from None


def preflight(configuration: Configuration) -> dict:
    """Validate local state and challenge configuration without a provider call."""
    from business.abuse import SubmissionGuard

    SubmissionGuard.from_origin(configuration.public_origin)
    return inspect_existing_storage(configuration)


def provision(configuration: Configuration) -> Path:
    """Explicit one-time creation; never overwrite an existing installation."""
    from business.seed import provision as seed

    if configuration.mfa_key_file is None:
        raise ValueError("Set BUSINESS_MFA_KEY_FILE to a precreated external key before hosted provisioning.")
    seed(configuration.data_dir, mfa_key_file=configuration.mfa_key_file)
    inspect_existing_storage(configuration)
    return configuration.data_dir / "ACCOUNTS.md"


def create_application(configuration: Configuration):
    """Create an application only after verifying existing schema-v10 state."""
    from business.app import create_app

    status = preflight(configuration)
    application = create_app(configuration.data_dir, public_origin=configuration.public_origin,
                             mfa_key_file=configuration.mfa_key_file, security_delivery_config=configuration.security_delivery_config)
    application.state.startup_authentication_status = status
    return application


def _report_authentication_status(status):
    state = status["deployment_state"]
    if state == "enrollment_only":
        print("Authentication state: enrollment only; ordinary account sign-in is unavailable until enrollment completes.")
    elif state == "enrollment_incomplete":
        print("Authentication state: enrollment incomplete; pending accounts cannot sign in. Enrolled accounts retain access.")
    elif state == "transition":
        print("Authentication state: legacy transition; strict authentication has not been activated.")
    else:
        print("Authentication state: strict policy with enrolled accounts. Actual-host/device acceptance remains separate.")
    if status["pending_grants_unavailable"]:
        print("Some pending accounts need a fresh offline enrollment grant; expired or missing grants do not activate access.")


class BootstrapApplication:
    """A maintenance-only listener for platforms needing a live shell first.

    It never reads private storage, creates accounts, or switches to serving
    the dashboard. Provisioning and the eventual command change stay explicit.
    """

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        elif scope["type"] == "http":
            body = b"Service is being prepared.\n"
            await send({"type": "http.response.start", "status": 503, "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ]})
            await send({"type": "http.response.body", "body": body})
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1013})


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Operate the Westbridge pilot behind verified HTTPS-only managed ingress.",
        epilog=(
            "Required: PUBLIC_ORIGIN and BUSINESS_DATA_DIR. PORT defaults to 10000. "
            "provision/preflight/serve require BUSINESS_MFA_KEY_FILE outside runtime storage. "
            "preflight/serve also require BUSINESS_TURNSTILE_SITE_KEY and "
            "BUSINESS_TURNSTILE_SECRET_KEY. No forwarding-header trust is enabled."
        ),
    )
    parser.add_argument("command", choices=("bootstrap", "provision", "preflight", "serve"), help=(
        "provision creates fictional accounts in empty storage once; preflight checks existing "
        "state without listening; serve never creates accounts or migrates old storage; "
        "bootstrap only serves a fixed maintenance response for initial shell access."
    ))
    arguments = parser.parse_args(argv)
    os.umask(0o077)
    try:
        configuration = load_configuration()
        if arguments.command == "provision":
            accounts = provision(configuration)
            print(f"Fictional pilot provisioned. Private expiring enrollment sheet: {accounts}")
            print("Ordinary account sign-in remains unavailable until enrollment completes.")
        elif arguments.command == "preflight":
            status = preflight(configuration)
            print("Existing pilot storage and configuration passed preflight; no listener started.")
            _report_authentication_status(status)
        else:
            import uvicorn

            application = BootstrapApplication() if arguments.command == "bootstrap" else create_application(configuration)
            if arguments.command == "serve":
                _report_authentication_status(application.state.startup_authentication_status)
            print("Starting maintenance-only bootstrap." if arguments.command == "bootstrap" else
                  "Starting the existing pilot behind the configured HTTPS-only ingress.", flush=True)
            uvicorn.run(
                application, host="0.0.0.0", port=configuration.port, workers=1,
                access_log=False, proxy_headers=False, forwarded_allow_ips="", server_header=False,
            )
    except ValueError as error:
        parser.exit(1, f"Pilot operation refused: {error}\n")
    except (OSError, sqlite3.Error):
        # OS errors can contain private paths or provider details. Keep logs
        # bounded; operators can inspect their private host through its shell.
        parser.exit(1, "Pilot operation refused: private storage could not be accessed.\n")


if __name__ == "__main__":
    main()
