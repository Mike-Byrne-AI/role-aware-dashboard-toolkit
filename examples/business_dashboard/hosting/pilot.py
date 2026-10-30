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
import os
from pathlib import Path
import re
import sqlite3
import sys
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
    return Configuration(origin, hostname, directory, int(raw_port), Path(raw_mfa_key) if raw_mfa_key else None)


def inspect_existing_storage(configuration: Configuration) -> None:
    """Read-only validation; incomplete/old storage is never initialized."""
    from business.db import _require_schema, check_private_file, validate_data_dir
    from business.security import TransactionAccessStore, principal_for_user
    from business.secret_store import SecretStore
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
            if connection.execute("PRAGMA user_version").fetchone()[0] != 5:
                raise ValueError("The existing schema needs an explicit reviewed migration before hosting.")
            _require_schema(connection, 5)
            secret_store.validate_database(connection)
            TransactionAccessStore(connection).read_freeze()
            users = connection.execute("SELECT id,principal FROM users").fetchall()
            if not users:
                raise ValueError("The existing database has no accounts; refusing to initialize it.")
            for row in users:
                if not (
                    isinstance(row["id"], str) and isinstance(row["principal"], str)
                    and row["principal"].isascii()
                    and hmac.compare_digest(row["principal"], principal_for_user(row["id"], identity_key))
                ):
                    raise ValueError("The database and identity key do not match every saved account.")
            admins = connection.execute("SELECT id FROM users WHERE role='admin' AND active=1").fetchall()
            if not admins:
                raise ValueError("The existing database has no active administrator; repair it explicitly.")
            enrollments = {row["user_id"]: row for row in connection.execute("SELECT * FROM admin_mfa")}
            if any(row["id"] not in enrollments for row in admins):
                raise ValueError("Enroll every active administrator's authenticator before hosting.")
            for row in enrollments.values():
                if not (
                    isinstance(row["generation"], str)
                    and re.fullmatch(r"[0-9a-f]{32}", row["generation"])
                    and type(row["last_counter"]) is int and row["last_counter"] >= -1
                ):
                    raise ValueError("An administrator authenticator is invalid; repair it explicitly.")
    except (sqlite3.Error, AccessStoreError):
        raise ValueError("The existing database could not be validated; preserve it and investigate.") from None


def preflight(configuration: Configuration) -> None:
    """Validate local state and challenge configuration without a provider call."""
    from business.abuse import SubmissionGuard

    SubmissionGuard.from_origin(configuration.public_origin)
    inspect_existing_storage(configuration)


def provision(configuration: Configuration) -> tuple[Path, Path]:
    """Explicit one-time creation; never overwrite an existing installation."""
    from business.seed import provision as seed

    if configuration.mfa_key_file is None:
        raise ValueError("Set BUSINESS_MFA_KEY_FILE to a precreated external key before hosted provisioning.")
    seed(configuration.data_dir, mfa_key_file=configuration.mfa_key_file)
    inspect_existing_storage(configuration)
    return configuration.data_dir / "ACCOUNTS.md", configuration.data_dir / "ADMIN_MFA_SETUP.md"


def create_application(configuration: Configuration):
    """Create an application only after verifying existing schema-v5 state."""
    from business.app import create_app

    preflight(configuration)
    return create_app(configuration.data_dir, public_origin=configuration.public_origin, mfa_key_file=configuration.mfa_key_file)


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
            accounts, authenticator = provision(configuration)
            print(f"Fictional pilot provisioned. Private account sheet: {accounts}")
            print(f"Private authenticator setup sheet: {authenticator}")
        elif arguments.command == "preflight":
            preflight(configuration)
            print("Existing pilot storage and configuration passed preflight; no listener started.")
        else:
            import uvicorn

            application = BootstrapApplication() if arguments.command == "bootstrap" else create_application(configuration)
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
