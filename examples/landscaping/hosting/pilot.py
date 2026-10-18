"""Operate the hosted pilot behind an HTTPS-only, isolated managed ingress.

This adapter never infers external HTTPS from forwarding headers. Client-IP
forwarding is off unless the operator explicitly configures verified proxy peers.
The platform must terminate HTTPS, redirect/reject public HTTP, and isolate this
plain HTTP backend. Verify those properties on the selected real host before
distributing accounts. Only ``provision`` can create fictional initial accounts.
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import os
import re
import sqlite3
import sys
from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
# Keep the shipped <source>/examples/landscaping/hosting/pilot.py layout.
# Both checkout and extracted source packages must keep private storage outside
# the entire source tree, including an invocation through a symlink alias.
SOURCE_ROOTS = frozenset({Path(__file__).absolute().parents[3], Path(__file__).resolve().parents[3]})
APPLICATION_ROOT = Path(__file__).resolve().parents[1]
if str(APPLICATION_ROOT) not in sys.path:
    sys.path.insert(0, str(APPLICATION_ROOT))

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_REQUIRED_TABLES = frozenset({
    "users", "sessions", "settings", "jobs", "job_signups", "job_history",
    "messages", "customers", "audit", "login_limits", "telemetry", "request_samples",
})


@dataclass(frozen=True)
class Configuration:
    public_origin: str
    hostname: str
    data_dir: Path
    port: int
    trusted_proxy_cidrs: tuple[str, ...] = ()


def _trusted_proxy_cidrs(raw: str) -> tuple[str, ...]:
    """Accept only explicitly verified, narrow ingress peers, never a wildcard."""
    if not raw:
        return ()
    peers = []
    for item in raw.split(","):
        item = item.strip()
        try:
            if not item or "%" in item:
                raise ValueError
            network = ipaddress.ip_network(item, strict=True)
            minimum_prefix = 24 if network.version == 4 else 64
            if (
                network.prefixlen < minimum_prefix or network.network_address.is_unspecified
                or network.network_address.is_multicast
            ):
                raise ValueError
        except ValueError:
            raise ValueError(
                "TRUSTED_PROXY_CIDRS accepts only verified proxy IPs or canonical narrow CIDRs "
                "(IPv4 /24 or narrower; IPv6 /64 or narrower); no wildcard, hostname, or default route."
            ) from None
        peer = str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
        if peer in peers:
            raise ValueError("TRUSTED_PROXY_CIDRS must not contain duplicate peers.")
        peers.append(peer)
    return tuple(peers)


def load_configuration(environ: Mapping[str, str] | None = None) -> Configuration:
    """Validate explicit deployment settings before touching private storage."""
    values = os.environ if environ is None else environ
    if os.name != "posix":
        raise ValueError("The hosted pilot requires a POSIX host with private file permissions.")
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
            "https://landscaping.example.com; no path, port, wildcard, or credentials."
        )

    raw_directory = values.get("LANDSCAPE_DATA_DIR", "")
    requested = Path(raw_directory)
    if not raw_directory or not requested.is_absolute():
        raise ValueError("LANDSCAPE_DATA_DIR must be an absolute private persistent directory.")
    resolved = requested.resolve()
    for candidate in (requested, resolved):
        if candidate == Path(candidate.anchor) or any(
            candidate == root or root in candidate.parents for root in SOURCE_ROOTS
        ):
            raise ValueError("LANDSCAPE_DATA_DIR must stay outside the entire repository/source directory.")
    if requested.is_symlink():
        raise ValueError("LANDSCAPE_DATA_DIR must not be a symbolic link.")
    raw_port = values.get("PORT", "10000")
    if not re.fullmatch(r"[0-9]{1,5}", raw_port) or not 1 <= int(raw_port) <= 65535:
        raise ValueError("PORT must be an integer from 1 through 65535.")
    trusted_proxy_cidrs = _trusted_proxy_cidrs(values.get("TRUSTED_PROXY_CIDRS", ""))
    return Configuration(origin, hostname, requested, int(raw_port), trusted_proxy_cidrs)


def inspect_existing_storage(configuration: Configuration) -> None:
    """Read-only readiness check; missing or partial storage is never initialized."""
    from landscape.db import SCHEMA, SCHEMA_VERSION, _check_private
    from landscape.paths import validate_data_dir
    from landscape.security import principal_for_user

    directory = validate_data_dir(configuration.data_dir)
    database_path = directory / "landscape.sqlite3"
    key_path = directory / "identity.key"
    if not directory.is_dir() or not database_path.is_file() or not key_path.is_file():
        raise ValueError(
            "Pilot storage is missing or incomplete. Provision an empty directory explicitly, "
            "or restore the original database and identity key together."
        )
    _check_private(directory, directory=True)
    _check_private(database_path)
    _check_private(key_path)
    identity_key = key_path.read_bytes()
    if len(identity_key) != 32:
        raise ValueError("The existing private identity key is invalid; preserve and repair storage.")
    handoff = directory / "TRIAL_ACCOUNTS.md"
    if handoff.exists() or handoff.is_symlink():
        _check_private(handoff)
    try:
        with closing(sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)) as connection:
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("The existing database failed its integrity check.")
            if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise ValueError("The existing database schema needs an explicit reviewed migration.")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
            if not _REQUIRED_TABLES <= tables:
                raise ValueError("The existing database is incomplete; refusing to initialize it.")
            # Compare structure with the pinned application's trusted schema in
            # memory. Never repair a partial on-disk table during normal startup.
            with closing(sqlite3.connect(":memory:")) as expected:
                expected.executescript(SCHEMA)
                for table in _REQUIRED_TABLES:
                    columns = connection.execute(f"PRAGMA table_info({table})").fetchall()
                    if columns != expected.execute(f"PRAGMA table_info({table})").fetchall():
                        raise ValueError("The existing database structure needs an explicit reviewed repair.")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ValueError("The existing database has inconsistent references.")
            if connection.execute("SELECT 1 FROM users WHERE active=1 AND role='admin' LIMIT 1").fetchone() is None:
                raise ValueError("The existing database has no active administrator; repair it explicitly.")
            for user_id, stored_principal in connection.execute("SELECT id,principal FROM users"):
                # The key must belong to this database, not merely have the
                # right length. Check inactive users too, before any listener or
                # schema initialization can conceal an incomplete restoration.
                try:
                    paired = (
                        isinstance(user_id, str) and isinstance(stored_principal, str)
                        and stored_principal.isascii()
                        and hmac.compare_digest(principal_for_user(user_id, identity_key), stored_principal)
                    )
                except (TypeError, ValueError):
                    paired = False
                if not paired:
                    raise ValueError(
                        "The database and identity key do not match every saved account; "
                        "restore the original matched pair or repair it explicitly."
                    )
            for singleton in ("settings", "telemetry"):
                if connection.execute(f"SELECT count(*) FROM {singleton} WHERE id=1").fetchone()[0] != 1:
                    raise ValueError("The existing database is incomplete; refusing to initialize it.")
    except sqlite3.Error:
        raise ValueError("The existing database could not be validated; refusing to initialize it.") from None


def provision(configuration: Configuration) -> Path:
    """Provision once, only when the operator explicitly selects empty storage."""
    from landscape.launcher import prepare_demo

    directory = configuration.data_dir
    if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
        raise ValueError("Provisioning requires empty storage; existing files and accounts are preserved.")
    database, seeded = prepare_demo(directory)
    if not seeded:
        raise ValueError("Provisioning did not create new storage; existing accounts were preserved.")
    inspect_existing_storage(configuration)
    return database.directory / "TRIAL_ACCOUNTS.md"


class ExternalHTTPS:
    """Use a deployment-configured HTTPS scheme, never client forwarding claims.

    This is correct only behind a verified HTTPS-only ingress with an isolated
    backend. It cannot turn a public HTTP backend into a secure deployment.
    Host/Origin checks and all security headers remain the application's job.
    """

    def __init__(self, application, configuration: Configuration):
        self.application = application
        self.scheme = urlsplit(configuration.public_origin).scheme

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.application(scope, receive, send)
        # Any outer trusted-peer middleware has already extracted client IP.
        # The deployment-configured scheme always overrides its proto claims.
        scope = {**scope, "scheme": self.scheme}

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = [
                    (key, value) for key, value in message.get("headers", [])
                    if key.lower() != b"strict-transport-security"
                ]
                headers.append((b"strict-transport-security", b"max-age=31536000"))
                message = {**message, "headers": headers}
            await send(message)

        await self.application(scope, receive, secure_send)


def create_application(configuration: Configuration):
    """Serve only previously provisioned state, with mandatory secure cookies."""
    from landscape.app import create_app

    inspect_existing_storage(configuration)
    application = create_app(
        configuration.data_dir,
        secure_cookies=True,
        allowed_hosts=[configuration.hostname],
    )
    application = ExternalHTTPS(application, configuration)
    if configuration.trusted_proxy_cidrs:
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

        # Enable only after verifying actual ingress peer addresses, header
        # replacement/append semantics, and backend isolation on the live host.
        # This outer layer extracts client IP first; ExternalHTTPS then restores
        # the configured scheme before the application's Host/Origin boundary.
        application = ProxyHeadersMiddleware(application, trusted_hosts=list(configuration.trusted_proxy_cidrs))
    return application


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Operate the hosted landscaping pilot behind verified HTTPS-only managed ingress.",
        epilog=(
            "Required environment: PUBLIC_ORIGIN and LANDSCAPE_DATA_DIR. Optional PORT defaults to 10000. "
            "TRUSTED_PROXY_CIDRS defaults to empty (no forwarded-IP trust); set only to verified ingress "
            "peer IPs or narrow CIDRs after testing header handling and backend isolation."
        ),
    )
    parser.add_argument("command", choices=("provision", "preflight", "serve"), help=(
        "provision creates fictional accounts in empty storage once; preflight validates existing storage "
        "without starting a listener; serve reuses existing state and never seeds accounts."
    ))
    arguments = parser.parse_args(argv)
    os.umask(0o077)
    try:
        configuration = load_configuration()
        if arguments.command == "provision":
            handoff = provision(configuration)
            print(f"Fictional pilot provisioned. Open the private account handoff securely: {handoff}")
        elif arguments.command == "preflight":
            inspect_existing_storage(configuration)
            print("Existing pilot storage passed preflight; no listener started.")
        else:
            import uvicorn

            application = create_application(configuration)
            print("Starting the existing pilot behind the configured HTTPS-only ingress.", flush=True)
            uvicorn.run(
                application, host="0.0.0.0", port=configuration.port,
                workers=1, access_log=False, proxy_headers=False,
                forwarded_allow_ips="", server_header=False,
            )
    except (OSError, ValueError) as error:
        parser.exit(1, f"Pilot operation refused: {error}\n")


if __name__ == "__main__":
    main()
