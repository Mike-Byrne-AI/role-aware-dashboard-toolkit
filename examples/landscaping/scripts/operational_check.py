"""Verify local TLS and a disposable backup/restore drill with fictional data.

This harness never opens an existing installation. It is not a production backup
utility: it owns every server, private key, account and snapshot used here. The
only retained output is a fixed-schema, secret-free summary. Passing proves
loopback HTTPS and this recovery scenario, not a public host, external identity
provider, browser cookie enforcement, or Windows/WSL integration.
"""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
import http.cookiejar
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_ROOT))

from landscape.db import Database, _check_private, add_audit  # noqa: E402
from landscape.paths import validate_data_dir  # noqa: E402
from landscape.security import COOKIE_NAME, authenticate  # noqa: E402
from landscape.seed import seed_trial  # noqa: E402

SCOPE = "local_loopback_tls_and_disposable_restore"
STAGES = ("preflight", "tls", "backup", "revocation", "reconciliation", "restored_tls", "complete")
CHECKS = (
    "untrusted_certificate_rejected",
    "incorrect_certificate_hostname_rejected",
    "trusted_certificate_and_hostname_verified",
    "secure_httponly_strict_session_cookie",
    "secure_cookie_withheld_from_http",
    "worker_admin_route_denied",
    "csrf_and_cross_origin_writes_denied_without_effects",
    "freeze_denies_worker_write_without_effects",
    "saved_signup_message_and_history",
    "stopped_backup_preserves_database_key_and_account_sheet",
    "live_revocation_denies_session_and_password",
    "old_backup_resurrects_revoked_access_offline",
    "restore_reconciliation_invalidates_all_sessions",
    "restore_reconciliation_reapplies_revocation_and_freeze",
    "restored_accounts_password_hashes_and_saved_work_preserved",
    "restored_old_sessions_and_revoked_password_denied_over_tls",
    "restored_valid_accounts_sign_in_with_original_passwords",
    "restored_freeze_blocks_write_until_admin_review_and_resume",
)
PRIVATE_FILES = frozenset({"landscape.sqlite3", "identity.key", "TRIAL_ACCOUNTS.md"})
WORK_TABLES = ("jobs", "job_signups", "job_history", "messages", "customers")


class CheckFailed(RuntimeError):
    """Messages are fixed internal labels, never HTTP bodies or private paths."""


def require(condition: bool, label: str) -> None:
    if not condition:
        raise CheckFailed(label)


def output_directory(value: str | None) -> Path:
    """Refuse source storage, symlinks and reused evidence directories."""
    if value is None:
        parent = validate_data_dir(tempfile.gettempdir())
        return Path(tempfile.mkdtemp(prefix="radt-landscape-operations-", dir=parent))
    path = validate_data_dir(value)
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError("Operational output directory must be empty.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_private(path, directory=True)
    return path.resolve()


def write_summary(out: Path, *, stage: str, checks: list[str], success: bool) -> None:
    """Whitelist all output values; never serialize exceptions or runtime state."""
    if type(success) is not bool or stage not in STAGES or any(check not in CHECKS for check in checks):
        raise ValueError("Only known operational evidence labels may be written.")
    if len(checks) != len(set(checks)) or (success and (stage != "complete" or tuple(checks) != CHECKS)):
        raise ValueError("Operational evidence is incomplete or duplicated.")
    payload = {"scope": SCOPE, "success": success, "stage": stage, "checks": checks,
               "not_verified": ["public_host", "external_identity_provider", "browser_cookie_enforcement",
                                "windows_wsl", "production_backup_policy"]}
    destination = out / "summary.json"
    with destination.open("x", encoding="utf-8") as handle:
        os.chmod(destination, 0o600)
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _private_storage(path: Path) -> Path:
    path = validate_data_dir(path)
    _check_private(path, directory=True)
    require({p.name for p in path.iterdir()} == PRIVATE_FILES, "unexpected snapshot files")
    for name in PRIVATE_FILES:
        item = path / name
        _check_private(item)
        require(item.stat().st_nlink == 1, "hard-linked snapshot file")
    require(len((path / "identity.key").read_bytes()) == 32, "invalid snapshot identity key")
    with closing(sqlite3.connect(f"{(path / 'landscape.sqlite3').as_uri()}?mode=ro", uri=True)) as conn:
        require(conn.execute("PRAGMA integrity_check").fetchone() == ("ok",), "snapshot database integrity")
        require(conn.execute("PRAGMA foreign_key_check").fetchone() is None, "snapshot foreign keys")
    return path


def copy_private_snapshot(source: Path, destination: Path) -> None:
    """Copy this harness's offline snapshot to a new directory, never overwrite.

    The caller owns the fixture and must have stopped its server. SQLite sidecar
    files are refused rather than guessed at; the harness uses DELETE journals.
    This cannot detect arbitrary external database users and is not a general
    online backup command.
    """
    source = _private_storage(source)
    destination = validate_data_dir(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError("Snapshot destination must not already exist.")
    if source.resolve() in destination.resolve().parents:
        raise ValueError("Snapshot destination must be separate from its source.")
    destination.mkdir(mode=0o700)
    try:
        for name in PRIVATE_FILES:
            with (source / name).open("rb") as incoming, (destination / name).open("xb") as outgoing:
                os.fchmod(outgoing.fileno(), 0o600)
                shutil.copyfileobj(incoming, outgoing)
                outgoing.flush()
                os.fsync(outgoing.fileno())
        _private_storage(destination)
    except BaseException:
        shutil.rmtree(destination)
        raise


def saved_work(path: Path) -> dict[str, list[tuple]]:
    """Private in-memory comparison only; never included in report output."""
    with closing(sqlite3.connect(f"{(path / 'landscape.sqlite3').as_uri()}?mode=ro", uri=True)) as conn:
        return {table: sorted(conn.execute(f"SELECT * FROM {table}").fetchall()) for table in WORK_TABLES}


def accounts(path: Path) -> list[tuple]:
    with closing(sqlite3.connect(f"{(path / 'landscape.sqlite3').as_uri()}?mode=ro", uri=True)) as conn:
        return conn.execute(
            "SELECT id,username,display_name,password_hash,role,principal,created_at FROM users ORDER BY id"
        ).fetchall()


def reconcile_restore(path: Path, *, expected_key: bytes, revoked_username: str) -> None:
    """Apply known post-backup security decisions while this fixture is offline.

    Revoke every restored session, reapply the known worker revocation and freeze
    all writes atomically. Preserve work records for review before resuming. A
    real recovery must reconcile *all* post-backup security/business decisions;
    this one-worker scenario is deliberately not a general recovery interface.
    """
    path = _private_storage(path)
    if (path / "identity.key").read_bytes() != expected_key:
        raise ValueError("Restore identity key does not match the original.")
    database = Database(path)
    with database.transaction() as conn:
        user = conn.execute("SELECT id,role FROM users WHERE username=?", (revoked_username,)).fetchone()
        if user is None or user["role"] != "worker":
            raise ValueError("Restore drill requires a known worker revocation.")
        conn.execute("DELETE FROM sessions")
        conn.execute("UPDATE users SET active=0 WHERE id=?", (user["id"],))
        conn.execute("UPDATE settings SET frozen=1,freeze_revision=freeze_revision+1,changed_by='restore-drill' WHERE id=1")
        add_audit(conn, "restore-drill", "recovery.sessions_invalidated", "all sessions")
        add_audit(conn, "restore-drill", "recovery.account_revoked", revoked_username)
        add_audit(conn, "restore-drill", "recovery.frozen", "dashboard")


def make_certificate(directory: Path) -> tuple[Path, Path]:
    """A one-day disposable self-signed certificate trusted only by this client."""
    key, cert = directory / "tls.key", directory / "tls.crt"
    config = directory / "openssl.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
        "[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"
        "extendedKeyUsage=serverAuth\n", encoding="ascii",
    )
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", str(key), "-out", str(cert), "-config", str(config)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
    )
    key.chmod(0o600)
    return key, cert


_SERVER_CODE = """
import sys
import uvicorn
from landscape.app import create_app
uvicorn.run(create_app(sys.argv[1], secure_cookies=True, allowed_hosts=['127.0.0.1']),
            fd=int(sys.argv[4]), ssl_keyfile=sys.argv[2], ssl_certfile=sys.argv[3],
            access_log=False, proxy_headers=False, log_level='critical')
"""


@dataclass
class OwnedServer:
    directory: Path
    process: subprocess.Popen = field(repr=False)
    port: int

    def snapshot(self, destination: Path) -> None:
        if self.process.poll() is None:
            raise ValueError("Stop the owned server before taking its snapshot.")
        copy_private_snapshot(self.directory, destination)


@contextmanager
def serve(directory: Path, key: Path, cert: Path):
    # The parent binds a loopback socket before spawning; no free-port race and
    # no accidental public listen address. All child logs are discarded.
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        process = subprocess.Popen(
            [sys.executable, "-c", _SERVER_CODE, str(directory), str(key), str(cert), str(sock.fileno())],
            cwd=EXAMPLE_ROOT, pass_fds=(sock.fileno(),),
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        server = OwnedServer(directory, process, sock.getsockname()[1])
        try:
            client = Client(server.port, cert)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                require(process.poll() is None, "owned TLS server exited")
                try:
                    if client.request("GET", "/")[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(0.1)
            else:
                raise CheckFailed("owned TLS server startup deadline")
            yield server
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


class Client:
    def __init__(self, port: int, cert: Path, *, cookies=None, csrf=""):
        self.base = f"https://127.0.0.1:{port}"
        self.cookies = cookies if cookies is not None else http.cookiejar.CookieJar()
        self.csrf = csrf
        context = ssl.create_default_context(cafile=str(cert))
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=context),
        )

    def request(self, method: str, path: str, body=None, *, headers=None):
        request_headers = {"Origin": self.base}
        if self.csrf:
            request_headers["X-CSRF-Token"] = self.csrf
        request_headers.update(headers or {})
        data = None if body is None else json.dumps(body).encode("utf-8")
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=request_headers)
        try:
            response = self.opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            payload = json.loads(raw) if response.headers.get_content_type() == "application/json" else None
            return response.status, payload, response.headers

    def login(self, username: str, password: str):
        code, data, headers = self.request("POST", "/api/login", {"username": username, "password": password})
        require(code == 200, "fixture login")
        self.csrf = data["csrf_token"]
        return data, headers

    def token(self) -> str:
        return next(cookie.value for cookie in self.cookies if cookie.name == COOKIE_NAME)


def tls_probe(port: int, context: ssl.SSLContext, hostname: str) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as connection:
            require(connection.version() in ("TLSv1.2", "TLSv1.3"), "modern TLS protocol")
            require(bool(connection.getpeercert()), "verified peer certificate")


def _denied_tls_probe(port: int, context: ssl.SSLContext, hostname: str) -> None:
    try:
        tls_probe(port, context, hostname)
    except ssl.SSLCertVerificationError:
        return
    raise CheckFailed("invalid TLS certificate accepted")


def run(out: Path) -> None:
    """All private state is disposable; failure output contains only fixed labels."""
    checks: list[str] = []
    stage = "preflight"
    try:
        require(os.name == "posix", "POSIX or WSL required")
        require(shutil.which("openssl") is not None, "OpenSSL required")
        temp_parent = validate_data_dir(tempfile.gettempdir())
        with tempfile.TemporaryDirectory(prefix="radt-landscape-private-", dir=temp_parent) as temp:
            root = Path(temp)
            source, backup, restored = (root / name for name in ("source", "backup", "restored"))
            passwords = seed_trial(source)
            key, cert = make_certificate(root)
            identity_key = (source / "identity.key").read_bytes()
            stage = "tls"
            with serve(source, key, cert) as original:
                port = original.port
                _denied_tls_probe(port, ssl.create_default_context(), "127.0.0.1")
                checks.append(CHECKS[0])
                _denied_tls_probe(port, ssl.create_default_context(cafile=str(cert)), "wrong.invalid")
                checks.append(CHECKS[1])
                tls_probe(port, ssl.create_default_context(cafile=str(cert)), "127.0.0.1")
                checks.append(CHECKS[2])
                admin, worker, revoked = (Client(port, cert) for _ in range(3))
                admin_data, _ = admin.login("admin", passwords["admin"])
                worker_data, cookie_headers = worker.login("blair", passwords["blair"])
                revoked_data, _ = revoked.login("alex", passwords["alex"])
                # Keep this drill's later revocation limited to access changes.
                # Clear the fake departing worker's crew assignments through the
                # normal admin action before the backup, retaining their history.
                code, job_list, _ = admin.request("GET", "/api/admin/jobs")
                require(code == 200, "fixture crew review")
                revoked_id = revoked_data["user"]["id"]
                for job in job_list["jobs"]:
                    remaining = [member["id"] for member in job["crew"] if member["id"] != revoked_id]
                    if len(remaining) != len(job["crew"]):
                        require(admin.request("PUT", f"/api/admin/jobs/{job['id']}/crew", {
                            "worker_ids": remaining, "capacity": job["capacity"],
                            "expected_revision": job["revision"],
                        })[0] == 200, "fixture departing worker crew removal")
                cookie = SimpleCookie(cookie_headers["Set-Cookie"])[COOKIE_NAME]
                require(bool(cookie["secure"] and cookie["httponly"]) and cookie["samesite"].lower() == "strict"
                        and cookie["path"] == "/", "secure cookie attributes")
                checks.append(CHECKS[3])
                insecure = urllib.request.Request(f"http://127.0.0.1:{port}/api/session")
                worker.cookies.add_cookie_header(insecure)
                require(not insecure.has_header("Cookie"), "secure cookie withheld")
                checks.append(CHECKS[4])
                require(worker.request("GET", "/api/admin/health")[0] == 403, "worker admin denial")
                checks.append(CHECKS[5])
                before_denials = saved_work(source)
                require(worker.request("POST", "/api/messages", {"body": "Rejected fixture message"},
                                       headers={"X-CSRF-Token": "invalid"})[0] == 403, "CSRF denial")
                require(worker.request("POST", "/api/messages", {"body": "Rejected fixture message"},
                                       headers={"Origin": "https://foreign.invalid"})[0] == 403, "origin denial")
                require(saved_work(source) == before_denials, "denied writes unchanged")
                checks.append(CHECKS[6])
                code, frozen, _ = admin.request("POST", "/api/admin/freeze",
                    {"frozen": True, "expected_revision": admin_data["freeze_revision"]})
                require(code == 200 and frozen["frozen"], "freeze application")
                require(worker.request("POST", "/api/messages", {"body": "Rejected fixture message"})[0] == 403,
                        "frozen write denial")
                require(saved_work(source) == before_denials, "frozen write unchanged")
                checks.append(CHECKS[7])
                require(admin.request("POST", "/api/admin/freeze", {"frozen": False,
                        "expected_revision": frozen["freeze_revision"]})[0] == 200, "resume application")
                with closing(sqlite3.connect(source / "landscape.sqlite3")) as conn:
                    job_id = conn.execute("SELECT id FROM jobs WHERE id NOT IN "
                                          "(SELECT job_id FROM job_signups) ORDER BY id LIMIT 1").fetchone()[0]
                require(worker.request("POST", f"/api/jobs/{job_id}/signup", {})[0] == 200, "saved signup")
                require(worker.request("POST", "/api/messages", {"body": "Fictional recovery drill work note."})[0] == 200,
                        "saved message")
                require(saved_work(source)["job_history"], "saved job history")
                checks.append(CHECKS[8])
            stage = "backup"
            original.snapshot(backup)
            require(all((source / name).read_bytes() == (backup / name).read_bytes() for name in PRIVATE_FILES),
                    "complete stopped backup")
            original_accounts, original_work = accounts(backup), saved_work(backup)
            checks.append(CHECKS[9])
            stage = "revocation"
            with serve(source, key, cert) as live:
                current_admin = Client(live.port, cert, cookies=admin.cookies, csrf=admin.csrf)
                current_revoked = Client(live.port, cert, cookies=revoked.cookies, csrf=revoked.csrf)
                require(current_admin.request("PATCH", f"/api/admin/users/{revoked_data['user']['id']}",
                                              {"active": False})[0] == 200, "live account revocation")
                require(current_revoked.request("GET", "/api/session")[0] == 401, "live revoked session")
                require(Client(live.port, cert).request("POST", "/api/login",
                        {"username": "alex", "password": passwords["alex"]})[0] == 401, "live revoked password")
                checks.append(CHECKS[10])
            require(saved_work(source) == original_work, "no unreconciled post-backup work changes")
            stage = "reconciliation"
            copy_private_snapshot(backup, restored)
            restored_db = Database(restored)
            # Intentionally inspect the unsafe old state *offline*, without ever
            # opening a restored listener before reconciliation.
            with restored_db.transaction() as conn:
                context = authenticate(conn, revoked.token(), restored_db.identity_key)
                context.authorize("can_view_work")
                require(context.user["username"] == "alex", "backup restores old access")
            checks.append(CHECKS[11])
            reconcile_restore(restored, expected_key=identity_key, revoked_username="alex")
            with restored_db.transaction() as conn:
                require(conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0, "restored sessions invalidated")
                checks.append(CHECKS[12])
                require(conn.execute("SELECT active FROM users WHERE username='alex'").fetchone()[0] == 0
                        and conn.execute("SELECT frozen FROM settings WHERE id=1").fetchone()[0] == 1,
                        "restored revocation and freeze")
                checks.append(CHECKS[13])
            require(accounts(restored) == original_accounts and saved_work(restored) == original_work
                    and (restored / "identity.key").read_bytes() == identity_key,
                    "restore retains accounts key and work")
            checks.append(CHECKS[14])
            stage = "restored_tls"
            with serve(restored, key, cert) as recovered:
                for old in (admin, worker, revoked):
                    stale = Client(recovered.port, cert, cookies=old.cookies, csrf=old.csrf)
                    require(stale.request("GET", "/api/session")[0] == 401, "restored old session denied")
                require(Client(recovered.port, cert).request("POST", "/api/login",
                        {"username": "alex", "password": passwords["alex"]})[0] == 401, "restored revoked password")
                checks.append(CHECKS[15])
                recovered_admin, recovered_worker = (Client(recovered.port, cert) for _ in range(2))
                recovery_state, _ = recovered_admin.login("admin", passwords["admin"])
                recovered_worker.login("blair", passwords["blair"])
                require(recovered_worker.request("GET", "/api/jobs")[0] == 200
                        and recovered_worker.request("GET", "/api/messages")[0] == 200, "restored saved views")
                require(saved_work(restored) == original_work, "restored views preserve saved work")
                checks.append(CHECKS[16])
                require(recovery_state["frozen"] and recovered_worker.request("POST", "/api/messages",
                        {"body": "Rejected while recovery review is pending."})[0] == 403, "restored freeze denial")
                require(saved_work(restored) == original_work, "restored frozen write unchanged")
                # Review passed above for this fake fixture. In a real recovery
                # an operator must reconcile every later security/business event.
                require(recovered_admin.request("POST", "/api/admin/freeze", {"frozen": False,
                        "expected_revision": recovery_state["freeze_revision"]})[0] == 200, "reviewed recovery resume")
                require(recovered_worker.request("POST", "/api/messages",
                        {"body": "Fictional recovery review complete."})[0] == 200, "recovered write")
                checks.append(CHECKS[17])
            stage = "complete"
    except BaseException:
        write_summary(out, stage=stage, checks=checks, success=False)
        raise
    write_summary(out, stage=stage, checks=checks, success=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", help="New or empty private directory outside the source tree; defaults to temporary storage.")
    args = parser.parse_args()
    try:
        out = output_directory(args.output_dir)
    except (OSError, ValueError):
        print("Operational output refused: choose an empty private directory outside the source tree.", file=sys.stderr)
        return 1
    try:
        run(out)
    except (Exception, KeyboardInterrupt):
        print("Operational checks failed. Inspect summary.json for the stage; private details were not emitted.", file=sys.stderr)
        return 1
    print(f"Passed {len(CHECKS)} local TLS and recovery checks. Evidence: {out / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
