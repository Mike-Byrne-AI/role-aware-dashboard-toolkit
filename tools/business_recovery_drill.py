"""Interactive recovery drill using a pinned official age release.

Only disposable fictional data is accepted: there is no runtime-directory or
target-URL option. Requires the platform's official age v1.3.2 release archive
and a new private output directory outside source. age owns private terminal prompts; use
a disposable test passphrase. No phrase is passed in argv or environment.
This exercises local encrypted full-application recovery, not hosted acceptance.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tarfile
import zipfile

# Assertions perform acceptance checks, including protected HTTP requests.
# Reject at import as well as CLI entry so no optimized caller can record a pass.
if not __debug__:
    raise SystemExit("This evidence runner requires assertions. Rerun without -O, -OO or PYTHONOPTIMIZE.")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/business_dashboard"))
AGE_VERSION = "v1.3.2"
# Pin archive digests published with the official release. Extraction admits
# only the native age binary, never paths or executables supplied by an archive.
ARCHIVES = {
    ("win32", "amd64"): ("age.exe", "f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7"),
    ("win32", "arm64"): ("age.exe", "fae351336c8d5f30f93cc3ccdec16d1ed7851d68cdd6656d41955cc31a447c9d"),
    ("linux", "amd64"): ("age", "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"),
    ("linux", "arm64"): ("age", "6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4"),
    ("darwin", "amd64"): ("age", "1d1e4bc66e1427edad7739ae7616157de0e79db8b6d2a1497d7d9925fb06a539"),
    ("darwin", "arm64"): ("age", "e2020b073c44f692685a24d6abc378817eb81ffaaf49fd0531ef8565f767f2f5"),
}
RELEASE_URL = "https://github.com/FiloSottile/age/releases/expanded_assets/v1.3.2"
ORIGIN = "http://127.0.0.1:8091"


def digest(path):
    with Path(path).open("rb") as stream:
        value = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def source_fingerprint():
    paths = [Path(__file__).resolve(), *sorted((ROOT / "examples/business_dashboard").rglob("*.py")),
             *(ROOT / "role_aware_dashboard_toolkit" / name for name in ("access.py", "access_store.py", "security.py"))]
    return {str(path.relative_to(ROOT)): digest(path) for path in paths}


@dataclass(frozen=True)
class DisposableFixture:
    runtime: Path
    key: Path
    custody_key: Path
    plaintext_zip: Path
    credentials: dict[str, str] = field(repr=False)
    previous_cookie: str = field(repr=False)
    replacement: str = field(repr=False)


def prepare_fixture(output):
    """Create only fictional state, without consulting hosted configuration."""
    import backup
    from business.app import create_app
    from business.db import Database, create_private_file
    from business.mfa import setup_admin_mfa
    from business.secret_store import create_key_file, default_key_path
    from business.security import COOKIE_NAME, hash_password
    from business.seed import provision
    from fastapi.testclient import TestClient

    runtime = output / "fictional-current"
    key = default_key_path(runtime)
    # Explicit creation and injection prevent a hosted Shell's ambient key
    # configuration from reading or reusing an actual application's secrets.
    create_key_file(runtime, key)
    credentials = provision(runtime, mfa_key_file=key)
    database = Database(runtime, mfa_key_file=key)
    with database.transaction() as connection:
        for index in range(600):
            body = "".join(hashlib.sha256(f"fictional-{index}-{part}".encode()).hexdigest() for part in range(40))
            connection.execute("INSERT INTO messages VALUES(?,?,?,?)", (f"drill-{index}", "alex", body, "2026-10-27T12:00:00+00:00"))
    # The explicit loopback origin also avoids hosted Turnstile configuration.
    with TestClient(create_app(runtime, public_origin=ORIGIN, mfa_key_file=key), base_url=ORIGIN) as client:
        login = client.post("/api/login", json={"username": "alex", "password": credentials["alex"]}, headers={"Origin": ORIGIN})
        assert login.status_code == 200, "Disposable initial login failed"
        previous_cookie = client.cookies.get(COOKIE_NAME)
    bundle = output / "backup"
    backup.create_backup(runtime, bundle, mfa_key_file=key)
    plaintext_zip = output / "backup.zip"
    with zipfile.ZipFile(plaintext_zip, "x", compression=zipfile.ZIP_STORED) as archive:
        if os.name == "posix":
            plaintext_zip.chmod(0o600)
        for name in (*backup.FILES, "manifest.json"):
            archive.write(bundle / name, name)
    assert plaintext_zip.stat().st_size > 1024 * 1024, "The full-bundle drill must exceed the sheet wrapper's cap"
    replacement = "Disposable restored login 93724!"
    with database.transaction() as connection:
        connection.execute("UPDATE users SET active=0,revision=revision+1 WHERE id='blair'")
        connection.execute("UPDATE users SET password_hash=?,revision=revision+1 WHERE id='alex'", (hash_password(replacement),))
        connection.execute("INSERT INTO login_limits VALUES('preserved-current-budget',12345,7)")
    setup_admin_mfa(runtime, reset=True, mfa_key_file=key)
    custody = output / "independent-key-custody"
    custody.mkdir(mode=0o700)
    create_private_file(custody / "mfa.key", key.read_bytes())
    return DisposableFixture(runtime, key, custody / "mfa.key", plaintext_zip,
                             credentials, previous_cookie, replacement)


def run(archive_path, output):
    architecture = {"amd64": "amd64", "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    selected = ARCHIVES.get((sys.platform, architecture))
    if selected is None:
        raise ValueError("No reviewed age release archive is pinned for this platform.")
    executable_name, archive_sha256 = selected
    if digest(archive_path) != archive_sha256:
        raise ValueError("Release archive checksum does not match the pinned official release.")
    source_hashes = source_fingerprint()
    import backup
    from business.app import create_app
    from business.db import create_private_file
    from business.security import COOKIE_NAME
    from fastapi.testclient import TestClient

    output = backup._new_directory(output)
    create_private_file(output / "source.json", json.dumps({
        "status": "started", "platform": sys.platform, "architecture": architecture,
        "official_release": RELEASE_URL, "official_archive_sha256": archive_sha256,
        "source_sha256": source_hashes,
    }, indent=2).encode() + b"\n")
    executable = output / executable_name
    if executable_name.endswith(".exe"):
        with zipfile.ZipFile(archive_path) as archive:
            create_private_file(executable, archive.read("age/age.exe"))
    else:
        with tarfile.open(archive_path, "r:gz") as archive:
            member = archive.getmember("age/age")
            if not member.isfile():
                raise ValueError("The verified archive does not contain the expected regular executable.")
            with archive.extractfile(member) as binary:
                create_private_file(executable, binary.read())
        executable.chmod(0o700)
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    if version != AGE_VERSION:
        raise ValueError("The release executable reported an unexpected version.")
    fixture = prepare_fixture(output)
    runtime, plaintext_zip = fixture.runtime, fixture.plaintext_zip

    print("Use a disposable test passphrase for age's encryption, confirmation, and decryption prompts.", flush=True)
    encrypted = output / "backup.zip.age"
    recovered_zip = output / "recovered.zip"
    subprocess.run([str(executable), "--encrypt", "--passphrase", "--output", str(encrypted), str(plaintext_zip)], check=True)
    subprocess.run([str(executable), "--decrypt", "--output", str(recovered_zip), str(encrypted)], check=True)
    assert digest(plaintext_zip) == digest(recovered_zip), "Authenticated recovered archive differs"
    extracted = output / "decrypted-bundle"
    extracted.mkdir(mode=0o700)
    with zipfile.ZipFile(recovered_zip) as archive:
        assert set(archive.namelist()) == {*backup.FILES, "manifest.json"}, "Unexpected archive members"
        for name in archive.namelist():
            create_private_file(extracted / name, archive.read(name))
    restored = output / "restored"
    result = backup.restore_backup(extracted, restored, mfa_key_file=fixture.custody_key, security_source=runtime)
    assert result == {"quarantined": False, "sessions_revoked": True, "frozen": True}
    with closing(sqlite3.connect(runtime / "business.sqlite3")) as current, closing(sqlite3.connect(restored / "business.sqlite3")) as recovered:
        for table in ("users", "admin_mfa", "mfa_key_binding", "passkey_credentials", "login_limits", "submission_limits"):
            assert current.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall() == recovered.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall(), "Current security reconciliation differs"
        for table in ("sessions", "session_mfa", "session_security", "session_passkey", "passkey_challenges"):
            assert recovered.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, "Historical session survived"
        assert recovered.execute("SELECT COUNT(*) FROM messages").fetchone()[0] >= 600
    application = create_app(restored, public_origin=ORIGIN, mfa_key_file=fixture.custody_key)
    with TestClient(application, base_url=ORIGIN) as client:
        assert client.get("/api/messages", headers={"Cookie": f"{COOKIE_NAME}={fixture.previous_cookie}"}).status_code == 401
        assert client.post("/api/login", json={"username": "alex", "password": fixture.credentials["alex"]}, headers={"Origin": ORIGIN}).status_code == 401
        login = client.post("/api/login", json={"username": "alex", "password": fixture.replacement}, headers={"Origin": ORIGIN})
        assert login.status_code == 200 and login.json()["frozen"] is True
        assert client.get("/api/messages").status_code == 200
        assert client.post("/api/messages", json={"body": "Frozen action must fail"}, headers={"Origin": ORIGIN, "X-CSRF-Token": login.json()["csrf"]}).status_code == 403
    with TestClient(application, base_url=ORIGIN) as client:
        assert client.post("/api/login", json={"username": "blair", "password": fixture.credentials["blair"]}, headers={"Origin": ORIGIN}).status_code == 401
    if source_hashes != source_fingerprint():
        raise ValueError("Source changed during the drill; preserve this run and repeat against a stable snapshot.")
    summary = {
        "status": "passed", "scope": "disposable recovery on the recorded platform; no hosted acceptance",
        "platform": sys.platform, "architecture": architecture,
        "age_version": version, "official_release": RELEASE_URL, "official_archive_sha256": archive_sha256,
        "age_executable_sha256": digest(executable), "archive_bytes": plaintext_zip.stat().st_size,
        "archive_sha256": digest(plaintext_zip), "ciphertext_sha256": digest(encrypted),
        "decrypted_archive_matches": True, "independent_mfa_key_custody_used": True,
        "synthetic_mfa_key_explicitly_created_and_injected": True,
        "current_credentials_disabled_accounts_mfa_and_budgets_preserved": True,
        "historical_sessions_and_old_password_rejected": True, "current_login_and_private_read_passed": True,
        "frozen_write_refused": True,
        "source_sha256": source_hashes,
    }
    create_private_file(output / "summary.json", json.dumps(summary, indent=2).encode() + b"\n")
    print("Disposable encrypted application recovery passed. Sanitized summary.json saved; retain the whole directory privately.")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-archive", type=Path, required=True, help="Official age v1.3.2 archive matching this OS and architecture")
    parser.add_argument("--output-dir", type=Path, required=True, help="New private directory outside every source/Git tree")
    args = parser.parse_args(argv)
    try:
        run(args.release_archive, args.output_dir)
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError, AssertionError, zipfile.BadZipFile, tarfile.TarError):
        print("Recovery drill failed. Preserve private outputs for investigation; no acceptance was recorded.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
