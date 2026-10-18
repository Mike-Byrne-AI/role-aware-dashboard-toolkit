"""Verify the shipped landscaping demo using a fresh installation and private data.

Run from a reviewed toolkit checkout. This is a local HTTP/POSIX release check,
not an external identity-provider, HTTPS, Windows integration, or browser check.
The supplied sdist is trusted executable code; archive validation prevents unsafe
extraction and verifies the reviewed release closure, not arbitrary code safety.
"""

from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


CHECKOUT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 4096
COVERAGE_BOUNDARY = {
    "included": ["POSIX", "fresh-sdist-install", "local-HTTP", "synthetic-accounts", "restart",
                 "hosted-startup-preflight", "hosted-checker-cli"],
    "excluded": ["HTTPS", "external-identity-provider", "Windows-WSL-integration", "browser", "production-restore"],
}


class SmokeFailure(RuntimeError):
    """A deliberately credential-free error suitable for release evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_output(path: Path, checkout: Path = CHECKOUT) -> Path:
    require(not path.is_symlink(), "Output must not be a symlink.")
    output = path.resolve()
    require(not output.is_relative_to(checkout.resolve()), "Output must be outside the checkout.")
    require(not output.exists() or (output.is_dir() and not any(output.iterdir())), "Output must be new or empty.")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    return output


def release_contract() -> tuple[str, set[str]]:
    # The controller uses the reviewed checkout contract, never archive code.
    sys.path.insert(0, str(CHECKOUT))
    try:
        from role_aware_dashboard_toolkit import release_audit
    finally:
        sys.path.pop(0)
    root = release_audit._SDIST_ROOT
    expected = {f"{root}/{name}" for name in release_audit._PUBLIC_PACKAGE_MEMBERS | release_audit._PUBLIC_SDIST_MEMBERS}
    return root, expected


def extract_sdist(sdist: Path, destination: Path, root: str, expected: set[str]) -> Path:
    require(sdist.is_file() and not sdist.is_symlink(), "Sdist must be a regular file.")
    require(sdist.stat().st_size <= MAX_ARCHIVE_BYTES, "Sdist exceeds the compressed size limit.")
    require(not destination.exists(), "Extraction directory already exists.")
    with tarfile.open(sdist, "r:gz") as archive:
        entries = []
        total = 0
        for entry in archive:
            require(len(entries) < MAX_MEMBERS, "Sdist contains too many members.")
            name = entry.name
            require(
                entry.isfile() and not entry.issparse()
                and name == str(PurePosixPath(name))
                and not name.startswith("/") and "\\" not in name and ":" not in name
                and all(part not in {"", ".", ".."} for part in name.split("/"))
                and all(ord(char) >= 32 and ord(char) != 127 for char in name),
                "Sdist contains an unsafe path or special member.",
            )
            require(0 <= entry.size <= MAX_MEMBER_BYTES, "Sdist member exceeds the size limit.")
            total += entry.size
            require(total <= MAX_EXPANDED_BYTES, "Sdist exceeds the expanded size limit.")
            entries.append(entry)
        names = [entry.name for entry in entries]
        require(len(names) == len(set(names)), "Sdist contains duplicate members.")
        require(set(names) == expected, "Sdist does not match the exact reviewed release closure.")
        require(all(name.startswith(root + "/") for name in names), "Sdist root does not match the release contract.")
        # Validate every member before writing any of them. Never honor archived
        # links, owner IDs, permissions, device types, or extraction metadata.
        destination.mkdir(mode=0o700)
        for entry in entries:
            path = destination / entry.name
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(archive.extractfile(entry)) as source, path.open("xb") as target:
                require(source is not None, "Sdist member could not be read.")
                shutil.copyfileobj(source, target)
    return destination / root


def clean_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "LANDSCAPE_DATA_DIR",
                 "PUBLIC_ORIGIN", "PORT", "TRUSTED_PROXY_CIDRS"):
        environment.pop(name, None)
    environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PIP_DISABLE_PIP_VERSION_CHECK="1")
    return environment


def stop_process(process: subprocess.Popen) -> None:
    # Every spawned process owns its group, including build-backend children.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def run_command(
    command: list[str], cwd: Path, *, label: str, timeout: float = 180,
    extra_environment: dict[str, str] | None = None, expected_returncode: int = 0,
) -> bytes:
    # Keep package-index diagnostics out of public receipts. They can contain
    # host configuration; command output is never copied into error messages.
    environment = clean_environment()
    environment.update(extra_environment or {})
    with tempfile.TemporaryFile() as stream:
        process = subprocess.Popen(
            command, cwd=cwd, env=environment, start_new_session=True,
            stdout=stream, stderr=subprocess.STDOUT,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop_process(process)
            raise SmokeFailure(f"{label} timed out.") from None
        finally:
            stop_process(process)
        require(process.returncode == expected_returncode, f"{label} failed; command diagnostics were withheld.")
        stream.seek(0)
        return stream.read()


class Client:
    def __init__(self, url: str):
        self.url = url
        self.opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))

    def request(self, path: str, *, method: str = "GET", body: dict | None = None, csrf: str = "", expected: int = 200) -> dict:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Origin": self.url, "X-CSRF-Token": csrf, "Content-Type": "application/json"}
        request = Request(self.url + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=3)
        except HTTPError as error:
            response = error
        with response:
            require(response.status == expected, f"HTTP check failed: {method} {path} returned {response.status}.")
            return json.loads(response.read())

    def change(self, path: str, body: dict, csrf: str = "", method: str = "POST") -> dict:
        return self.request(path, method=method, body=body, csrf=csrf)


LAUNCH_CODE = """
import pathlib, runpy, sys
import role_aware_dashboard_toolkit as toolkit
assert pathlib.Path(toolkit.__file__).resolve().is_relative_to(pathlib.Path(sys.prefix).resolve())
demo, data, port = sys.argv[1:]
sys.path.insert(0, demo)
sys.argv = [str(pathlib.Path(demo) / 'run.py'), '--data-dir', data, '--port', port]
runpy.run_path(sys.argv[0], run_name='__main__')
"""


@contextmanager
def server(python: Path, source: Path, data: Path, cwd: Path, log_path: Path, *, readiness_timeout: float = 30):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [str(python), "-I", "-c", LAUNCH_CODE, str(source / "examples/landscaping"), str(data), str(port)],
            cwd=cwd, env=clean_environment(), start_new_session=True, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + readiness_timeout
            client = Client(url)
            while time.monotonic() < deadline:
                require(process.poll() is None, "Demo exited before readiness.")
                try:
                    client.request("/api/session", expected=401)
                    break
                except (URLError, TimeoutError, ConnectionError):
                    time.sleep(0.1)
            else:
                raise SmokeFailure("Demo readiness timed out.")
            yield url
        finally:
            stop_process(process)


def snapshot(data: Path) -> tuple[dict, dict]:
    with closing(sqlite3.connect(f"{(data / 'landscape.sqlite3').as_uri()}?mode=ro", uri=True)) as connection:
        rows = {table: connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                for table in ("users", "jobs", "job_signups", "job_history", "customers", "messages", "settings")}
    private = {name: sha256(data / name) for name in ("identity.key", "TRIAL_ACCOUNTS.md")}
    return rows, private


def source_snapshot(source: Path) -> dict[str, str]:
    return {str(path.relative_to(source)): sha256(path) for path in source.rglob("*") if path.is_file()}


def check_runtime(python: Path, source: Path, output: Path, checks: list[str]) -> None:
    # No generated credentials, DBs, identity keys, or session data survive this
    # context. Server logs are inspected privately and never published verbatim.
    with tempfile.TemporaryDirectory(prefix="radt-landscape-private-") as temporary:
        fixture = Path(temporary)
        fixture.chmod(0o700)
        data = fixture / "data"
        first_log = fixture / "first.log"
        restart_log = fixture / "restart.log"
        with server(python, source, data, output, first_log) as url:
            sheet = (data / "TRIAL_ACCOUNTS.md").read_text(encoding="utf-8")
            passwords = dict(re.findall(r"\| `?([a-z]+)`? \| `([^`]+)` \|", sheet))
            require(set(passwords) == {"admin", "alex", "blair", "casey", "drew", "ellis"}, "Fresh fictional account set is incomplete.")
            require(len(set(passwords.values())) == 6, "Fresh passwords must be unique.")
            admin, worker = Client(url), Client(url)
            adm = admin.change("/api/login", {"username": "admin", "password": passwords["admin"]})
            wrk = worker.change("/api/login", {"username": "alex", "password": passwords["alex"]})
            csrf = adm["csrf_token"]
            worker.request("/api/admin/jobs", expected=403)
            checks.append("fresh-accounts-login-and-worker-admin-denial")
            job = worker.request("/api/jobs")["jobs"][0]
            worker.change(f"/api/jobs/{job['id']}/signup", {}, wrk["csrf_token"])
            worker.change("/api/messages", {"body": "Synthetic artifact restart verification"}, wrk["csrf_token"])
            path = f"/api/admin/jobs/{job['id']}"
            detail = admin.request(path)["job"]
            require(len(detail["crew"]) == 1, "Signup did not save the expected crew.")
            moved = admin.change(path + "/schedule", {
                "starts_at": (datetime.now(timezone.utc) + timedelta(days=8)).isoformat(),
                "expected_revision": detail["revision"], "reason": "Artifact schedule check",
            }, csrf, "PUT")["job"]
            cancelled = admin.change(path + "/status", {
                "status": "cancelled", "expected_revision": moved["revision"], "reason": "Artifact cancellation check",
            }, csrf)["job"]
            require(cancelled["lifecycle"] == "cancelled" and len(cancelled["crew"]) == 1, "Cancellation did not retain crew.")
            history = admin.request(path + "/history")["history"]
            require(history[0]["after"]["lifecycle"] == "cancelled", "Saved lifecycle history is missing.")
            worker.request(path + "/history", expected=403)
            require(job["id"] in {item["id"] for item in worker.request("/api/jobs?view=history")["jobs"]}, "Closed job is missing from the shared history view.")
            checks.append("signup-message-reschedule-cancellation-and-private-history")
            before = snapshot(data)
        with server(python, source, data, output, restart_log) as url:
            require(snapshot(data) == before, "Restart changed saved accounts, work, messages, history, settings, or identity material.")
            login = Client(url).change("/api/login", {"username": "alex", "password": passwords["alex"]})
            require(login["user"]["username"] == "alex", "Original worker password did not survive restart.")
        checks.append("restart-preserves-accounts-work-history-and-original-password")
        require(not any(password in log.read_text(encoding="utf-8", errors="replace") for log in (first_log, restart_log) for password in passwords.values()), "Launcher logs exposed a generated password; private diagnostics were discarded.")
        checks.append("launcher-logs-contain-no-generated-passwords")


def check_hosted_entrypoints(python: Path, source: Path, output: Path, checks: list[str]) -> None:
    # These are subprocesses running the shipped files and installed toolkit,
    # not imports from the checkout. No public listener or HTTPS claim is made.
    demo = source / "examples/landscaping"
    pilot = [str(python), "-I", str(demo / "hosting/pilot.py")]
    checker = [str(python), "-I", str(demo / "scripts/hosted_acceptance.py")]
    with tempfile.TemporaryDirectory(prefix="radt-hosted-artifact-private-") as temporary:
        fixture = Path(temporary)
        fixture.chmod(0o700)
        data = fixture / "data"
        environment = {"PUBLIC_ORIGIN": "https://landscaping.example.test", "LANDSCAPE_DATA_DIR": str(data)}
        diagnostics = []

        def operate(command: str, expected_returncode: int = 0) -> None:
            diagnostics.append(run_command(
                [*pilot, command], output, label=f"Shipped hosted {command}",
                extra_environment=environment, expected_returncode=expected_returncode, timeout=30,
            ))

        operate("preflight", 1)
        operate("serve", 1)
        require(not data.exists(), "Hosted startup initialized missing storage.")
        operate("provision")
        before = snapshot(data)
        require(len(before[0]["users"]) == 6, "Hosted provision did not create six fictional accounts.")
        operate("preflight")
        operate("provision", 1)
        require(snapshot(data) == before, "Hosted preflight or repeated provisioning changed saved state.")
        checks.append("hosted-provision-once-and-read-only-preflight-without-implicit-seeding")

        # A valid-length key from a different backup must fail before serving;
        # rejection must not replace the key or silently repair the database.
        (data / "identity.key").write_bytes(os.urandom(32))
        mismatched = snapshot(data)
        operate("serve", 1)
        require(snapshot(data) == mismatched, "Hosted startup changed mismatched identity storage.")
        checks.append("hosted-startup-refuses-mismatched-database-and-key-without-mutation")

        passwords = re.findall(r"\| `?[a-z]+`? \| `([^`]+)` \|", (data / "TRIAL_ACCOUNTS.md").read_text(encoding="utf-8"))
        require(len(passwords) == 6, "Hosted fictional account handoff is incomplete.")
        require(not any(password.encode() in item for password in passwords for item in diagnostics),
                "Hosted operation diagnostics exposed a generated password.")
        checks.append("hosted-operation-logs-contain-no-generated-passwords")

        run_command([*checker, "--help"], output, label="Shipped hosted checker help")
        receipt = fixture / "unexpected-receipt.json"
        run_command(
            [*checker, "--base-url", "http://127.0.0.1:1", "--output", str(receipt)],
            output, label="Shipped hosted checker plaintext rejection", expected_returncode=2,
        )
        require(not receipt.exists(), "Hosted checker accepted a plaintext origin.")
        checks.append("hosted-checker-cli-runs-and-rejects-plaintext-before-creating-evidence")


def smoke(sdist: Path, output: Path, checks: list[str]) -> dict:
    root, expected = release_contract()
    require(sdist.is_file() and not sdist.is_symlink(), "Sdist must be a regular file.")
    require(sdist.stat().st_size <= MAX_ARCHIVE_BYTES, "Sdist exceeds the compressed size limit.")
    artifact_hash = sha256(sdist)
    source = extract_sdist(sdist, output / "extracted", root, expected)
    pristine = source_snapshot(source)
    checks.append("safe-extraction-and-exact-release-closure")
    environment = output / "environment"
    run_command([sys.executable, "-I", "-m", "venv", str(environment)], output, label="Fresh environment creation")
    python = environment / "bin/python"
    run_command([str(python), "-I", "-m", "pip", "install", "--no-input", "--no-compile", f"{source}[api]", "-r", str(source / "examples/landscaping/requirements.txt")], output, label="Extracted sdist and demo dependency installation", timeout=300)
    run_command([str(python), "-I", "-m", "pip", "check"], output, label="Installed dependency check")
    probe = run_command([str(python), "-I", "-c", "import pathlib,sys; import role_aware_dashboard_toolkit as r; p=pathlib.Path(r.__file__).resolve(); assert p.is_relative_to(pathlib.Path(sys.prefix).resolve()); print(p)"], output, label="Isolated installed import check")
    imported = Path(probe.decode().strip())
    require(imported.is_relative_to(environment), "Toolkit import escaped the fresh environment.")
    checks.append("fresh-sdist-install-dependencies-and-isolated-toolkit-import")
    check_runtime(python, source, output, checks)
    check_hosted_entrypoints(python, source, output, checks)
    require(source_snapshot(source) == pristine, "Extracted public source changed during installation or execution.")
    require(sha256(sdist) == artifact_hash, "Sdist bytes changed during verification.")
    checks.append("public-source-pristine-and-artifact-bytes-unchanged")
    return {"artifact": {"filename": sdist.name, "sha256": artifact_hash},
            "toolkit_import": str(imported.relative_to(output)), "source_root": root}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdist", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    if os.name != "posix":
        parser.error("This demo verification requires POSIX; use Linux, macOS, or Windows WSL.")
    try:
        output = prepare_output(args.output_dir)
    except (OSError, SmokeFailure) as error:
        parser.error(str(error))
    receipt = {"passed": False, "checks": [], "coverage_boundary": COVERAGE_BOUNDARY}
    try:
        # Do not resolve away a symlink before the archive validation sees it.
        sdist = args.sdist.absolute()
        receipt.update(smoke(sdist, output, receipt["checks"]))
        receipt["passed"] = True
    except SmokeFailure as error:
        receipt["error"] = str(error)
    except Exception as error:
        receipt["error"] = f"Verification failed ({type(error).__name__}); private diagnostics were withheld."
    finally:
        (output / "summary.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
