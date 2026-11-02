"""Bounded, secret-free security receipts; checksums are not signatures.

Receipts are operator-supplied observations, never authorization or a security
certification. Only fixed check labels are exported. Runtime data, credentials,
exception messages, hostnames and filesystem paths have no schema fields.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from uuid import UUID, uuid4

MAX_BYTES = 128 * 1024
MAX_CHECKS = 512
MODES = frozenset({"scenarios", "browser", "challenge", "save", "admin_tools",
                   "password_faults", "safe_saves", "security", "passkeys", "lab"})
DEPENDENCIES = ("fastapi", "starlette", "httpx", "pydantic", "pyotp", "cryptography",
                "webauthn", "playwright")
CHECKS = {
    "revoke_initial_access": "Host: the disposable employee session initially has access",
    "revoke_other_session": "Host: a separate session revokes the selected session",
    "revoke_next_request": "Host: the revoked session's next write is rejected",
    "revoke_no_business_change": "Host: the rejected write leaves business records unchanged",
    "revoke_legitimate_control": "Host: the remaining authorized session can still write",
    "cas_shared_revision": "Toolkit API: separate apps read the same initial revision",
    "cas_one_winner": "Toolkit API: competing writes produce one success and one conflict",
    "cas_one_commit": "Toolkit API: only the winning value and one audit event are committed",
    "cas_fresh_control": "Toolkit API: a reviewed fresh revision can be saved",
    "restore_historical_record": "Host: the backup restores the historical business record",
    "restore_old_session_denied": "Host: the restored workspace rejects the historical session",
    "restore_disabled_user_denied": "Host: restoring data does not reactivate a disabled account",
    "restore_current_access": "Host: current authorized credentials still permit a private read",
    "restore_remains_frozen": "Host: restored business writes remain paused",
}
ERROR_CODES = frozenset({"assertion_failed", "execution_error", "source_changed", "interrupted"})
SOURCE_SUFFIXES = frozenset({".py", ".js", ".css", ".html", ".toml", ".yml", ".yaml"})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _title(identifier):
    if identifier in CHECKS:
        return CHECKS[identifier]
    if identifier == "browser_workflow_complete":
        return "Browser workflow completed"
    if isinstance(identifier, str) and re.fullmatch(r"browser_step_[0-9]{3}", identifier):
        number = int(identifier[-3:])
        if 1 <= number <= MAX_CHECKS:
            return f"Local browser acceptance check {number}"
    raise ValueError("Security receipt is invalid.")


def source_fingerprint(root=None):
    """Hash reviewed source bytes, including dirty files; never runtime files.

    Paths are used only inside the digest. The public receipt exposes a count,
    aggregate hash and optional Git identity. A source archive works without Git.
    """
    root = Path(root) if root is not None else Path(__file__).resolve().parents[3]
    candidates = []
    for relative in ("role_aware_dashboard_toolkit", "examples/business_dashboard", ".github/workflows"):
        base = root / relative
        if base.is_dir():
            candidates.extend(path for path in base.rglob("*") if path.is_file()
                              and not path.is_symlink() and path.suffix in SOURCE_SUFFIXES
                              and not {"__pycache__", ".pytest_cache", ".venv"}.intersection(path.parts))
    for relative in ("pyproject.toml", "tools/business_dashboard_browser.py",
                     "tools/business_security_demo.py", "tools/business_dashboard_fuzz.py",
                     "tools/business_recovery_drill.py", "examples/business_dashboard/requirements.txt",
                     "examples/business_dashboard/business/password_data/common-passwords.txt.gz",
                     "examples/business_dashboard/business/password_data/SOURCE.txt",
                     "examples/business_dashboard/SECURITY_LAB.md", "examples/business_dashboard/SECURITY_DESIGN.md",
                     "tests/conftest.py", "tests/test_state_store.py", "tests/test_security_evidence.py"):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            candidates.append(path)
    for pattern in ("test_business*.py", "test_api*.py"):
        candidates.extend(path for path in (root / "tests").glob(pattern) if path.is_file() and not path.is_symlink())
    digest = hashlib.sha256()
    paths = sorted(set(candidates), key=lambda path: path.relative_to(root).as_posix())
    if not paths:
        raise ValueError("Security evidence source is unavailable.")
    for path in paths:
        digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    commit, dirty = None, None
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                              text=True, timeout=5, check=True).stdout.strip()
        changes = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"],
                                 cwd=root, capture_output=True, text=True, timeout=5, check=True).stdout
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
            commit, dirty = head, bool(changes.strip())
    except (OSError, subprocess.SubprocessError):
        pass  # Source byte identity remains available in a non-Git installation.
    return {"sha256": digest.hexdigest(), "files": len(paths), "git_commit": commit, "dirty": dirty}


def new_receipt(mode, checks, *, root=None):
    if mode not in MODES:
        raise ValueError("Security receipt mode is invalid.")
    versions = {}
    for name in DEPENDENCIES:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        if re.fullmatch(r"[A-Za-z0-9.!+_-]{1,80}", version):
            versions[name] = version
    return {
        "schema_version": 1, "receipt_id": str(uuid4()), "mode": mode,
        "scope": "local_scenarios" if mode == "scenarios" else "local_browser",
        "started_at": _now(), "finished_at": None, "status": "not_run",
        "source": source_fingerprint(root), "source_unchanged": None,
        "runtime": {"python": platform.python_version(), "platform": sys.platform,
                    "dependencies": versions, "browser": None},
        "checks": [{"id": key, "title": _title(key), "status": "not_run"} for key in checks],
        "error": None,
    }


def safe_error(error):
    """Classify errors without copying class names, paths or secret messages."""
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        return {"type": "Interrupted", "code": "interrupted"}
    if isinstance(error, AssertionError):
        return {"type": "AssertionError", "code": "assertion_failed"}
    return {"type": "ExecutionError", "code": "execution_error"}


def finish_receipt(receipt, *, root=None, error=None, browser=None):
    receipt["finished_at"] = _now()
    receipt["runtime"]["browser"] = browser
    receipt["error"] = safe_error(error) if error is not None else None
    try:
        receipt["source_unchanged"] = receipt["source"]["sha256"] == source_fingerprint(root)["sha256"]
    except (OSError, ValueError):
        receipt["source_unchanged"] = False
    if not receipt["source_unchanged"]:
        receipt["error"] = {"type": "SourceChanged", "code": "source_changed"}
    complete = bool(receipt["checks"]) and all(row["status"] == "passed" for row in receipt["checks"])
    receipt["status"] = "passed" if complete and receipt["error"] is None else "failed"
    if receipt["status"] == "failed" and receipt["error"] is None:
        receipt["error"] = {"type": "ExecutionError", "code": "execution_error"}
    receipt.pop("sha256", None)
    receipt["sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return validate_receipt(receipt)


def finish_browser_receipt(receipt, completed_checks, *, completed, root=None, error=None, browser=None):
    """Publish no free-text browser diagnostics; retain workflow completion."""
    if type(completed_checks) is not int or not 0 <= completed_checks < MAX_CHECKS:
        raise ValueError("Security receipt check count is invalid.")
    receipt["checks"] = [
        {"id": f"browser_step_{index:03}", "title": _title(f"browser_step_{index:03}"),
         "status": "passed"}
        for index in range(1, completed_checks + 1)
    ]
    receipt["checks"].append({"id": "browser_workflow_complete", "title": _title("browser_workflow_complete"),
                              "status": "passed" if completed else "failed"})
    return finish_receipt(receipt, root=root, error=error, browser=browser)


def validate_receipt(value):
    """Validate a bounded exact schema and return a detached safe projection."""
    def require(condition):
        if not condition:
            raise ValueError("Security receipt is invalid.")

    try:
        encoded = _canonical(value)
        require(len(encoded) <= MAX_BYTES and isinstance(value, dict))
        require(set(value) == {"schema_version", "receipt_id", "mode", "scope", "started_at",
                               "finished_at", "status", "source", "source_unchanged", "runtime",
                               "checks", "error", "sha256"})
        require(type(value["schema_version"]) is int and value["schema_version"] == 1)
        require(str(UUID(value["receipt_id"])) == value["receipt_id"])
        require(value["mode"] in MODES)
        require(value["scope"] == ("local_scenarios" if value["mode"] == "scenarios" else "local_browser"))
        for field in ("started_at", "finished_at"):
            require(isinstance(value[field], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value[field]))
            datetime.fromisoformat(value[field].replace("Z", "+00:00"))
        require(value["finished_at"] >= value["started_at"])
        require(value["status"] in {"passed", "failed", "not_run"})
        require(type(value["source_unchanged"]) is bool)
        source = value["source"]
        require(isinstance(source, dict) and set(source) == {"sha256", "files", "git_commit", "dirty"})
        require(isinstance(source["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", source["sha256"]))
        require(type(source["files"]) is int and 1 <= source["files"] <= 10000)
        require(source["git_commit"] is None or isinstance(source["git_commit"], str)
                and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source["git_commit"]))
        require(source["dirty"] is None or type(source["dirty"]) is bool)
        runtime = value["runtime"]
        require(isinstance(runtime, dict) and set(runtime) == {"python", "platform", "dependencies", "browser"})
        require(isinstance(runtime["python"], str) and re.fullmatch(r"\d{1,2}\.\d{1,2}\.\d{1,3}", runtime["python"]))
        require(runtime["platform"] in {"win32", "linux", "darwin", "freebsd", "openbsd"})
        dependencies = runtime["dependencies"]
        require(isinstance(dependencies, dict) and set(dependencies) <= set(DEPENDENCIES))
        require(all(isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9.!+_-]{1,80}", version)
                    for version in dependencies.values()))
        browser = runtime["browser"]
        require(browser is None or isinstance(browser, dict) and set(browser) == {"name", "version"})
        if browser is not None:
            require(browser["name"] in {"chromium", "chrome", "msedge"})
            require(isinstance(browser["version"], str) and re.fullmatch(r"[0-9.]{1,80}", browser["version"]))
        checks = value["checks"]
        require(isinstance(checks, list) and 1 <= len(checks) <= MAX_CHECKS)
        seen = set()
        for row in checks:
            require(isinstance(row, dict) and set(row) == {"id", "title", "status"})
            require(row["id"] not in seen)
            seen.add(row["id"])
            require(row["title"] == _title(row["id"]))
            require((row["id"] in CHECKS) == (value["mode"] == "scenarios"))
            require(row["status"] in {"passed", "failed", "not_run"})
        if value["mode"] == "scenarios":
            require(seen == set(CHECKS))
        else:
            require("browser_workflow_complete" in seen)
        error = value["error"]
        require(error is None or isinstance(error, dict) and set(error) == {"type", "code"})
        if error is not None:
            require(error["code"] in ERROR_CODES)
            require(error["type"] == {"assertion_failed": "AssertionError", "execution_error": "ExecutionError",
                                      "source_changed": "SourceChanged", "interrupted": "Interrupted"}[error["code"]])
        if value["status"] == "passed":
            require(error is None and value["source_unchanged"] is True
                    and all(row["status"] == "passed" for row in checks))
            require(value["mode"] == "scenarios" or browser is not None)
        elif value["status"] == "not_run":
            require(error is None and all(row["status"] == "not_run" for row in checks))
        else:
            require(error is not None or any(row["status"] == "failed" for row in checks))
        if value["source_unchanged"] is False:
            require(value["status"] == "failed" and error == {"type": "SourceChanged", "code": "source_changed"})
        digest = value["sha256"]
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest))
        require(digest == hashlib.sha256(_canonical({key: item for key, item in value.items() if key != "sha256"})).hexdigest())
        return json.loads(encoded)
    except (TypeError, KeyError, ValueError, OverflowError, RecursionError, AttributeError):
        raise ValueError("Security receipt is invalid.") from None


def load_receipt(path):
    """Read a single bounded receipt without following arbitrary nested input."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Security receipt is invalid.")
            result[key] = value
        return result

    try:
        with Path(path).open("rb") as stream:
            encoded = stream.read(MAX_BYTES + 1)
        if len(encoded) > MAX_BYTES:
            raise ValueError
        return validate_receipt(json.loads(encoded, object_pairs_hook=unique))
    except (OSError, ValueError, RecursionError, UnicodeError):
        raise ValueError("Security receipt is unavailable or invalid.") from None


def public_receipt(value):
    """Only the exact safe schema is exportable; never forward unknown fields."""
    return validate_receipt(value)


def write_receipt(path, value):
    """Create a private receipt exclusively; preserve every earlier result."""
    encoded = json.dumps(validate_receipt(value), indent=2).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
