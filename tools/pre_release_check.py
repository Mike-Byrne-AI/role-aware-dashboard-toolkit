from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

# The checker must not create the cache artifacts it is about to audit.
sys.dont_write_bytecode = True


REPO_ROOT = Path(__file__).resolve().parents[1]
JUNK_DIR_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
JUNK_SUFFIXES = {".pyc", ".pyo", ".pyd"}
_SECURITY_PLACEHOLDER_MARKERS = (
    "private coordination channel",
    "private maintainer channel",
    "keeps security intake private",
    "canonical public release coordinates",
    "official intake coordinates are published",
    "avoids placeholder public contact paths",
)
_PRE_OSS_BLOCKED_CHECK_IDS = ("oss_public_coordinates", "security_intake_contact")
_INTAKE_DOC_BLOCKED_STATE_MARKERS = (
    "pre-oss release state",
    "oss_public_coordinates",
    "security_intake_contact",
)
_PUBLIC_COORDINATE_PLACEHOLDER_MARKERS = (
    "example.",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "todo",
    "tbd",
    "placeholder",
    "replace-me",
    "changeme",
    "your-org",
    "your_org",
    "your-name",
    "your_name",
    "fake",
)
_SECURITY_REPORTING_CONTEXT_MARKERS = (
    "security",
    "vulnerab",
    "report",
    "disclosure",
    "incident",
    "psirt",
)
_SECURITY_EMAIL_HINT_MARKERS = ("security", "vulnerab", "disclosure", "incident", "psirt")
_SECURITY_URL_HINT_MARKERS = (
    "/security",
    "/vulnerab",
    "/disclosure",
    "/incident",
    "/report",
    "security.",
    "psirt",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run lightweight Role-Aware Dashboard Toolkit pre-release checks.")
    parser.add_argument("--json", action="store_true", help="Emit a structured JSON report.")
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Fail unless the Git working tree contains no tracked or untracked changes.",
    )
    args = parser.parse_args(argv)

    report = build_report(require_clean=args.require_clean)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_text_report(report)
    return 0 if report["ok"] else 1


def build_report(*, require_clean: bool = False) -> dict[str, Any]:
    sys.path.insert(0, str(REPO_ROOT))
    import role_aware_dashboard_toolkit as radt

    pyproject = _load_pyproject()
    checks = [
        _check_runtime_version(radt, pyproject),
        _check_changelog(radt),
        _check_release_audit_doc(radt),
        _check_release_checklist(),
        _check_public_coordinates(pyproject),
        _check_distribution_name_ownership(pyproject),
        _check_oss_intake_files(),
        _check_security_intake_contact(),
        _check_generated_cache_artifacts(),
    ]
    if require_clean:
        checks.append(_check_source_tree_clean())
    status = _overall_status(checks)
    blocked = [item["id"] for item in checks if item["status"] == "blocked"]
    failures = [item["id"] for item in checks if item["status"] == "fail"]
    warnings = [item["id"] for item in checks if item["status"] == "warn"]
    return {
        "ok": status == "pass",
        "status": status,
        "checks": checks,
        "blocked": blocked,
        "failures": failures,
        "warnings": warnings,
        "blocked_count": len(blocked),
        "failure_count": len(failures),
        "warning_count": len(warnings),
    }


def _load_pyproject() -> dict[str, Any]:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _check_runtime_version(radt: Any, pyproject: dict[str, Any]) -> dict[str, Any]:
    expected = str(pyproject.get("project", {}).get("version") or "")
    actual = str(getattr(radt, "__version__", ""))
    if actual == expected and actual:
        return _record("runtime_version", "pass", f"runtime and pyproject agree on {actual}")
    return _record("runtime_version", "fail", f"runtime={actual!r}, pyproject={expected!r}")


def _check_changelog(radt: Any) -> dict[str, Any]:
    version = str(getattr(radt, "__version__", ""))
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {version}" in changelog:
        return _record("changelog_version", "pass", f"CHANGELOG.md mentions {version}")
    return _record("changelog_version", "fail", f"CHANGELOG.md does not mention {version}")


def _check_release_audit_doc(radt: Any) -> dict[str, Any]:
    from role_aware_dashboard_toolkit.release_audit import build_release_audit_markdown

    expected = build_release_audit_markdown().strip()
    actual = (REPO_ROOT / "docs" / "release_audit.md").read_text(encoding="utf-8").strip()
    if actual == expected:
        return _record("release_audit_doc", "pass", "docs/release_audit.md matches generated release audit")
    return _record("release_audit_doc", "fail", "docs/release_audit.md differs from build_release_audit_markdown()")


def _check_release_checklist() -> dict[str, Any]:
    checklist = (REPO_ROOT / "docs" / "release_checklist.md").read_text(encoding="utf-8")
    required = [
        "py -3 -m pytest -q",
        "py -3 -m pytest -q --cov=role_aware_dashboard_toolkit --cov-report=term-missing --cov-fail-under=75",
        "py -3 -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache",
        "py -3 tools/pre_release_check.py --json --require-clean",
        "py -3 -m pip check",
        "`oss_public_coordinates`",
        "`distribution_name_ownership`",
        "`security_intake_contact`",
        "`failure_count` must remain `0`",
        "py -3 -m build",
        "Get-ChildItem -LiteralPath dist -File",
        "py @twineArgs",
        "`role_aware_dashboard_toolkit.release_audit.audit_release_artifact_members`",
        "private records and internal maintenance data",
        "temporary directories outside the repository",
        "SHA-256 digests",
    ]
    missing = [item for item in required if item not in checklist]
    if not missing:
        return _record("release_checklist_commands", "pass", "release checklist names maintained pre-release gates")
    return _record("release_checklist_commands", "fail", f"missing checklist commands: {', '.join(missing)}")


def _check_public_coordinates(pyproject: dict[str, Any]) -> dict[str, Any]:
    urls = dict(pyproject.get("project", {}).get("urls") or {})
    required = ("Repository", "Issues", "Documentation", "Homepage")
    missing = [key for key in required if not str(urls.get(key) or "").strip()]
    if missing:
        return _record(
            "oss_public_coordinates",
            "blocked",
            "missing real project URLs: " + ", ".join(missing),
            required_inputs=[
                "Repository URL",
                "Issues URL",
                "Documentation URL",
                "Homepage URL",
            ],
            remediation=(
                "Add real public project URLs under pyproject.toml [project.urls]. "
                "Do not use example, localhost, TODO, or placeholder hosts."
            ),
        )
    placeholders = [
        f"{key} ({reason})"
        for key in required
        if (reason := _public_coordinate_problem(str(urls.get(key) or "")))
    ]
    if placeholders:
        return _record(
            "oss_public_coordinates",
            "blocked",
            "placeholder or invalid project URLs: " + ", ".join(placeholders),
            required_inputs=[
                "Repository URL",
                "Issues URL",
                "Documentation URL",
                "Homepage URL",
            ],
            remediation=(
                "Replace placeholder or invalid project URLs with canonical public HTTP(S) coordinates."
            ),
        )
    return _record("oss_public_coordinates", "pass", "project URLs are present")


def _public_coordinate_problem(value: str) -> str:
    text = str(value or "").strip()
    lowered = text.lower()
    if not text:
        return "empty"
    if any(marker in lowered for marker in _PUBLIC_COORDINATE_PLACEHOLDER_MARKERS):
        return "placeholder"
    try:
        parsed = urlparse(text)
        hostname = (parsed.hostname or "").rstrip(".")
        _ = parsed.port  # Reject invalid or out-of-range explicit ports.
    except ValueError:
        return "invalid host"
    if parsed.scheme not in {"https", "http"}:
        return "not http(s)"
    if not hostname:
        return "missing public host"
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        if all(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]*)", part) for part in hostname.split(".")):
            return "invalid IP host"
        if "." not in hostname:
            return "missing public host"
    else:
        if not address.is_global or address.is_multicast:
            return "non-public IP host"
    return ""


def _check_distribution_name_ownership(pyproject: dict[str, Any]) -> dict[str, Any]:
    distribution_name = str(pyproject.get("project", {}).get("name") or "").strip()
    normalized_name = re.sub(r"[-_.]+", "-", distribution_name).lower()
    release_config = (
        pyproject.get("tool", {}).get("role_aware_dashboard_toolkit", {}).get("release", {})
    )
    if not isinstance(release_config, dict):
        release_config = {}
    verified_name = str(
        release_config.get("verified-distribution-name") or ""
    ).strip()
    normalized_verified_name = re.sub(r"[-_.]+", "-", verified_name).lower()

    if normalized_name and normalized_verified_name == normalized_name:
        return _record(
            "distribution_name_ownership",
            "pass",
            (
                f"configured distribution name {distribution_name!r} matches the "
                "recorded normalized PyPI availability or ownership verification"
            ),
        )
    if not normalized_name:
        return _record(
            "distribution_name_ownership",
            "blocked",
            "pyproject.toml does not define a distribution name",
            required_inputs=["publishable PyPI distribution name"],
        )
    return _record(
        "distribution_name_ownership",
        "blocked",
        (
            f"configured distribution name {distribution_name!r} has no matching "
            "PyPI availability or ownership verification"
        ),
        required_inputs=[
            f"verified availability or ownership for PyPI distribution name {distribution_name!r}"
        ],
        remediation=(
            "Verify the normalized name on PyPI and confirm the releasing account can "
            "publish it, then record the exact name under [tool.role_aware_dashboard_toolkit.release] "
            "verified-distribution-name."
        ),
    )


def _check_oss_intake_files() -> dict[str, Any]:
    required = ("SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md")
    missing = [path for path in required if not (REPO_ROOT / path).exists()]
    if missing:
        return _record("oss_intake_files", "blocked", "missing OSS intake files: " + ", ".join(missing))
    missing_markers: dict[str, list[str]] = {}
    for path in required:
        lowered = (REPO_ROOT / path).read_text(encoding="utf-8").lower()
        absent = [marker for marker in _INTAKE_DOC_BLOCKED_STATE_MARKERS if marker not in lowered]
        if absent:
            missing_markers[path] = absent
    if missing_markers:
        details = ", ".join(f"{path}: {', '.join(markers)}" for path, markers in missing_markers.items())
        return _record(
            "oss_intake_files",
            "fail",
            "OSS intake docs missing explicit pre-OSS blocked-state markers: " + details,
            remediation=(
                "Update SECURITY.md, CONTRIBUTING.md, and CODE_OF_CONDUCT.md to explicitly state "
                "that pre-OSS release remains blocked on "
                f"{_PRE_OSS_BLOCKED_CHECK_IDS[0]} and {_PRE_OSS_BLOCKED_CHECK_IDS[1]}."
            ),
        )
    return _record(
        "oss_intake_files",
        "pass",
        "OSS intake docs explicitly acknowledge pre-OSS blocked-state gates.",
    )


def _check_security_intake_contact() -> dict[str, Any]:
    security_path = REPO_ROOT / "SECURITY.md"
    if not security_path.exists():
        return _record(
            "security_intake_contact",
            "blocked",
            "SECURITY.md is missing",
            required_inputs=["monitored security reporting contact"],
            remediation=(
                "Add SECURITY.md with a real monitored security reporting contact path before publishing."
            ),
        )
    text = security_path.read_text(encoding="utf-8")
    lowered = text.lower()
    if any(marker in lowered for marker in _SECURITY_PLACEHOLDER_MARKERS):
        return _record(
            "security_intake_contact",
            "blocked",
            "SECURITY.md still uses private or placeholder intake wording; add a monitored public reporting contact.",
            required_inputs=["monitored security reporting contact"],
            remediation=(
                "Replace private or placeholder security intake wording in SECURITY.md "
                "with a real monitored public reporting path."
            ),
        )
    if not _has_monitored_security_reporting_contact(text):
        return _record(
            "security_intake_contact",
            "blocked",
            "SECURITY.md does not include an explicit monitored security reporting contact path.",
            required_inputs=["monitored security reporting contact"],
            remediation=(
                "Add a monitored security mailto/email or dedicated vulnerability reporting URL to SECURITY.md."
            ),
        )
    return _record("security_intake_contact", "pass", "SECURITY.md names a monitored security reporting contact")


def _has_monitored_security_reporting_contact(text: str) -> bool:
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if "mailto:" in lowered:
            for match in re.finditer(r"\bmailto:([^\s<>()\[\]`\"']*)", stripped, flags=re.IGNORECASE):
                target, _, query = match.group(1).partition("?")
                recipient_fields = [unquote(target)] if target else []
                recipient_fields.extend(
                    field
                    for name, fields in parse_qs(query, keep_blank_values=True).items()
                    if name.lower() in {"to", "cc", "bcc"}
                    for field in fields
                )
                recipients = [
                    recipient
                    for field in recipient_fields
                    for recipient in field.split(",")
                ]
                if recipients and _has_reporting_context(lowered) and all(
                    _looks_like_email(recipient)
                    and not _is_placeholder_contact_token(recipient)
                    for recipient in recipients
                ):
                    return True
            continue

        for token in stripped.replace("<", " ").replace(">", " ").split():
            cleaned = token.strip().strip("`.,;:()[]{}\"'")
            lowered_token = cleaned.lower()
            if _looks_like_email(cleaned):
                if _is_placeholder_contact_token(cleaned):
                    continue
                local = lowered_token.split("@", 1)[0]
                if any(marker in local for marker in _SECURITY_EMAIL_HINT_MARKERS):
                    return True
                if _has_reporting_context(lowered):
                    return True
            elif lowered_token.startswith(("https://", "http://")):
                if _public_coordinate_problem(cleaned):
                    continue
                if any(marker in lowered_token for marker in _SECURITY_URL_HINT_MARKERS):
                    return True
    return False


def _has_reporting_context(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in _SECURITY_REPORTING_CONTEXT_MARKERS)


def _looks_like_email(token: str) -> bool:
    if any(ord(char) < 32 or ord(char) == 127 for char in token):
        return False
    cleaned = token.strip().strip("`.,;:()[]{}\"'")
    if "@" not in cleaned or cleaned.count("@") != 1:
        return False
    if any(char.isspace() or char in "/\\:<>(),;" for char in cleaned):
        return False
    local, domain = cleaned.split("@", 1)
    return bool(local and "." in domain and all(domain.split(".")))


def _is_placeholder_contact_token(token: str) -> bool:
    lowered = str(token or "").strip().lower()
    return any(marker in lowered for marker in _PUBLIC_COORDINATE_PLACEHOLDER_MARKERS)


def _check_generated_cache_artifacts() -> dict[str, Any]:
    junk, scan_errors = _scan_generated_cache_artifacts()
    if scan_errors:
        preview = ", ".join(item["path"] for item in scan_errors[:10])
        suffix = (
            "" if len(scan_errors) <= 10 else f", ... +{len(scan_errors) - 10} more"
        )
        detail = f"generated/cache scan incomplete after walk errors: {preview}{suffix}"
        if junk:
            artifact_preview = ", ".join(junk[:10])
            artifact_suffix = (
                "" if len(junk) <= 10 else f", ... +{len(junk) - 10} more"
            )
            detail += f"; artifacts also present: {artifact_preview}{artifact_suffix}"
        return _record(
            "generated_cache_artifacts",
            "fail",
            detail,
            scan_errors=scan_errors,
            artifacts=junk,
        )
    if junk:
        preview = ", ".join(junk[:10])
        suffix = "" if len(junk) <= 10 else f", ... +{len(junk) - 10} more"
        return _record("generated_cache_artifacts", "fail", f"generated/cache artifacts present: {preview}{suffix}")
    return _record("generated_cache_artifacts", "pass", "no generated/cache artifacts found")


def _check_source_tree_clean() -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _record(
            "source_tree_clean",
            "fail",
            f"unable to verify Git source state ({type(exc).__name__})",
        )
    if result.returncode != 0:
        return _record(
            "source_tree_clean",
            "fail",
            f"git status failed with exit code {result.returncode}",
        )

    changes = [line for line in result.stdout.splitlines() if line.strip()]
    if changes:
        preview = ", ".join(changes[:10])
        suffix = "" if len(changes) <= 10 else f", ... +{len(changes) - 10} more"
        return _record(
            "source_tree_clean",
            "fail",
            f"working tree has {len(changes)} tracked or untracked changes: {preview}{suffix}",
            change_count=len(changes),
        )
    return _record(
        "source_tree_clean",
        "pass",
        "Git working tree is clean, including untracked files",
    )


def _scan_generated_cache_artifacts() -> tuple[list[str], list[dict[str, str]]]:
    found: list[str] = []
    scan_errors: list[dict[str, str]] = []
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "dist",
        "build",
        ".eggs",
        ".ruff_cache",
        ".pytest-runtime-tmp",
        ".wheel-smoke",
        ".wheel-smoke-win",
        ".wheel-extras-smoke",
        ".sdist-smoke",
        ".release-smoke",
        ".testpypi-smoke",
        ".pypi-smoke",
    }

    def record_walk_error(exc: OSError) -> None:
        filename = getattr(exc, "filename", None)
        error_path = Path(os.fsdecode(filename)) if filename else REPO_ROOT
        if not error_path.is_absolute():
            error_path = REPO_ROOT / error_path
        error_code = getattr(exc, "errno", None)
        code_suffix = (
            f" (errno {error_code})"
            if isinstance(error_code, int) and not isinstance(error_code, bool)
            else ""
        )
        scan_errors.append(
            {
                "path": _cache_scan_record_path(error_path),
                "reason": "walk_error",
                "message": (
                    f"{type(exc).__name__}: directory traversal failed{code_suffix}"
                ),
            }
        )

    for current_root, dirnames, filenames in os.walk(
        REPO_ROOT, topdown=True, onerror=record_walk_error
    ):
        current = Path(current_root)
        resolved_current = current.resolve(strict=False)
        if not resolved_current.is_relative_to(REPO_ROOT):
            continue
        rel_current = resolved_current.relative_to(REPO_ROOT)
        dirnames.sort()
        filenames.sort()
        kept_dirs: list[str] = []
        for dirname in dirnames:
            rel_dir = (rel_current / dirname).as_posix()
            if dirname in skip_dirs or dirname.endswith(".egg-info"):
                continue
            if dirname in JUNK_DIR_NAMES:
                found.append(rel_dir)
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in filenames:
            if Path(filename).suffix in JUNK_SUFFIXES:
                found.append((rel_current / filename).as_posix())
    scan_errors.sort(
        key=lambda item: (item["path"], item["reason"], item["message"])
    )
    return sorted(set(found)), scan_errors


def _cache_scan_record_path(path: Path) -> str:
    try:
        lexical_relative = path.relative_to(REPO_ROOT)
    except ValueError:
        lexical_relative = None
    if lexical_relative is not None and ".." not in lexical_relative.parts:
        return lexical_relative.as_posix() or "."
    try:
        resolved_path = path.resolve(strict=False)
    except OSError:
        return "<outside-root>"
    if resolved_path.is_relative_to(REPO_ROOT):
        return resolved_path.relative_to(REPO_ROOT).as_posix() or "."
    return "<outside-root>"


def _overall_status(checks: list[dict[str, str]]) -> str:
    statuses = {item["status"] for item in checks}
    if "fail" in statuses:
        return "fail"
    if "blocked" in statuses:
        return "blocked"
    if "warn" in statuses:
        return "warn"
    return "pass"


def _record(check_id: str, status: str, detail: str, **metadata: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": check_id, "status": status, "detail": detail}
    payload.update({key: value for key, value in metadata.items() if value not in (None, "", [])})
    return payload


def _print_text_report(report: dict[str, Any]) -> None:
    print(
        "Role-Aware Dashboard Toolkit pre-release status: "
        f"{report['status']} "
        f"(failures={report.get('failure_count', len(report.get('failures', [])))}, "
        f"blocked={report.get('blocked_count', len(report.get('blocked', [])))}, "
        f"warnings={report.get('warning_count', len(report.get('warnings', [])))})"
    )
    for item in report["checks"]:
        print(f"- {item['id']}: {item['status']} - {item['detail']}")


if __name__ == "__main__":
    raise SystemExit(main())
