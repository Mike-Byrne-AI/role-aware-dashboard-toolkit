"""Audit resolved runtime dependencies without installing audit tools into the target.

Use a fresh virtual environment containing the built toolkit wheel and its desired
extra, and a separate environment containing pip-audit. Evidence directories must
be new or empty. Exit codes: 0 complete/clean, 1 known vulnerabilities, 2 incomplete
or failed audit. This checks published advisories, not application exploitability.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

TOOLKIT = "role-aware-dashboard-toolkit"
EXCLUSIONS = {
    TOOLKIT: "The locally built toolkit is not published on PyPI.",
    "pip": "Environment installation tooling, not a toolkit runtime dependency.",
    "setuptools": "Environment installation tooling, not a toolkit runtime dependency.",
    "wheel": "Environment installation tooling, not a toolkit runtime dependency.",
}
_INVENTORY_CODE = """
import importlib.metadata
import json
import sys
print(json.dumps({
    "isolated_venv": sys.prefix != sys.base_prefix,
    "python": sys.version,
    "packages": [{"name": item.metadata["Name"], "version": item.version}
                 for item in importlib.metadata.distributions()],
}))
"""


class AuditError(ValueError):
    """The audit cannot establish complete coverage of the target environment."""


def _package_name(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", value
    ):
        raise AuditError("Invalid package name in audit evidence.")
    return re.sub(r"[-_.]+", "-", value).lower()


def resolved_requirements(inventory: Any) -> dict[str, str]:
    """Select the exact runtime distribution versions, with explicit exclusions."""
    if not isinstance(inventory, dict) or inventory.get("isolated_venv") is not True:
        raise AuditError("The target must be a virtual environment.")
    packages = inventory.get("packages")
    if not isinstance(packages, list):
        raise AuditError("Target package inventory is missing or malformed.")
    resolved = {}
    for package in packages:
        if not isinstance(package, dict):
            raise AuditError("Malformed package in target inventory.")
        name = _package_name(package.get("name"))
        version = package.get("version")
        if not isinstance(version, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", version
        ):
            raise AuditError(f"Invalid resolved version for {name}.")
        if name in resolved:
            raise AuditError(f"Duplicate installed distribution: {name}.")
        resolved[name] = version
    if TOOLKIT not in resolved:
        raise AuditError("The target environment does not contain the toolkit.")
    dependencies = {
        name: version
        for name, version in sorted(resolved.items())
        if name not in EXCLUSIONS
    }
    if not dependencies:
        raise AuditError(
            "No third-party runtime dependencies found; install the api or full extra."
        )
    return dependencies


def assess_report(
    report: Any, expected: dict[str, str], returncode: int
) -> dict[str, Any]:
    """Require complete version coverage, including no skipped dependencies."""
    if not expected:
        raise AuditError(
            "An empty dependency set cannot establish runtime audit coverage."
        )
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise AuditError("pip-audit JSON has no valid dependencies array.")
    if report.get("fixes") != []:
        raise AuditError("Unexpected or malformed fix results in a read-only audit.")
    audited = {}
    vulnerabilities = 0
    for package in report["dependencies"]:
        if not isinstance(package, dict):
            raise AuditError("Malformed dependency in pip-audit JSON.")
        name = _package_name(package.get("name"))
        if "skip_reason" in package:
            raise AuditError(
                f"pip-audit skipped dependency {name}: {package['skip_reason']}"
            )
        if name in audited:
            raise AuditError(f"Duplicate dependency in pip-audit JSON: {name}.")
        version = package.get("version")
        if not isinstance(version, str) or expected.get(name) != version:
            raise AuditError(
                f"Unexpected package or version in pip-audit JSON: {name}."
            )
        vulns = package.get("vulns")
        if not isinstance(vulns, list):
            raise AuditError(f"Missing or malformed vulnerability results for {name}.")
        for vuln in vulns:
            if (
                not isinstance(vuln, dict)
                or not isinstance(vuln.get("id"), str)
                or not vuln["id"].strip()
                or not isinstance(vuln.get("fix_versions"), list)
                or not all(
                    isinstance(version, str) and version
                    for version in vuln["fix_versions"]
                )
            ):
                raise AuditError(f"Malformed vulnerability record for {name}.")
        vulnerabilities += len(vulns)
        audited[name] = version
    if audited != expected:
        missing = ", ".join(sorted(set(expected) - set(audited)))
        raise AuditError(
            f"pip-audit report does not cover all resolved dependencies; missing: {missing}."
        )
    expected_code = 1 if vulnerabilities else 0
    if returncode != expected_code:
        raise AuditError(
            f"pip-audit exit code {returncode} disagrees with the complete JSON results."
        )
    return {
        "status": "vulnerabilities_found" if vulnerabilities else "clean",
        "audited_packages": len(audited),
        "vulnerabilities": vulnerabilities,
        "exit_code": expected_code,
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _run_logged(
    command: list[str], report_dir: Path, label: str, timeout: int
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        for suffix, output in (("stdout", exc.stdout), ("stderr", exc.stderr)):
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            (report_dir / f"{label}.{suffix}.log").write_text(
                output or "", encoding="utf-8"
            )
        raise AuditError(f"{label} timed out after {timeout} seconds.") from exc
    (report_dir / f"{label}.stdout.log").write_text(result.stdout, encoding="utf-8")
    (report_dir / f"{label}.stderr.log").write_text(result.stderr, encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        required=True,
        type=Path,
        help="Fresh runtime virtual environment's interpreter.",
    )
    parser.add_argument(
        "--audit-python",
        required=True,
        type=Path,
        help="Separate interpreter with pip-audit installed.",
    )
    parser.add_argument(
        "--report-dir",
        required=True,
        type=Path,
        help="New or empty directory for all audit evidence.",
    )
    args = parser.parse_args(argv)
    report_dir = args.report_dir.resolve()
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        if any(report_dir.iterdir()):
            raise AuditError(
                "Use a new or empty report directory; previous evidence must not be overwritten."
            )
    except (OSError, AuditError) as exc:
        print(f"Dependency audit failed: {exc}", file=sys.stderr)
        return 2

    summary: dict[str, Any] = {
        "status": "audit_failed",
        "exit_code": 2,
        "exclusions": EXCLUSIONS,
    }
    try:
        # Keep the venv launcher path: on POSIX both launchers can be symlinks
        # to the same base interpreter, but their enclosing pyvenv.cfg differs.
        runtime_python = args.python.absolute()
        audit_python = args.audit_python.absolute()
        if runtime_python == audit_python:
            raise AuditError(
                "Runtime and audit interpreters must use separate environments."
            )
        inventory_run = _run_logged(
            [str(runtime_python), "-I", "-c", _INVENTORY_CODE],
            report_dir,
            "inventory",
            60,
        )
        if inventory_run.returncode:
            raise AuditError(
                f"Target inventory failed with exit code {inventory_run.returncode}."
            )
        inventory = json.loads(inventory_run.stdout)
        _write_json(report_dir / "inventory.json", inventory)
        dependencies = resolved_requirements(inventory)
        summary["resolved_packages"] = len(dependencies)
        requirements_path = report_dir / "requirements.txt"
        requirements_path.write_text(
            "".join(f"{name}=={version}\n" for name, version in dependencies.items()),
            encoding="utf-8",
        )
        report_path = report_dir / "pip-audit.json"
        audit_run = _run_logged(
            [
                str(audit_python),
                "-I",
                "-m",
                "pip_audit",
                "--requirement",
                str(requirements_path),
                "--no-deps",
                "--disable-pip",
                "--strict",
                "--vulnerability-service",
                "pypi",
                "--format",
                "json",
                "--progress-spinner",
                "off",
                "--cache-dir",
                str(report_dir / "cache"),
                "--timeout",
                "30",
                "--output",
                str(report_path),
            ],
            report_dir,
            "pip-audit",
            900,
        )
        summary["scanner_exit_code"] = audit_run.returncode
        summary.update(
            assess_report(
                json.loads(report_path.read_text(encoding="utf-8")),
                dependencies,
                audit_run.returncode,
            )
        )
    except (OSError, ValueError) as exc:
        summary["error"] = str(exc)
    _write_json(report_dir / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return summary["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
