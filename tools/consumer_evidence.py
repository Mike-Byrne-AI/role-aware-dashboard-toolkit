"""Bind supplied consumer reports to an explicit source snapshot and artifacts.

This tool does not run tests, authenticate reports, or establish hosted/device
acceptance. Call snapshot before the consumer checks and finish afterwards.
Select source files deliberately; never select runtime data or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET

MAX_FILES = 1000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_CHECKS = 1000
MAX_JUNIT_DEPTH = 64
MAX_JUNIT_NODES = 100000
SCOPE = "Local supplied-report binding; not independent execution/authenticity or hosted/device proof."
_SNAPSHOT_FIELDS = {"schema_version", "kind", "source_sha256", "artifact_sha256"}
_HASH = re.compile(r"[0-9a-f]{64}")


def _invalid():
    return ValueError("Consumer evidence configuration is invalid.")


def _relative(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise _invalid()
    value = value.replace("\\", "/")
    parts = value.split("/")
    if any(part in ("", ".", "..") or part.endswith((".", " ")) for part in parts):
        raise _invalid()
    if any(ord(char) < 32 or char in ':*?<>"|' for char in value):
        raise _invalid()
    return value


def _is_link(metadata):
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _root(root):
    try:
        path = Path(root).absolute()
        if _is_link(path.lstat()) or not path.is_dir():
            raise _invalid()
        return path.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise _invalid() from error


def _file(root, relative):
    path = root
    for part in _relative(relative).split("/"):
        path = path / part
        if _is_link(path.lstat()):
            raise _invalid()
    if not stat.S_ISREG(path.stat().st_mode) or not path.resolve(strict=True).is_relative_to(root):
        raise _invalid()
    return path


def _digest_file(root, relative):
    path = _file(root, relative)
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise _invalid()
        total = 0
        while chunk := stream.read(64 * 1024):
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                raise _invalid()
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    current = _file(root, relative).stat()
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(current):
        raise _invalid()
    return digest.hexdigest()


def _paths(values, *, required):
    if not isinstance(values, (list, tuple)) or len(values) > MAX_FILES or required and not values:
        raise _invalid()
    paths = [_relative(value) for value in values]
    if len(paths) != len({os.path.normcase(path) for path in paths}):
        raise _invalid()
    return sorted(paths)


def capture_source(root, files, artifacts=()):
    """Capture explicit source/artifact bytes; invalid selections fail closed."""
    base = _root(root)
    try:
        return {
            "schema_version": 1,
            "kind": "consumer-source-snapshot",
            "source_sha256": {name: _digest_file(base, name) for name in _paths(files, required=True)},
            "artifact_sha256": {name: _digest_file(base, name) for name in _paths(artifacts, required=False)},
        }
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise _invalid() from error


def _hash_map(value, *, required):
    if not isinstance(value, dict) or len(value) > MAX_FILES or required and not value:
        raise _invalid()
    for name, digest in value.items():
        if _relative(name) != name or not isinstance(digest, str) or not _HASH.fullmatch(digest):
            raise _invalid()
    if len(value) != len({os.path.normcase(name) for name in value}):
        raise _invalid()
    return dict(sorted(value.items()))


def _snapshot(value):
    if not isinstance(value, dict) or set(value) != _SNAPSHOT_FIELDS:
        raise _invalid()
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise _invalid()
    if value["kind"] != "consumer-source-snapshot":
        raise _invalid()
    return {
        "schema_version": 1, "kind": "consumer-source-snapshot",
        "source_sha256": _hash_map(value["source_sha256"], required=True),
        "artifact_sha256": _hash_map(value["artifact_sha256"], required=False),
    }


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


def _parse_json(data):
    def reject_constant(value):
        raise _invalid()
    return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=reject_constant)


def _read(path):
    path = Path(path)
    if _is_link(path.lstat()) or not stat.S_ISREG(path.stat().st_mode):
        raise _invalid()
    with path.open("rb") as stream:
        data = stream.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise _invalid()
    return data


def load_json(path):
    """Load bounded UTF-8 JSON with duplicate keys and nonfinite values refused."""
    try:
        return _parse_json(_read(path))
    except (OSError, RuntimeError, TypeError, ValueError, RecursionError) as error:
        raise _invalid() from error


def write_json(path, value):
    """Write a new receipt/snapshot exclusively; never replace earlier evidence."""
    try:
        data = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if len(data.encode("ascii")) > MAX_REPORT_BYTES:
            raise _invalid()
        with Path(path).open("x", encoding="ascii", newline="\n") as stream:
            stream.write(data)
    except (OSError, TypeError, ValueError, RecursionError) as error:
        raise ValueError("Consumer evidence output is unavailable.") from error


def _junit(data):
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return None, "junit_invalid"
    if "\0" in text or "<!doctype" in text.lower() or "<!entity" in text.lower():
        return None, "junit_invalid"
    declaration = re.match(r"\ufeff?<\?xml\b[^?]*\?>", text)
    if declaration:
        encoding = re.search(r"\bencoding\s*=\s*['\"]([^'\"]+)['\"]", declaration[0])
        if encoding and encoding[1].lower() not in ("utf-8", "utf8"):
            return None, "junit_invalid"
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError, RecursionError):
        return None, "junit_invalid"
    if root.tag not in ("testsuite", "testsuites"):
        return None, "junit_invalid"
    # This parser supports unnamespaced JUnit only. Otherwise a namespaced
    # failure/error/skipped element could silently look like a passing case.
    # Bound structural work before repeatedly traversing nested suites below.
    pending, nodes = [(root, 1)], 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if (depth > MAX_JUNIT_DEPTH or nodes > MAX_JUNIT_NODES or "{" in node.tag
                or any("{" in name for name in node.attrib)):
            return None, "junit_invalid"
        pending.extend((child, depth + 1) for child in node)
    parents = {child: parent for parent in root.iter() for child in parent}
    cases = list(root.iter("testcase"))
    count = len(cases)
    if count > 100000 or any(parents[case].tag != "testsuite" for case in cases):
        return None, "junit_invalid"
    totals = {}
    for case in cases:
        for field, allowed in (("status", {"run", "passed", "completed"}),
                               ("result", {"completed", "passed", "success"})):
            if field not in case.attrib:
                continue
            value = case.attrib[field].lower()
            if value in {"notrun", "disabled", "skipped", "suppressed", "failed", "failure", "error"}:
                return count, "junit_failed"
            if value not in allowed:
                return count, "junit_invalid"
        statuses = tuple(int(any(child.tag == name for child in case))
                         for name in ("failure", "error", "skipped"))
        if sum(statuses) > 1 or len(list(case.iter("testcase"))) != 1:
            return None, "junit_invalid"
        totals[case] = (1, *statuses)
    if any(parents.get(node) not in totals for node in root.iter()
           if node.tag in ("failure", "error", "skipped")):
        return count, "junit_invalid"
    for suite in root.iter():
        if suite.tag not in ("testsuite", "testsuites"):
            continue
        observed = tuple(sum(totals[case][index] for case in suite.iter("testcase"))
                         for index in range(4))
        for index, field in enumerate(("tests", "failures", "errors", "skipped")):
            if field in suite.attrib:
                value = suite.attrib[field]
                if not re.fullmatch(r"[0-9]{1,8}", value) or int(value) != observed[index]:
                    return count, "junit_invalid"
        if "disabled" in suite.attrib and suite.attrib["disabled"] != "0":
            return count, "junit_invalid"
    if not cases:
        return 0, "junit_invalid"
    return count, "junit_failed" if any(any(row[1:]) for row in totals.values()) else None


def _browser(data, source):
    try:
        value = _parse_json(data)
        if not isinstance(value, dict) or type(value.get("passed")) is not bool:
            return None, "browser_invalid"
        checks = value.get("checks")
        if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS:
            return None, "browser_invalid"
        if any(not isinstance(check, str) or not check.strip() or len(check) > 512 for check in checks):
            return None, "browser_invalid"
        if len(checks) != len(set(checks)):
            return None, "browser_invalid"
        observed = _hash_map(value.get("source_sha256"), required=True)
        if observed != source:
            return len(checks), "browser_source_mismatch"
        return len(checks), None if value["passed"] else "browser_failed"
    except (TypeError, ValueError, RecursionError):
        return None, "browser_invalid"


def finish_evidence(root, snapshot, *, junit_path, browser_path):
    """Bind supplied reports to unchanged selected bytes, preserving refusals."""
    baseline, base = _snapshot(snapshot), _root(root)
    errors = []
    unchanged = {}
    for name, field in (("source", "source_sha256"), ("artifacts", "artifact_sha256")):
        try:
            unchanged[name] = all(_digest_file(base, path) == digest
                                  for path, digest in baseline[field].items())
        except (OSError, RuntimeError, TypeError, ValueError):
            unchanged[name] = False
        if not unchanged[name]:
            errors.append("source_changed" if name == "source" else "artifact_changed")
    reports, counts = {}, {}
    for name, path in (("junit", junit_path), ("browser", browser_path)):
        reports[name + "_sha256"] = None
        try:
            data = _read(path)
        except FileNotFoundError:
            count, error = None, name + "_missing"
        except (OSError, RuntimeError, TypeError, ValueError):
            count, error = None, name + "_invalid"
        else:
            reports[name + "_sha256"] = hashlib.sha256(data).hexdigest()
            count, error = _junit(data) if name == "junit" else _browser(data, baseline["source_sha256"])
        counts["junit_cases" if name == "junit" else "browser_checks"] = count
        if error:
            errors.append(error)
    return {
        "schema_version": 1, "kind": "consumer-evidence-receipt", "scope": SCOPE,
        "status": "failed" if errors else "passed", "source_unchanged": unchanged["source"],
        "artifacts_unchanged": unchanged["artifacts"], "snapshot": baseline,
        "reports": reports, "counts": counts, "errors": errors,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("snapshot", help="Capture explicit source before running checks.")
    capture.add_argument("--root", type=Path, required=True)
    capture.add_argument("--file", action="append", required=True)
    capture.add_argument("--artifact", action="append", default=[])
    capture.add_argument("--output", type=Path, required=True)
    finish = commands.add_parser("finish", help="Bind supplied reports after checks finish.")
    finish.add_argument("--root", type=Path, required=True)
    finish.add_argument("--snapshot", type=Path, required=True)
    finish.add_argument("--junit", type=Path, required=True)
    finish.add_argument("--browser", type=Path, required=True)
    finish.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "snapshot":
            value = capture_source(args.root, args.file, args.artifact)
        else:
            value = finish_evidence(args.root, load_json(args.snapshot),
                                    junit_path=args.junit, browser_path=args.browser)
        write_json(args.output, value)
    except (OSError, RuntimeError, TypeError, ValueError, RecursionError):
        parser.error("Consumer evidence configuration or output is unavailable.")
    return 1 if value.get("status") == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
