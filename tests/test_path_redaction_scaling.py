"""Path redaction stays linear on hostile text and bounds how much it scans.

Redaction runs synchronously on audit events, exports and packets, and its
regular expressions hold the GIL. Each shape below took seconds to minutes with
the 0.1.0 scanner (quadratic or cubic growth), freezing every other session in
the process. A linear scanner takes milliseconds, so the generous bound passes
on a slow CI runner while any return to superlinear scanning fails it.
"""
from __future__ import annotations

import time

import pytest

import role_aware_dashboard_toolkit.path_redaction as path_redaction
from role_aware_dashboard_toolkit.path_redaction import redact_payload_local_paths, redact_text_local_paths

_BOUND_SECONDS = 1.0

HOSTILE_SHAPES = {
    # Every letter started a scheme-URL scan to the end of the run.
    "unbroken letters, 200 KB": "a" * 200_000,
    # Each path match rescanned every scheme URL candidate in the token.
    "interleaved letters and paths, 8 KB": "a" * 4_000 + "|/a" * 1_333,
    # Each slash rescanned the rest of the token for a path character.
    "slashes without path characters, 64 KB": "(/" * 32_000,
    "many short paths in one token, 64 KB": "|/a" * 21_333,
    # Each escaped quote restarted a quoted-path body scan to the end.
    "escaped quotes after a quoted path, 48 KB": "'/" + "\\'/" * 16_000,
    # Each OSError prefix rescanned the line for a quoted filename.
    "repeated OSError prefixes, 128 KB": "[Errno 2] x" + "[Errno 1]" * 14_000,
    "OSError text with a long space run, 64 KB": "[Errno 2] x" + " " * 64_000,
}


@pytest.mark.parametrize("text", list(HOSTILE_SHAPES.values()), ids=list(HOSTILE_SHAPES))
def test_redaction_time_stays_linear_on_hostile_text(text):
    started = time.perf_counter()
    redact_text_local_paths(text)
    elapsed = time.perf_counter() - started

    assert elapsed < _BOUND_SECONDS, f"redaction took {elapsed:.2f}s for {len(text)} characters"


def test_payload_redaction_time_stays_linear_on_hostile_values():
    payload = {"note": "a" * 100_000, "detail": "a" * 2_000 + "|/a" * 666}

    started = time.perf_counter()
    redact_payload_local_paths(payload, repo_root="")
    elapsed = time.perf_counter() - started

    assert elapsed < _BOUND_SECONDS, f"payload redaction took {elapsed:.2f}s"


def test_default_scan_cap_is_1_mib():
    assert path_redaction._MAX_SCAN_CHARACTERS == 1024 * 1024


def test_oversize_text_keeps_whole_lines_and_drops_the_line_crossing_the_cap(monkeypatch):
    # raising=False lets this run against a scanner without a cap, which fails it.
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", 40, raising=False)
    head = "see /Users/alice/x\n"
    text = head + "and " + "b" * 30 + " /Users/alice/secret.txt"

    redacted = redact_text_local_paths(text)

    omitted = len(text) - len(head)
    assert redacted == f"see <redacted-local-path>\n<redacted-oversize-text: {omitted} characters omitted>"
    assert "alice" not in redacted
    assert "secret" not in redacted


def test_text_at_the_scan_cap_is_not_truncated(monkeypatch):
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", 40, raising=False)
    text = "x" * 40

    assert redact_text_local_paths(text) == text
    # One line longer than the cap crosses it, so all of it is dropped.
    assert redact_text_local_paths(text + "y") == "<redacted-oversize-text: 41 characters omitted>"
    # A line ending exactly at the cap is complete, so it is kept.
    assert redact_text_local_paths(text + "\nyy") == "x" * 40 + "<redacted-oversize-text: 3 characters omitted>"
    assert redact_text_local_paths("x" * 39 + "\nyy") == "x" * 39 + "\n<redacted-oversize-text: 2 characters omitted>"
    assert redact_text_local_paths("x" * 39 + "\r\nyy") == "x" * 39 + "\r<redacted-oversize-text: 3 characters omitted>"


# Each line straddles the cap. 0.1.0 redacted each path whole; cutting at the
# cap split a quoted path, a Windows path with spaces or an OSError filename,
# and the part before the cut no longer read as a path, so a name leaked.
STRADDLING = {
    "quoted POSIX path with spaces": ('Could not read "/Users/alice/Secret Merger Plans/acme deal.xlsx" (retry)', 40),
    "Windows path with spaces": ("Could not read C:\\Users\\alice\\Secret Merger Plans\\acme.xlsx now", 40),
    "OSError double-root filename": ("[Errno 63] File name too long: '//fs01/share/alice-payroll/q3/xxxxxxxx'", 50),
    "unquoted POSIX path": ("Could not read /Users/alice/secretproject/file.txt now", 22),
}
_PRIVATE_FRAGMENTS = ("alice", "Mer", "Plans", "acme", "fs01", "payroll", "secretproject")


@pytest.mark.parametrize("line,cut", list(STRADDLING.values()), ids=list(STRADDLING))
def test_a_path_crossing_the_cap_is_dropped_whole(monkeypatch, line, cut):
    first = "ok line\n"
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", len(first) + cut, raising=False)
    text = first + line

    redacted = redact_text_local_paths(text)

    assert [fragment for fragment in _PRIVATE_FRAGMENTS if fragment in redacted] == []
    assert redacted == f"ok line\n<redacted-oversize-text: {len(line)} characters omitted>"


def test_a_real_overlong_oserror_at_the_default_cap_leaks_nothing():
    # A host building a path from user text gets ENAMETOOLONG naming all of it.
    cap = path_redaction._MAX_SCAN_CHARACTERS
    message = "[Errno 63] File name too long: '//fs01/share/alice-payroll/" + "x" * cap + "'"

    redacted = redact_text_local_paths(message)

    assert "fs01" not in redacted and "alice" not in redacted
    assert redacted == f"<redacted-oversize-text: {len(message)} characters omitted>"


def test_oversize_payload_values_and_keys_are_capped_but_opt_in_paths_are_untouched(monkeypatch):
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", 16, raising=False)
    long_value = "/Users/alice/" + "x" * 30
    payload = {"note": "ok\n" + "z" * 30, "k" * 20: "value", "path": long_value}

    redacted = redact_payload_local_paths(payload, repo_root="")
    visible = redact_payload_local_paths(payload, repo_root="", include_local_paths=True)

    assert redacted["note"] == "ok\n<redacted-oversize-text: 30 characters omitted>"
    assert redacted["<redacted-oversize-text: 20 characters omitted>"] == "value"
    assert redacted["path"] == "<redacted-oversize-text: 43 characters omitted>"
    assert "alice" not in json_text(redacted)
    assert visible == payload


def json_text(value):
    import json

    return json.dumps(value)


# Measured on an Apple M2, Python 3.12, for the text below: this code resolves
# 2.0x the text's characters in 0.21 s; the rescanning code it replaced
# resolved 50.6x in 7.58 s. Resolution costs a file-system call per path
# component, two on Windows, where a CI runner took 1.96 s for the same
# amount of resolution (about 10x the M2). The bound leaves that runner about
# 2x headroom and is still under the old code on the fastest machine; the
# character count is the oracle that does not depend on the runner.
_COMMA_RUN_BOUND_SECONDS = 4.0


def test_comma_joined_repo_paths_scan_in_linear_time(monkeypatch):
    # Distinct in-repository paths joined by commas form one long candidate;
    # its relative remainder is scanned once more, not once per path.
    text = "log: " + " ".join(
        ",".join(f"/srv/repo/pkg{run}/mod{index}.py" for index in range(100)) for run in range(47)
    )
    resolved: list[int] = []
    resolve = path_redaction._redact_absolute_path_once

    def counting(value, *, repo_root_path):
        resolved.append(len(value))
        return resolve(value, repo_root_path=repo_root_path)

    monkeypatch.setattr(path_redaction, "_redact_absolute_path_once", counting)
    started = time.perf_counter()
    redact_text_local_paths(text, repo_root="/srv/repo")
    elapsed = time.perf_counter() - started

    assert sum(resolved) <= 3 * len(text), f"resolved {sum(resolved) / len(text):.1f}x the text"
    assert elapsed < _COMMA_RUN_BOUND_SECONDS, f"redaction took {elapsed:.2f}s for {len(text)} characters"


def test_an_escaped_carriage_return_inside_quotes_is_not_a_cut_point(monkeypatch):
    # A quoted body continues past a backslash-escaped CR, so cutting after
    # that CR split the quoted path and leaked the part before the cut.
    head = "ok\n"
    line = '"C:\\Users\\alice smith\\pay roll\\\r' + "z" * 60 + '" tail'
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", len(head) + line.index("\r") + 5, raising=False)

    redacted = redact_text_local_paths(head + line)

    assert redacted == f"ok\n<redacted-oversize-text: {len(line)} characters omitted>"


def test_an_unescaped_carriage_return_still_ends_a_line(monkeypatch):
    # Two backslashes escape each other, so the CR after them is a line end.
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", 10, raising=False)

    assert redact_text_local_paths("ab\\\\\rcdefghijkl") == "ab\\\\\r<redacted-oversize-text: 10 characters omitted>"
