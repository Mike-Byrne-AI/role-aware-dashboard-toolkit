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


def test_default_scan_cap_is_256_kib():
    assert path_redaction._MAX_SCAN_CHARACTERS == 256 * 1024


def test_oversize_text_is_scanned_up_to_the_cap_and_its_tail_is_dropped(monkeypatch):
    # raising=False lets this run against a scanner without a cap, which fails it.
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", 40, raising=False)
    head = "see /Users/alice/x and "
    text = head + "b" * (40 - len(head)) + " /Users/alice/secret.txt"

    redacted = redact_text_local_paths(text)

    omitted = len(text) - 40
    assert redacted == (
        "see <redacted-local-path> and " + "b" * (40 - len(head))
        + f"<redacted-oversize-text: {omitted} characters omitted>"
    )
    assert "alice" not in redacted
    assert "secret" not in redacted


def test_text_at_the_scan_cap_is_not_truncated(monkeypatch):
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", 40, raising=False)
    text = "x" * 40

    assert redact_text_local_paths(text) == text
    assert redact_text_local_paths(text + "y") == "x" * 40 + "<redacted-oversize-text: 1 character omitted>"


def test_oversize_payload_values_and_keys_are_capped_but_opt_in_paths_are_untouched(monkeypatch):
    monkeypatch.setattr(path_redaction, "_MAX_SCAN_CHARACTERS", 16, raising=False)
    long_value = "/Users/alice/" + "x" * 30
    payload = {"note": "ok " + "z" * 30, "k" * 20: "value", "path": long_value}

    redacted = redact_payload_local_paths(payload, repo_root="")
    visible = redact_payload_local_paths(payload, repo_root="", include_local_paths=True)

    assert redacted["note"] == "ok " + "z" * 13 + "<redacted-oversize-text: 17 characters omitted>"
    assert redacted["k" * 16 + "<redacted-oversize-text: 4 characters omitted>"] == "value"
    assert redacted["path"].startswith("<redacted-local-path>")
    assert "alice" not in json_text(redacted)
    assert visible == payload


def json_text(value):
    import json

    return json.dumps(value)
