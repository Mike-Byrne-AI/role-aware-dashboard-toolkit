"""URL queries nested inside URL queries are redacted to a bounded depth."""
from __future__ import annotations

import time

from role_aware_dashboard_toolkit import build_packet
from role_aware_dashboard_toolkit.path_redaction import redact_text_local_paths


def test_deeply_nested_url_queries_do_not_exhaust_the_stack():
    text = "http://a/?" * 400

    redacted = redact_text_local_paths(text)

    assert redacted.startswith("http://a/?http://a/?")
    assert "<redacted-local-path>" in redacted


def test_packets_with_deeply_nested_url_queries_still_build():
    packet = build_packet("x_probe", {"schema_version": 1, "link": "http://a/?" * 400})

    assert "<redacted-local-path>" in packet["payload"]["link"]


def test_nested_url_query_redaction_time_stays_linear():
    text = "http://a/?" * 20_000

    started = time.perf_counter()
    redact_text_local_paths(text)
    elapsed = time.perf_counter() - started

    assert elapsed < 1.0, f"redaction took {elapsed:.2f}s"


def test_a_path_below_the_nesting_limit_is_never_emitted():
    text = "http://a/?" * 12 + "/Users/alice/private.json"

    assert "alice" not in redact_text_local_paths(text)


def test_ordinary_nested_redirects_keep_their_redaction():
    assert redact_text_local_paths("https://x.test/login?next=https://y.test/cb?file=/tmp/a.json") == (
        "https://x.test/login?next=https://y.test/cb?file=<redacted-local-path>"
    )
