"""File URIs without an authority and editor file links name local paths."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit.packet_core import build_packet
from role_aware_dashboard_toolkit.path_redaction import redact_text_local_paths


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("open file:/Users/alice/private.json now", "open <redacted-local-path> now"),
        ("FILE:/home/alice/.ssh/id_rsa", "<redacted-local-path>"),
        ("file:/C:/Users/alice/notes.txt", "<redacted-local-path>"),
        (r"file:\\fileserver\alice\payroll.xlsx", "<redacted-local-path>"),
        ("(file:/srv/private/a.json)", "(<redacted-local-path>)"),
        ("vscode://file/Users/alice/proj/a.py:10", "<redacted-local-path>"),
        ("cursor://file/home/alice/a.py", "<redacted-local-path>"),
        ("see (vscode-insiders://File/c:/Users/alice/a.py:3:1)", "see (<redacted-local-path>)"),
        ("https://example.test/a?open=file:/Users/alice/x.json",
         "https://example.test/a?open=<redacted-local-path>"),
    ],
)
def test_file_uris_and_editor_file_links_are_redacted(message, expected):
    assert redact_text_local_paths(message) == expected


@pytest.mark.parametrize(
    "message",
    [
        "profile:/x",
        "https://example.test/file:/docs",
        "vscode://settings/editor",
        "file:report.txt",
        "a file: see notes",
    ],
)
def test_file_uri_rule_leaves_other_text_unchanged(message):
    assert redact_text_local_paths(message) == message


def test_packets_redact_file_uris_and_editor_file_links():
    packet = build_packet(
        "x_probe",
        {"schema_version": 1, "a": "file:/Users/alice/x", "b": "vscode://file/Users/alice/proj/a.py:10"},
    )

    assert packet["payload"]["a"] == "<redacted-local-path>"
    assert packet["payload"]["b"] == "<redacted-local-path>"
