import json
import logging
import os
from pathlib import Path

import pytest

import role_aware_dashboard_toolkit.path_redaction as path_redaction
from role_aware_dashboard_toolkit.packet_core import build_packet
from role_aware_dashboard_toolkit.path_redaction import redact_diagnostic_path, redact_payload_local_paths, redact_text_local_paths
from role_aware_dashboard_toolkit.store_diagnostics import build_read_error as build_store_read_error


def test_redact_text_local_paths_preserves_safe_tokens_and_redacts_file_urls():
    text = (
        "release date 2026/05/01 ratio 3/4 version v1/2 "
        "URL 'https://example.test/C:/docs/readme.txt' "
        "file 'file:///C:/docs/readme.txt' ref \"namespace/name\""
    )
    assert redact_text_local_paths(text) == (
        "release date 2026/05/01 ratio 3/4 version v1/2 "
        "URL 'https://example.test/C:/docs/readme.txt' "
        "file '<redacted-local-path>' ref \"namespace/name\""
    )


def test_redact_text_local_paths_preserves_non_path_backslash_and_double_slash_prose():
    text = (
        r"escape '\n' regex '\d+' latex '\frac{a}{b}' root '/' "
        r"ratio a//b date 2026//05//01 url=//example.test/assets/app.js"
    )

    assert redact_text_local_paths(text) == text


def test_redact_text_local_paths_redacts_absolute_paths_in_mixed_text():
    text = "run /tmp/repo logs=(/tmp/repo/logs/audit.json) bin=C:\\tools\\runner.exe"
    redacted = redact_text_local_paths(text)
    assert redacted == "run <redacted-local-path> logs=(<redacted-local-path>) bin=<redacted-local-path>"


def test_redact_text_local_paths_preserves_runtime_coercion_compatibility(tmp_path):
    private_path = tmp_path / "private" / "secret.json"

    assert redact_text_local_paths(private_path) == "<redacted-local-path>"
    assert redact_text_local_paths(None) == ""
    assert redact_text_local_paths(123) == "123"
    assert redact_text_local_paths(b"plain") == "b'plain'"


@pytest.mark.parametrize(
    "filename",
    [
        r"C:\Private Root\Dash Forge\secret file.json",
        r"\\private-server\Secret Share\secret.json",
        "//private-server/Secret Share/secret file.json",
        "/srv/Private Root/Dash Forge/secret file.json",
        "/srv/Both ' and \" Quotes/secret.json",
    ],
)
def test_redact_text_local_paths_redacts_standard_oserror_filenames(filename):
    message = str(OSError(5, "access denied", filename))

    redacted = redact_text_local_paths(message)

    assert redacted == "[Errno 5] access denied: '<redacted-local-path>'"


def test_redact_text_local_paths_redacts_both_standard_oserror_filenames():
    message = str(
        OSError(
            18,
            "move failed",
            "/srv/Private Root/source file.json",
            None,
            "//private-server/Secret Share/destination file.json",
        )
    )

    redacted = redact_text_local_paths(message)

    assert redacted.count("<redacted-local-path>") == 2
    assert "Private Root" not in redacted
    assert "private-server" not in redacted
    assert " -> " in redacted


def test_redact_text_local_paths_fails_closed_for_escaped_wrapper_relative_tail():
    filename = "/srv/Both ' and \" Quotes/secret.json"
    message = str(PermissionError(13, "denied", filename))

    assert redact_text_local_paths(message, repo_root="/srv") == (
        "[Errno 13] denied: '<redacted-local-path>'"
    )


@pytest.mark.parametrize(
    ("error_message", "filename", "expected"),
    [
        (
            "user's access denied",
            "//private-server/Secret Share/secret file.json",
            "[Errno 5] user's access denied: '<redacted-local-path>'",
        ),
        (
            'say "denied" now',
            "//private-server/It's Secret/secret.json",
            '[Errno 5] say "denied" now: "<redacted-local-path>"',
        ),
    ],
)
def test_redact_text_local_paths_redacts_oserror_filename_after_quoted_message(
    error_message,
    filename,
    expected,
):
    message = str(OSError(5, error_message, filename))

    assert redact_text_local_paths(message) == expected


@pytest.mark.parametrize(
    ("repo_root", "filename"),
    [
        (
            r"C:\Fixture Root\Dash Forge",
            r"C:\Fixture Root\Dash Forge\reports\secret file.json",
        ),
        (
            r"\\private-server\Secret Share\repo",
            r"\\private-server\Secret Share\repo\reports\secret file.json",
        ),
    ],
)
def test_redact_text_local_paths_preserves_windows_repo_relative_oserror_filename(repo_root, filename):
    message = str(OSError(5, "access denied", filename))

    assert redact_text_local_paths(message, repo_root=repo_root) == "[Errno 5] access denied: 'reports/secret file.json'"


def test_redact_text_local_paths_redacts_escaped_windows_path_without_quotes():
    message = r"failed C:\\Private\\Role-Aware Dashboard Toolkit\\secret.json"

    assert redact_text_local_paths(message) == "failed <redacted-local-path>"


@pytest.mark.parametrize(
    "message",
    [
        "https://[::1]/a/b",
        "https://example.test/a//b?next=relative/path#frag/one",
        "https://example.test/C:/docs/readme.txt?mode=preview#section",
        "ftp://[2001:db8::1]/pub/file.txt",
    ],
)
def test_redact_text_local_paths_preserves_safe_scheme_urls(message):
    assert redact_text_local_paths(message) == message


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "https://example.test/a//b?next=/tmp/private.json#frag/one",
            "https://example.test/a//b?next=<redacted-local-path>#frag/one",
        ),
        (
            r"https://example.test/a?next=C:\Private\secret.json",
            "https://example.test/a?next=<redacted-local-path>",
        ),
        (
            r"https://example.test/a?next=\\private-server\share\secret.json",
            "https://example.test/a?next=<redacted-local-path>",
        ),
        (
            "https://example.test/view?"
            "path=%252Fhome%252Falice%252Fprivate.json"
            "#%2Fvar%2Flog%2Faudit.log",
            "https://example.test/view?"
            "path=<redacted-local-path>#<redacted-local-path>",
        ),
        (
            "file:///home/alice/private.json",
            "<redacted-local-path>",
        ),
        (
            "FILE://private-server/share/private.json",
            "<redacted-local-path>",
        ),
    ],
)
def test_redact_text_local_paths_redacts_local_paths_in_url_surfaces(
    message,
    expected,
):
    assert redact_text_local_paths(message) == expected


def test_redact_text_local_paths_keeps_repo_relative_context_in_url_query():
    message = "https://example.test/view?path=/srv/repo/reports/audit.json"

    assert redact_text_local_paths(message, repo_root="/srv/repo") == (
        "https://example.test/view?path=reports/audit.json"
    )


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "refs=https://example.test/a,/tmp/private.json",
            "refs=https://example.test/a,<redacted-local-path>",
        ),
        (
            "refs=https://[::1]/a,/tmp/private.json",
            "refs=https://[::1]/a,<redacted-local-path>",
        ),
    ],
)
def test_redact_text_local_paths_preserves_url_and_redacts_adjacent_path(message, expected):
    assert redact_text_local_paths(message) == expected


def test_redact_text_local_paths_preserves_windows_path_wrappers():
    message = r"failed (C:\Private\secret.txt), and [\\server\share\other.json];"

    assert redact_text_local_paths(message) == (
        "failed (<redacted-local-path>), and [<redacted-local-path>];"
    )


def test_store_read_error_preserves_only_spaced_repo_relative_oserror_filename(tmp_path):
    repo_root = tmp_path / "Private Root" / "profiles"
    path = repo_root / "broken.json"
    secret_path = repo_root / "secret file.json"

    error = build_store_read_error(path, PermissionError(13, "profile read denied", str(secret_path)))

    assert error["message"] == "[Errno 13] profile read denied: 'secret file.json'"
    assert str(tmp_path) not in error["message"]


def test_redact_payload_local_paths_preserves_non_path_slash_text_and_redacts_paths():
    payload = {
        "summary_text": "release date 2026/05/01 ratio 3/4 path /tmp/repo",
        "run_ref": "v1/2",
        "source_path": "/tmp/repo/reports/audit.json",
        "repo_root": "/tmp/repo",
    }
    redacted = redact_payload_local_paths(payload, repo_root="/tmp/repo", include_local_paths=False)
    assert redacted["summary_text"] == "release date 2026/05/01 ratio 3/4 path ."
    assert redacted["run_ref"] == "v1/2"
    assert redacted["source_path"] == "reports/audit.json"
    assert redacted["repo_root"] == "."


def test_redact_payload_local_paths_redacts_tuple_values_as_json_safe_lists():
    payload = {"paths": ("/tmp/repo/reports/audit.json", r"C:\private\secret.json")}

    redacted = redact_payload_local_paths(payload, repo_root="/tmp/repo")

    assert redacted["paths"] == ["reports/audit.json", "<redacted-local-path>"]


def test_redact_payload_local_paths_normalizes_pathlike_values(tmp_path):
    class BytesPath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return os.fsencode(self.value)

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"
    outside = tmp_path / "outside" / "secret.json"
    payload = {
        "repo_root": repo_root,
        "inside": inside,
        "outside": outside,
        "nested": (BytesPath(inside),),
    }

    redacted = redact_payload_local_paths(payload, repo_root=repo_root)

    assert redacted == {
        "repo_root": ".",
        "inside": "reports/inside.json",
        "outside": "<redacted-local-path>",
        "nested": ["reports/inside.json"],
    }
    assert json.loads(json.dumps(redacted)) == redacted

    visible = redact_payload_local_paths(
        payload,
        repo_root=repo_root,
        include_local_paths=True,
    )
    assert visible == {
        "repo_root": str(repo_root),
        "inside": str(inside),
        "outside": str(outside),
        "nested": [str(inside)],
    }
    assert json.loads(json.dumps(visible)) == visible


def test_redact_payload_local_paths_uses_custom_pathlike_repo_root(tmp_path):
    class OnlyFspath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return str(self.value)

        def __str__(self):
            raise AssertionError("path context must use __fspath__, not __str__")

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"

    redacted = redact_payload_local_paths(
        {"path": OnlyFspath(inside)},
        repo_root=OnlyFspath(repo_root),
    )

    assert redacted == {"path": "reports/inside.json"}


def test_redact_payload_local_paths_canonicalizes_pathlike_text_subclasses(tmp_path):
    class HostileText(str):
        def __str__(self):
            raise AssertionError("path text must not invoke an override")

        def __bool__(self):
            raise AssertionError("path text must be a plain string")

        def strip(self, *_args, **_kwargs):
            raise AssertionError("repo root text must be a plain string")

    class HostileTextPath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return HostileText(self.value)

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"
    payload = {
        "repo_root": HostileTextPath(repo_root),
        "path": HostileTextPath(inside),
    }

    redacted = redact_payload_local_paths(
        payload,
        repo_root=HostileTextPath(repo_root),
    )
    visible = redact_payload_local_paths(
        payload,
        repo_root=HostileTextPath(repo_root),
        include_local_paths=True,
    )

    assert redacted == {"repo_root": ".", "path": "reports/inside.json"}
    assert visible == {"repo_root": str(repo_root), "path": str(inside)}
    assert type(visible["repo_root"]) is str
    assert type(visible["path"]) is str


def test_redact_payload_local_paths_normalizes_hybrid_string_pathlike_values(tmp_path):
    class HybridPath(str, os.PathLike):
        def __fspath__(self):
            return str.__str__(self)

        def __str__(self):
            raise AssertionError("hybrid PathLike must use __fspath__")

        def __bool__(self):
            raise AssertionError("hybrid PathLike must not retain string overrides")

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"
    hybrid = HybridPath(inside)

    redacted = redact_payload_local_paths(
        {"path": hybrid, hybrid: "path-key"},
        repo_root=repo_root,
    )
    visible = redact_payload_local_paths(
        {"path": hybrid},
        repo_root=repo_root,
        include_local_paths=True,
    )

    assert redacted == {
        "path": "reports/inside.json",
        "reports/inside.json": "path-key",
    }
    assert visible == {"path": str(inside)}
    assert type(visible["path"]) is str


def test_redact_payload_local_paths_normalizes_set_before_ordering(tmp_path):
    class HostileReprPath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return str(self.value)

        def __repr__(self):
            raise RuntimeError(f"repr leaked {self.value}")

    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"

    redacted = redact_payload_local_paths(
        {"paths": {HostileReprPath(inside)}},
        repo_root=repo_root,
    )

    assert redacted == {"paths": ["reports/inside.json"]}
    assert redact_payload_local_paths(
        {"values": {b"c", b"a", b"b"}},
        repo_root="",
    ) == {"values": [b"a", b"b", b"c"]}


def test_redact_payload_local_paths_fails_closed_for_invalid_pathlike_values(caplog):
    class RaisingPath(os.PathLike):
        def __fspath__(self):
            raise RuntimeError(r"failed at C:\Private\secret.json")

    class InvalidPath(os.PathLike):
        def __fspath__(self):
            return 42

    class InvalidDecodedBytes(bytes):
        def decode(self, *_args, **_kwargs):
            return 42

    class InvalidDecodedPath(os.PathLike):
        def __fspath__(self):
            return InvalidDecodedBytes(b"C:/Private/secret.json")

    caplog.set_level(logging.WARNING, logger=path_redaction.__name__)
    sentinel = object()

    redacted = redact_payload_local_paths(
        {
            "raising": RaisingPath(),
            "invalid": InvalidPath(),
            "invalid_decoded": InvalidDecodedPath(),
            "sentinel": sentinel,
        },
        repo_root="",
    )

    assert redacted["raising"] == "<redacted-local-path>"
    assert redacted["invalid"] == "<redacted-local-path>"
    assert redacted["invalid_decoded"] == "<redacted-local-path>"
    assert redacted["sentinel"] is sentinel
    assert [record.getMessage() for record in caplog.records] == [
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (RuntimeError).",
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (TypeError).",
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (TypeError).",
    ]
    assert "Private" not in "\n".join(record.getMessage() for record in caplog.records)


def test_redact_payload_local_paths_preserves_repo_root_rule_for_invalid_pathlike(caplog):
    class RaisingPath(os.PathLike):
        def __fspath__(self):
            raise RuntimeError(r"failed at C:\Private\secret.json")

    caplog.set_level(logging.WARNING, logger=path_redaction.__name__)

    hidden = redact_payload_local_paths(
        {"repo_root": RaisingPath()},
        repo_root="",
    )
    visible = redact_payload_local_paths(
        {"repo_root": RaisingPath()},
        repo_root="",
        include_local_paths=True,
    )

    assert hidden == {"repo_root": "."}
    assert visible == {"repo_root": "<redacted-local-path>"}
    assert [record.getMessage() for record in caplog.records] == [
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (RuntimeError).",
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (RuntimeError).",
    ]


def test_redact_payload_local_paths_rejects_non_utf8_pathlike_text(caplog):
    class SurrogatePath(os.PathLike):
        def __fspath__(self):
            return "relative-\udcff-name.json"

    caplog.set_level(logging.WARNING, logger=path_redaction.__name__)

    redacted = redact_payload_local_paths(
        {"path": SurrogatePath()},
        repo_root="",
        include_local_paths=True,
    )

    assert redacted == {"path": "<redacted-local-path>"}
    assert json.dumps(redacted, ensure_ascii=False).encode("utf-8")
    assert [record.getMessage() for record in caplog.records] == [
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (UnicodeEncodeError)."
    ]


def test_redact_payload_local_paths_fails_closed_for_unresolvable_path_text(
    tmp_path,
    caplog,
):
    class NullPath(os.PathLike):
        def __fspath__(self):
            return f"{tmp_path / 'private'}\0secret.json"

    caplog.set_level(logging.WARNING, logger=path_redaction.__name__)
    redacted = redact_payload_local_paths(
        {"value": NullPath(), NullPath(): "path-key"},
        repo_root=NullPath(),
    )

    assert redacted == {
        "value": "<redacted-local-path>",
        "<redacted-local-path>": "path-key",
    }
    warnings = [record.getMessage() for record in caplog.records]
    assert warnings == [
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (ValueError).",
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (ValueError).",
        "Role-Aware Dashboard Toolkit path redaction could not read path-like value (ValueError).",
    ]
    assert str(tmp_path) not in "\n".join(warnings)


def test_redact_payload_local_paths_preserves_colliding_mapping_keys(tmp_path):
    repo_root = tmp_path / "repo"
    outside_a = tmp_path / "outside-a.json"
    outside_b = tmp_path / "outside-b.json"
    payload = {
        outside_a: "path-a",
        "<redacted-local-path>": "literal-marker",
        outside_b: "path-b",
        str(outside_a): "string-a",
        repo_root / "schema_version": "path-schema",
        "schema_version": 1,
    }

    redacted = redact_payload_local_paths(payload, repo_root=repo_root)

    assert redacted == {
        "<redacted-local-path>#2": "path-a",
        "<redacted-local-path>": "literal-marker",
        "<redacted-local-path>#3": "path-b",
        "<redacted-local-path>#4": "string-a",
        "schema_version#2": "path-schema",
        "schema_version": 1,
    }
    assert len(redacted) == len(payload)
    assert str(tmp_path) not in json.dumps(redacted)


def test_build_packet_normalizes_pathlike_payload_for_strict_json(tmp_path):
    repo_root = tmp_path / "repo"
    inside = repo_root / "reports" / "inside.json"
    packet = build_packet(
        "audit_slice",
        {"repo_root": repo_root, "path": inside, inside: "key"},
        repo_root=repo_root,
    )

    assert packet["payload"] == {
        "repo_root": ".",
        "path": "reports/inside.json",
        "reports/inside.json": "key",
    }
    assert json.loads(json.dumps(packet))["payload"] == packet["payload"]


def test_build_packet_redaction_preserves_slash_text_while_removing_absolute_paths():
    payload = {
        "summary_text": "release date 2026/05/01 ratio 3/4",
        "details": "wrote /tmp/repo/reports/audit.json",
        "repo_root": "/tmp/repo",
    }
    packet = build_packet("audit_slice", payload, repo_root="/tmp/repo")
    assert packet["payload"]["summary_text"] == "release date 2026/05/01 ratio 3/4"
    assert packet["payload"]["details"] == "wrote reports/audit.json"
    assert packet["payload"]["repo_root"] == "."


def test_redact_diagnostic_path_preserves_repo_relative_context():
    path = Path("/tmp/repo/reports/audit.json")

    assert redact_diagnostic_path(path, repo_root="/tmp/repo") == "reports/audit.json"
    assert redact_diagnostic_path(path, repo_root="/tmp/other") == "<redacted-local-path>"


def test_redact_diagnostic_path_preserves_symlink_name_without_exposing_target(tmp_path):
    repo_root = tmp_path / "repo"
    reports_dir = repo_root / "reports"
    reports_dir.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = reports_dir / "linked.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    assert redact_diagnostic_path(link, repo_root=str(repo_root)) == "reports/linked.json"


def test_redact_text_local_paths_redacts_spaced_windows_paths_and_preserves_repo_relative_tail():
    repo_root = r"C:\Fixture Root\Dash Forge Fixture"
    text = rf"failed at {repo_root}\reports\secret.txt while collecting diagnostics"
    redacted = redact_text_local_paths(text, repo_root=repo_root)
    assert redacted == "failed at reports/secret.txt while collecting diagnostics"


def test_redact_text_local_paths_redacts_quoted_and_wrapped_windows_paths_with_spaces():
    repo_root = r"C:\Fixture Root\Dash Forge Fixture"
    text = rf'read ("{repo_root}\reports\my file.txt") and ({repo_root}\logs\audit.json)'
    redacted = redact_text_local_paths(text, repo_root=repo_root)
    assert redacted == 'read ("reports/my file.txt") and (logs/audit.json)'


def test_store_read_error_redacts_spaced_windows_paths_without_leaking_tail():
    repo_root = Path(r"C:\Fixture Root\Dash Forge Fixture\profiles")
    path = repo_root / "broken.json"
    message_path = r"C:\Fixture Root\Dash Forge Fixture\profiles\secret.txt"
    error = build_store_read_error(path, OSError(f"cannot open {message_path}"))
    assert error["path"] == "broken.json"
    assert error["message"] == "cannot open secret.txt"


def test_redact_text_local_paths_logs_repo_root_resolve_failure_without_leaking_path(monkeypatch, caplog):
    class FailingPath:
        def __init__(self, value):
            self.value = value

        def resolve(self, strict=False):
            raise OSError(f"cannot resolve {self.value}")

    monkeypatch.setattr(path_redaction, "Path", FailingPath)
    caplog.set_level(logging.WARNING, logger=path_redaction.__name__)

    redacted = redact_text_local_paths("release date 2026/05/01", repo_root="/secret/repo")

    messages = [record.getMessage() for record in caplog.records]
    assert redacted == "release date 2026/05/01"
    assert messages == ["Role-Aware Dashboard Toolkit path redaction could not resolve repo root (OSError)."]
    assert "/secret/repo" not in messages[0]


def test_redact_text_local_paths_logs_absolute_path_resolve_failure_without_leaking_path(monkeypatch, caplog):
    class FailingPath:
        def __init__(self, value):
            self.value = value

        def resolve(self, strict=False):
            raise OSError(f"cannot resolve {self.value}")

    monkeypatch.setattr(path_redaction, "Path", FailingPath)
    caplog.set_level(logging.WARNING, logger=path_redaction.__name__)

    redacted = redact_text_local_paths("/secret/report.txt")

    messages = [record.getMessage() for record in caplog.records]
    assert redacted == "<redacted-local-path>"
    assert messages == ["Role-Aware Dashboard Toolkit path redaction could not resolve absolute path (OSError)."]
    assert "/secret/report.txt" not in messages[0]
