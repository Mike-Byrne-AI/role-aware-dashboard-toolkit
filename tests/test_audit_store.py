import errno
import json
import logging
import os
import queue
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import role_aware_dashboard_toolkit.audit as audit_module
import role_aware_dashboard_toolkit.store_diagnostics as store_diagnostics
from role_aware_dashboard_toolkit import AuditLog, FileAuditStore, InMemoryAuditStore
from role_aware_dashboard_toolkit.diagnostics import diagnostic_text
from role_aware_dashboard_toolkit.audit_store import (
    AUDIT_EVENT_SCHEMA_VERSION,
    redact_audit_event,
)
from role_aware_dashboard_toolkit.store_diagnostics import StorePathSecurityError


def test_inmemory_audit_store_appends_and_reads():
    store = InMemoryAuditStore()
    event = {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "test", "ts": "now"}
    store.append(event)
    rows = store.read_all()
    assert rows == [event]


def test_inmemory_audit_store_preserves_append_and_read_mutation_isolation():
    store = InMemoryAuditStore()
    source = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "test",
        "ts": "now",
        "detail": {"status": "ok"},
    }
    store.append(source)
    source["detail"]["status"] = "mutated-after-append"

    first = store.read_all()
    assert first[0]["detail"]["status"] == "ok"
    first[0]["detail"]["status"] = "mutated-after-read"

    second = store.read_all()
    assert second[0]["detail"]["status"] == "ok"


def test_inmemory_audit_store_coerces_non_json_values_with_default_str():
    store = InMemoryAuditStore()

    class _Value:
        def __str__(self):
            return "coerced-value"

    store.append(
        {
            "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "type": "test",
            "ts": "now",
            "detail": _Value(),
        }
    )

    row = store.read_all()[0]
    assert row["detail"] == "coerced-value"


def test_audit_stores_sanitize_nested_non_finite_numbers(tmp_path):
    event = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "diagnostic",
        "ts": "now",
        "detail": {
            "nan": float("nan"),
            "positive_infinity": [float("inf")],
            "negative_infinity": ({"value": float("-inf")},),
            "finite": 1.25,
        },
    }
    expected = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "diagnostic",
        "ts": "now",
        "detail": {
            "nan": None,
            "positive_infinity": [None],
            "negative_infinity": [{"value": None}],
            "finite": 1.25,
        },
    }

    assert redact_audit_event(event) == expected

    memory_store = InMemoryAuditStore()
    memory_store.append(event)
    assert memory_store.read_all() == [expected]

    file_path = tmp_path / "audit.jsonl"
    file_store = FileAuditStore(str(file_path))
    file_store.append(event)
    assert file_store.read_all() == [expected]
    persisted = file_path.read_text(encoding="utf-8")
    assert "NaN" not in persisted
    assert "Infinity" not in persisted


def test_audit_log_export_jsonl_emits_strict_json_for_non_finite_values():
    event = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "diagnostic",
        "ts": "now",
        "detail": [float("nan"), {"value": float("inf")}],
    }

    exported = AuditLog().export_jsonl(events=[event, float("-inf")])

    assert exported.splitlines() == [
        '{"schema_version": 1, "type": "diagnostic", "ts": "now", "detail": [null, {"value": null}]}',
        "null",
    ]
    assert "NaN" not in exported
    assert "Infinity" not in exported


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029", "\n", "\r\n"])
def test_file_audit_store_round_trips_string_line_separators(tmp_path, separator):
    path = tmp_path / "audit.jsonl"
    store = FileAuditStore(str(path))
    events = [
        {"type": "before", "detail": "ordinary text"},
        {"type": "multiline", "detail": {"message": f"first{separator}second"}},
        {"type": "after", "detail": "more ordinary text"},
    ]

    store.append_many(events)

    assert store.read_all() == events
    assert store.read_errors == []


@pytest.mark.parametrize("record_separator", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_file_audit_store_reports_physical_line_after_unicode_text(
    tmp_path, record_separator
):
    path = tmp_path / "audit.jsonl"
    before = {"type": "before", "detail": "first\u0085second\u2028third\u2029fourth\nlast"}
    after = {"type": "after", "detail": "healthy neighboring record"}
    path.write_bytes(
        record_separator.join(
            [
                json.dumps(before, ensure_ascii=False),
                "",
                "{not json",
                json.dumps(after),
                "",
            ]
        ).encode("utf-8")
    )
    store = FileAuditStore(str(path))

    assert store.read_all() == [before, after]
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"
    assert store.read_errors[0]["message"].startswith("line 3:")


def test_file_audit_store_records_corrupt_jsonl_read_errors(tmp_path):
    path = tmp_path / "audit.jsonl"
    valid = {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "good", "ts": "now"}
    path.write_text(
        "\n".join(
            [
                json.dumps(valid),
                "{not json",
                json.dumps(["not", "an", "object"]),
                "",
            ]
        ),
        encoding="utf-8",
    )
    store = FileAuditStore(str(path))

    assert store.read_all() == [valid]
    assert len(store.read_errors) == 2
    assert store.read_errors[0]["path"] == "audit.jsonl"
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"
    assert store.read_errors[0]["exception_type"] == "JSONDecodeError"
    assert "line 2" in store.read_errors[0]["message"]
    assert store.read_errors[1]["path"] == "audit.jsonl"
    assert store.read_errors[1]["error_type"] == "list"
    assert store.read_errors[1]["exception_type"] == "list"
    assert str(tmp_path) not in "\n".join(error["path"] for error in store.read_errors)

    store.clear_read_errors()
    assert store.read_errors == []


def test_file_audit_store_rejects_non_finite_json_and_continues(tmp_path):
    path = tmp_path / "audit.jsonl"
    valid_before = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "before",
        "ts": "now",
    }
    valid_after = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "after",
        "ts": "later",
    }
    path.write_text(
        "\n".join(
            [
                json.dumps(valid_before),
                '{"type": "nan", "detail": NaN}',
                '{"type": "positive", "detail": Infinity}',
                '{"type": "negative", "detail": -Infinity}',
                '{"type": "overflow", "detail": 1e9999}',
                json.dumps(valid_after),
            ]
        ),
        encoding="utf-8",
    )
    store = FileAuditStore(str(path))

    assert store.read_all() == [valid_before, valid_after]
    assert len(store.read_errors) == 4
    assert all(error["error_type"] == "ValueError" for error in store.read_errors)
    assert [f"line {line_number}" in error["message"] for line_number, error in zip(range(2, 6), store.read_errors)] == [
        True,
        True,
        True,
        True,
    ]


def test_file_audit_store_records_metadata_probe_errors(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps(
            {
                "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
                "type": "inside",
                "ts": "now",
            }
        ),
        encoding="utf-8",
    )
    store = FileAuditStore(str(path))
    original_stat = Path.stat
    original_is_symlink = Path.is_symlink

    def denied_stat(path_to_probe, *args, **kwargs):
        if path_to_probe == path:
            raise PermissionError(
                13,
                r"denied via \\private-server\secret share\audit.jsonl",
                str(path),
            )
        return original_stat(path_to_probe, *args, **kwargs)

    def simulated_is_symlink(path_to_probe):
        if path_to_probe == path:
            return False
        return original_is_symlink(path_to_probe)

    monkeypatch.setattr(Path, "is_symlink", simulated_is_symlink)
    monkeypatch.setattr(Path, "stat", denied_stat)

    assert store.read_all() == []
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "PermissionError"
    assert "private-server" not in store.read_errors[0]["message"]
    assert str(tmp_path) not in "\n".join(store.read_errors[0].values())


def test_file_audit_store_treats_read_disappearance_as_missing(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps(
            {
                "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
                "type": "transient",
                "ts": "now",
            }
        ),
        encoding="utf-8",
    )
    store = FileAuditStore(str(path))
    original_open = store_diagnostics.os.open

    def disappearing_open(path_to_open, flags):
        if Path(path_to_open) == path:
            path.unlink()
            raise FileNotFoundError(str(path))
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", disappearing_open)

    assert store.read_all() == []
    assert store.read_errors == []


def test_file_audit_store_read_rejects_hard_link_alias(tmp_path, monkeypatch):
    outside = tmp_path / "outside-audit.jsonl"
    outside_payload = json.dumps(
        {
            "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "type": "outside-secret",
            "ts": "private",
        }
    )
    outside.write_text(outside_payload, encoding="utf-8")
    path = tmp_path / "store" / "audit.jsonl"
    path.parent.mkdir()
    try:
        os.link(outside, path)
    except (OSError, NotImplementedError):
        pytest.skip("hard-link creation is not available in this environment")
    store = FileAuditStore(str(path))
    original_open = store_diagnostics.os.open

    def guarded_open(path_to_open, flags):
        if Path(path_to_open) == path:
            raise AssertionError("multi-link audit records must not be opened")
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", guarded_open)

    assert store.read_all() == []
    assert len(store.read_errors) == 1
    error = store.read_errors[0]
    assert error["error_type"] == "StorePathSecurityError"
    assert error["path"] == "audit.jsonl"
    assert "outside-secret" not in "\n".join(error.values())
    assert str(outside) not in "\n".join(error.values())
    assert outside.read_text(encoding="utf-8") == outside_payload


def test_file_audit_store_rejects_opened_file_substitution(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_text(
        json.dumps(
            {
                "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
                "type": "inside",
                "ts": "now",
            }
        ),
        encoding="utf-8",
    )
    replacement = tmp_path / "outside-audit.jsonl"
    replacement.write_text('{"type": "outside-secret"}', encoding="utf-8")
    store = FileAuditStore(str(path))
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_read = store_diagnostics.os.read
    original_fstat = store_diagnostics.os.fstat

    def substituted_open(path_to_open, flags):
        if Path(path_to_open) == path:
            fd = original_open(replacement, flags)
            opened_fds.append(fd)
            return fd
        return original_open(path_to_open, flags)

    def guarded_read(fd, size):
        if fd in opened_fds:
            raise AssertionError("replacement audit payload must not be read")
        return original_read(fd, size)

    monkeypatch.setattr(store_diagnostics.os, "open", substituted_open)
    monkeypatch.setattr(store_diagnostics.os, "read", guarded_read)

    assert store.read_all() == []
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"
    assert "outside-secret" not in "\n".join(store.read_errors[0].values())
    assert str(replacement) not in "\n".join(store.read_errors[0].values())
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_audit_log_events_include_schema_and_source():
    audit = AuditLog()
    audit.log_control_change("temperature", 0.7, 0.8, role="Admin")
    evt = audit.recent(1)[0]
    assert evt["schema_version"] == AUDIT_EVENT_SCHEMA_VERSION
    assert evt["source"] == "ui"


def test_audit_store_redacts_sensitive_keys_and_local_paths():
    store = InMemoryAuditStore()
    event = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "command_execution",
        "ts": "now",
        "detail": "release date 2026/05/01 ratio 3/4 run /tmp/repo/reports/audit.json",
        "new": {
            "cwd": "/tmp/repo",
            "executable_path": r"C:\tools\runner.exe",
            "argv": [r"C:\tools\runner.exe", "audit", "/tmp/repo"],
            "authorization": "Bearer top-secret",
            "stdout": "wrote /tmp/repo/reports/audit.json",
        },
        "api_key": "abc123",
    }
    store.append(event)
    row = store.read_all()[0]

    assert (
        row["detail"] == "release date 2026/05/01 ratio 3/4 run <redacted-local-path>"
    )
    assert row["new"]["cwd"] == "<redacted-local-path>"
    assert row["new"]["executable_path"] == "<redacted-local-path>"
    assert row["new"]["argv"][0] == "<redacted-local-path>"
    assert row["new"]["argv"][2] == "<redacted-local-path>"
    assert row["new"]["authorization"] == "<redacted-secret>"
    assert row["new"]["stdout"] == "wrote <redacted-local-path>"
    assert row["api_key"] == "<redacted-secret>"


def test_audit_boundaries_redact_pathlike_values_and_keys(tmp_path):
    class BytesPath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return os.fsencode(self.value)

    private_path = tmp_path / "Private Root" / "artifact.json"
    event = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "custom",
        "path": private_path,
        "nested": (BytesPath(private_path),),
        private_path: "path-key",
        "<redacted-local-path>": "literal-marker",
        "api_key": "top-secret",
    }
    expected = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "custom",
        "path": "<redacted-local-path>",
        "nested": ["<redacted-local-path>"],
        "<redacted-local-path>#2": "path-key",
        "<redacted-local-path>": "literal-marker",
        "api_key": "<redacted-secret>",
    }

    memory_store = InMemoryAuditStore()
    memory_store.append(event)
    assert memory_store.read_all() == [expected]

    file_path = tmp_path / "audit.jsonl"
    file_store = FileAuditStore(str(file_path))
    file_store.append(event)
    assert file_store.read_all() == [expected]
    assert str(private_path) not in file_path.read_text(encoding="utf-8")

    exported = AuditLog().export_jsonl(events=[event])
    assert json.loads(exported) == expected
    assert str(private_path) not in exported


def test_audit_sensitive_path_keys_stay_masked_through_path_redaction(tmp_path):
    path_key = tmp_path / "private" / "api_key.json"
    string_key = str(tmp_path / "private" / "token.txt")
    event = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "custom",
        path_key: "path-secret",
        string_key: "string-secret",
        "<redacted-local-path>": "literal-marker",
        "nested": ({path_key: "nested-secret"},),
    }

    redacted = redact_audit_event(event)

    assert redacted == {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "custom",
        "<redacted-local-path>#2": "<redacted-secret>",
        "<redacted-local-path>#3": "<redacted-secret>",
        "<redacted-local-path>": "literal-marker",
        "nested": [{"<redacted-local-path>": "<redacted-secret>"}],
    }
    assert len(redacted) == len(event)
    exported = AuditLog().export_jsonl(events=[event])
    assert json.loads(exported) == redacted
    assert str(tmp_path) not in exported
    assert "path-secret" not in exported
    assert "string-secret" not in exported
    assert "nested-secret" not in exported


def test_audit_control_change_masks_pathlike_sensitive_key_values(tmp_path):
    class BytesPath(os.PathLike):
        def __init__(self, value):
            self.value = value

        def __fspath__(self):
            return os.fsencode(self.value)

    sensitive_key = tmp_path / "private" / "api_token.txt"

    for key_value in (sensitive_key, BytesPath(sensitive_key)):
        redacted = redact_audit_event(
            {
                "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
                "type": "control_change",
                "key": key_value,
                "old": "old-secret-value",
                "new": "new-secret-value",
            }
        )

        assert redacted["key"] == "<redacted-local-path>"
        assert redacted["old"] == "<redacted-secret>"
        assert redacted["new"] == "<redacted-secret>"


def test_audit_invalid_pathlike_names_fail_closed_without_leaky_logs(caplog):
    class RaisingPath(os.PathLike):
        def __fspath__(self):
            raise RuntimeError(r"failed at C:\Private\api_key.txt")

    caplog.set_level(logging.WARNING, logger="role_aware_dashboard_toolkit.path_redaction")

    redacted = redact_audit_event(
        {
            "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "type": "control_change",
            "key": RaisingPath(),
            RaisingPath(): "mapping-secret",
            "old": "old-secret-value",
            "new": "new-secret-value",
        }
    )

    assert redacted["key"] == "<redacted-local-path>"
    assert redacted["<redacted-local-path>"] == "<redacted-secret>"
    assert redacted["old"] == "<redacted-secret>"
    assert redacted["new"] == "<redacted-secret>"
    warnings = "\n".join(record.getMessage() for record in caplog.records)
    assert warnings.count("could not read path-like value (RuntimeError)") == 2
    assert "Private" not in warnings


def test_audit_log_masks_sensitive_control_change_values():
    audit = AuditLog()
    audit.log_control_change("api_token", "old-secret", "new-secret", role="Admin")

    event = audit.recent(1)[0]
    assert event["key"] == "api_token"
    assert event["old"] == "<redacted-secret>"
    assert event["new"] == "<redacted-secret>"


def test_audit_log_writer_status_surfaces_dropped_event_accounting():
    class _FullQueue:
        def put_nowait(self, _item):
            raise queue.Full

        def qsize(self):
            return 0

    audit = AuditLog()
    audit._writer_queue = _FullQueue()
    audit.log("control_change", key="threshold", old_value=1, new_value=2, role="Admin")

    status = audit.writer_status()
    assert status["queue_purpose"] == "audit_persistence_only"
    assert status["dropped_events"] == 1
    assert status["queued_events"] == 0
    assert status["writer_error_count"] == 0
    assert status["last_writer_error"] == {}


def test_audit_log_writer_status_surfaces_persistence_failures_without_losing_memory_events():
    class _FailingStore:
        def append(self, _event):
            raise RuntimeError("disk write failed")

    audit = AuditLog()
    audit._writer_store = _FailingStore()
    audit._writer_queue = queue.Queue()
    audit.log("control_change", key="threshold", old_value=1, new_value=2, role="Admin")
    audit._writer_stop.set()

    audit._writer_loop()
    status = audit.writer_status()

    assert len(audit.all_events()) == 1
    assert status["writer_error_count"] == 1
    assert status["last_writer_error"]["error_type"] == "RuntimeError"
    assert status["last_writer_error"]["exception_type"] == "RuntimeError"
    assert status["last_writer_error"]["message"] == diagnostic_text("RADT-AUDIT-IO")


def test_file_audit_store_append_preserves_order_flags_and_native_newlines(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "nested" / "audit.jsonl"
    store = FileAuditStore(str(path))
    events = [
        {
            "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "type": "first",
            "ts": "now",
            "detail": "caf\u00e9",
        },
        {
            "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "type": "second",
            "ts": "later",
            "detail": "snowman \u2603",
        },
    ]
    append_calls = []
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_fstat = store_diagnostics.os.fstat

    def tracked_open(path_to_open, flags, mode=0o777):
        if flags & os.O_CREAT:
            fd = original_open(path_to_open, flags, mode)
        else:
            fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path and flags & os.O_APPEND:
            append_calls.append((flags, mode))
            opened_fds.append(fd)
        return fd

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)

    assert store.append(events[0]) is None
    assert store.append(events[1]) is None

    expected_text = "".join(
        json.dumps(event, ensure_ascii=False, default=str) + os.linesep
        for event in events
    )
    assert path.read_bytes() == expected_text.encode("utf-8")
    assert store.read_all() == events
    assert store.read_errors == []

    assert len(append_calls) == 2
    create_flags, create_mode = append_calls[0]
    existing_flags, _ = append_calls[1]
    assert create_mode == 0o666
    assert create_flags & os.O_CREAT == os.O_CREAT
    assert create_flags & os.O_EXCL == os.O_EXCL
    assert existing_flags & os.O_CREAT == 0
    assert existing_flags & os.O_EXCL == 0
    for flags in (create_flags, existing_flags):
        assert flags & os.O_WRONLY == os.O_WRONLY
        assert flags & os.O_APPEND == os.O_APPEND
        assert flags & os.O_TRUNC == 0
        for flag_name in (
            "O_BINARY",
            "O_CLOEXEC",
            "O_NOINHERIT",
            "O_NOCTTY",
            "O_NOFOLLOW",
            "O_NONBLOCK",
        ):
            flag = getattr(os, flag_name, 0)
            if flag:
                assert flags & flag == flag
    for fd in set(opened_fds):
        with pytest.raises(OSError):
            original_fstat(fd)


def test_file_audit_store_append_rejects_lost_create_race(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    store = FileAuditStore(str(path))
    raced_payload = b"raced target must remain unchanged"
    create_attempts = 0
    original_open = store_diagnostics.os.open

    def racing_open(path_to_open, flags, mode=0o777):
        nonlocal create_attempts
        if Path(path_to_open) == path and flags & os.O_EXCL:
            create_attempts += 1
            path.write_bytes(raced_payload)
        if flags & os.O_CREAT:
            return original_open(path_to_open, flags, mode)
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", racing_open)

    with pytest.raises(StorePathSecurityError):
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "blocked"}
        )

    assert create_attempts == 1
    assert path.read_bytes() == raced_payload
    assert store.read_errors == []


def test_file_audit_store_append_rejects_opened_file_substitution(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "audit.jsonl"
    original_payload = b"original audit bytes"
    path.write_bytes(original_payload)
    outside = tmp_path / "outside.jsonl"
    outside_payload = b"outside sentinel bytes"
    outside.write_bytes(outside_payload)
    store = FileAuditStore(str(path))
    opened_fds = []
    write_attempted = False
    original_open = store_diagnostics.os.open
    original_write = store_diagnostics.os.write
    original_fstat = store_diagnostics.os.fstat

    def substituted_open(path_to_open, flags, mode=0o777):
        if Path(path_to_open) == path:
            fd = original_open(outside, flags)
            opened_fds.append(fd)
            return fd
        if flags & os.O_CREAT:
            return original_open(path_to_open, flags, mode)
        return original_open(path_to_open, flags)

    def guarded_write(fd, payload):
        nonlocal write_attempted
        if fd in opened_fds:
            write_attempted = True
            raise AssertionError("replacement audit target must not be written")
        return original_write(fd, payload)

    monkeypatch.setattr(store_diagnostics.os, "open", substituted_open)
    monkeypatch.setattr(store_diagnostics.os, "write", guarded_write)

    with pytest.raises(StorePathSecurityError):
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "blocked"}
        )

    assert write_attempted is False
    assert path.read_bytes() == original_payload
    assert outside.read_bytes() == outside_payload
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


@pytest.mark.parametrize(
    ("file_mode", "inode", "link_count"),
    [
        (stat.S_IFIFO, 1, 1),
        (stat.S_IFREG, 0, 1),
        (stat.S_IFREG, 1, 0),
    ],
)
def test_file_audit_store_append_rejects_unsafe_initial_file_identity(
    tmp_path,
    monkeypatch,
    file_mode,
    inode,
    link_count,
):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    store = FileAuditStore(str(path))
    original_stat = Path.stat
    original_is_symlink = Path.is_symlink
    original_open = store_diagnostics.os.open

    def simulated_is_symlink(path_to_probe):
        if path_to_probe == path:
            return False
        return original_is_symlink(path_to_probe)

    def simulated_stat(path_to_probe, *args, **kwargs):
        if path_to_probe == path:
            return SimpleNamespace(
                st_mode=file_mode,
                st_ino=inode,
                st_dev=1,
                st_nlink=link_count,
            )
        return original_stat(path_to_probe, *args, **kwargs)

    def guarded_open(path_to_open, flags, mode=0o777):
        if Path(path_to_open) == path:
            raise AssertionError("unsafe append targets must not be opened")
        if flags & os.O_CREAT:
            return original_open(path_to_open, flags, mode)
        return original_open(path_to_open, flags)

    monkeypatch.setattr(Path, "is_symlink", simulated_is_symlink)
    monkeypatch.setattr(Path, "stat", simulated_stat)
    monkeypatch.setattr(store_diagnostics.os, "open", guarded_open)

    with pytest.raises(StorePathSecurityError):
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "blocked"}
        )


@pytest.mark.parametrize(
    ("file_mode", "inode", "link_count"),
    [
        (stat.S_IFIFO, 1, 1),
        (stat.S_IFREG, 0, 1),
        (stat.S_IFREG, 1, 0),
    ],
)
def test_file_audit_store_append_rejects_unsafe_opened_file_identity(
    tmp_path,
    monkeypatch,
    file_mode,
    inode,
    link_count,
):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    store = FileAuditStore(str(path))
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_fstat = store_diagnostics.os.fstat
    original_write = store_diagnostics.os.write

    def tracked_open(path_to_open, flags, mode=0o777):
        if flags & os.O_CREAT:
            fd = original_open(path_to_open, flags, mode)
        else:
            fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def simulated_fstat(fd):
        if fd in opened_fds:
            return SimpleNamespace(
                st_mode=file_mode,
                st_ino=inode,
                st_dev=1,
                st_nlink=link_count,
            )
        return original_fstat(fd)

    def guarded_write(fd, payload):
        if fd in opened_fds:
            raise AssertionError("unsafe opened append targets must not be written")
        return original_write(fd, payload)

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "fstat", simulated_fstat)
    monkeypatch.setattr(store_diagnostics.os, "write", guarded_write)

    with pytest.raises(StorePathSecurityError):
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "blocked"}
        )
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_file_audit_store_append_rejects_hard_link_alias(tmp_path, monkeypatch):
    outside = tmp_path / "outside.jsonl"
    outside_payload = b"outside sentinel bytes"
    outside.write_bytes(outside_payload)
    path = tmp_path / "audit.jsonl"
    try:
        os.link(outside, path)
    except (OSError, NotImplementedError):
        pytest.skip("hard-link creation is not available in this environment")
    store = FileAuditStore(str(path))
    original_open = store_diagnostics.os.open

    def guarded_open(path_to_open, flags, mode=0o777):
        if Path(path_to_open) == path:
            raise AssertionError("multi-link append targets must not be opened")
        if flags & os.O_CREAT:
            return original_open(path_to_open, flags, mode)
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", guarded_open)

    with pytest.raises(StorePathSecurityError):
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "blocked"}
        )
    assert outside.read_bytes() == outside_payload


def test_file_audit_store_append_completes_short_writes(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    store = FileAuditStore(str(path))
    opened_fds = []
    write_calls = 0
    original_open = store_diagnostics.os.open
    original_write = store_diagnostics.os.write

    def tracked_open(path_to_open, flags, mode=0o777):
        if flags & os.O_CREAT:
            fd = original_open(path_to_open, flags, mode)
        else:
            fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def partial_write(fd, payload):
        nonlocal write_calls
        if fd in opened_fds:
            write_calls += 1
            rendered = bytes(payload)
            if write_calls == 1:
                split_at = max(1, len(rendered) // 2)
                return original_write(fd, rendered[:split_at])
        return original_write(fd, payload)

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "write", partial_write)
    event = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "partial",
        "detail": "caf\u00e9",
    }

    store.append(event)

    expected = (
        json.dumps(event, ensure_ascii=False, default=str) + os.linesep
    ).encode("utf-8")
    assert path.read_bytes() == expected
    assert write_calls == 2


def test_file_audit_store_append_preserves_partial_prefix_on_write_failure(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    store = FileAuditStore(str(path))
    opened_fds = []
    expected_prefix = b""
    write_calls = 0
    original_open = store_diagnostics.os.open
    original_write = store_diagnostics.os.write
    original_fstat = store_diagnostics.os.fstat

    def tracked_open(path_to_open, flags, mode=0o777):
        if flags & os.O_CREAT:
            fd = original_open(path_to_open, flags, mode)
        else:
            fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def partial_then_failing_write(fd, payload):
        nonlocal expected_prefix, write_calls
        if fd in opened_fds:
            write_calls += 1
            if write_calls == 1:
                rendered = bytes(payload)
                split_at = max(1, len(rendered) // 2)
                expected_prefix = rendered[:split_at]
                return original_write(fd, expected_prefix)
            raise PermissionError(13, "append continuation failed")
        return original_write(fd, payload)

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "write", partial_then_failing_write)

    with pytest.raises(PermissionError, match="append continuation failed"):
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "partial"}
        )

    assert write_calls == 2
    assert path.read_bytes() == expected_prefix
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_file_audit_store_append_zero_write_progress_raises(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    store = FileAuditStore(str(path))
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_fstat = store_diagnostics.os.fstat
    original_write = store_diagnostics.os.write

    def tracked_open(path_to_open, flags, mode=0o777):
        if flags & os.O_CREAT:
            fd = original_open(path_to_open, flags, mode)
        else:
            fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def zero_write(fd, payload):
        if fd in opened_fds:
            return 0
        return original_write(fd, payload)

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "write", zero_write)

    with pytest.raises(OSError) as caught:
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "blocked"}
        )
    assert caught.value.errno == errno.EIO
    assert path.read_bytes() == b""
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_file_audit_store_append_preserves_primary_error_after_close_failure(
    tmp_path,
    monkeypatch,
    caplog,
):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    store = FileAuditStore(str(path))
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_write = store_diagnostics.os.write
    original_close = store_diagnostics.os.close
    original_fstat = store_diagnostics.os.fstat

    def tracked_open(path_to_open, flags, mode=0o777):
        if flags & os.O_CREAT:
            fd = original_open(path_to_open, flags, mode)
        else:
            fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def failing_write(fd, payload):
        if fd in opened_fds:
            raise PermissionError(13, "append write failed")
        return original_write(fd, payload)

    def failing_close(fd):
        original_close(fd)
        if fd in opened_fds:
            raise PermissionError(13, "descriptor close failed")

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "write", failing_write)
    monkeypatch.setattr(store_diagnostics.os, "close", failing_close)

    with caplog.at_level("WARNING", logger="role_aware_dashboard_toolkit.store_diagnostics"):
        with pytest.raises(PermissionError, match="append write failed"):
            store.append(
                {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "blocked"}
            )

    assert path.read_bytes() == b""
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "descriptor cleanup failed after PermissionError: PermissionError" in messages
    assert "append write failed" not in messages
    assert "descriptor close failed" not in messages
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_file_audit_store_append_surfaces_close_failure(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    store = FileAuditStore(str(path))
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_close = store_diagnostics.os.close
    original_fstat = store_diagnostics.os.fstat

    def tracked_open(path_to_open, flags, mode=0o777):
        if flags & os.O_CREAT:
            fd = original_open(path_to_open, flags, mode)
        else:
            fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def failing_close(fd):
        original_close(fd)
        if fd in opened_fds:
            raise PermissionError(13, "descriptor close failed")

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "close", failing_close)
    event = {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "type": "close-failure",
    }

    with pytest.raises(PermissionError, match="descriptor close failed"):
        store.append(event)

    expected = (
        json.dumps(event, ensure_ascii=False, default=str) + os.linesep
    ).encode("utf-8")
    assert path.read_bytes() == expected
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_file_audit_store_append_rejects_invalid_utf8_text(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = FileAuditStore(str(path))

    with pytest.raises(UnicodeEncodeError):
        store.append(
            {
                "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
                "type": "invalid-unicode",
                "detail": "\ud800",
            }
        )

    assert path.read_bytes() == b""
    assert store.read_errors == []


def test_file_audit_store_append_rejects_symlink_target(tmp_path):
    outside = tmp_path / "outside_audit.jsonl"
    outside.write_text("", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    store = FileAuditStore(str(link))
    with pytest.raises(StorePathSecurityError):
        store.append(
            {"schema_version": AUDIT_EVENT_SCHEMA_VERSION, "type": "test", "ts": "now"}
        )
    assert outside.read_text(encoding="utf-8") == ""


def test_file_audit_store_read_rejects_symlink_target(tmp_path):
    outside = tmp_path / "outside_audit.jsonl"
    outside.write_text(
        json.dumps(
            {
                "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
                "type": "outside",
                "ts": "now",
            }
        ),
        encoding="utf-8",
    )
    link = tmp_path / "audit.jsonl"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    store = FileAuditStore(str(link))
    assert store.read_all() == []
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"


def test_audit_log_writer_error_redacts_local_paths(tmp_path):
    class _FailingStore:
        def append(self, _event):
            raise OSError(f"cannot write {tmp_path / 'audit.jsonl'}")

    audit = AuditLog()
    audit._writer_store = _FailingStore()
    audit._writer_queue = queue.Queue()
    audit.log("control_change", key="threshold", old_value=1, new_value=2, role="Admin")
    audit._writer_stop.set()

    audit._writer_loop()
    message = audit.writer_status()["last_writer_error"]["message"]
    assert message == diagnostic_text("RADT-AUDIT-IO")
    assert str(tmp_path) not in message


class _ControllableWriterThread:
    def __init__(self, *, alive=True):
        self.alive = alive
        self.join_timeouts = []

    def is_alive(self):
        return self.alive

    def join(self, timeout=None):
        self.join_timeouts.append(timeout)


class _StartFailureThread(_ControllableWriterThread):
    def __init__(self, error, *, alive_after_failure, probe_error=None):
        super().__init__(alive=False)
        self.error = error
        self.alive_after_failure = alive_after_failure
        self.probe_error = probe_error

    def start(self):
        self.alive = self.alive_after_failure
        raise self.error

    def is_alive(self):
        if self.probe_error is not None:
            probe_error = self.probe_error
            self.probe_error = None
            raise probe_error
        return super().is_alive()


class _RecordingStore:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


def _install_writer_state(audit, path, *, alive=True):
    writer_thread = _ControllableWriterThread(alive=alive)
    writer_queue = queue.Queue()
    writer_store = _RecordingStore()
    audit._writer_thread = writer_thread
    audit._writer_queue = writer_queue
    audit._writer_store = writer_store
    audit._writer_path = str(path)
    return writer_thread, writer_queue, writer_store


def _assert_writer_state_cleared(audit):
    assert audit._writer_thread is None
    assert audit._writer_queue is None
    assert audit._writer_store is None
    assert audit._writer_path is None


@pytest.mark.parametrize("failure_stage", ["store", "queue", "thread"])
def test_start_writer_constructor_failure_is_atomic_and_retryable(
    tmp_path, monkeypatch, failure_stage
):
    audit = AuditLog()
    audit.dropped = 4
    audit._writer_error_count = 8
    audit._last_writer_error = {"error_type": "OldError", "message": "old"}
    raw_path = str(tmp_path / "private" / failure_stage / "events.jsonl")
    error = RuntimeError(f"{failure_stage} construction failed at {raw_path}")

    def fail_construction(*_args, **_kwargs):
        raise error

    with monkeypatch.context() as patch:
        if failure_stage == "store":
            patch.setattr(audit_module, "FileAuditStore", fail_construction)
        elif failure_stage == "queue":
            patch.setattr(audit_module.queue, "Queue", fail_construction)
        else:
            patch.setattr(audit_module.threading, "Thread", fail_construction)

        with pytest.raises(RuntimeError) as caught:
            audit.start_writer(raw_path)

    assert caught.value is error
    assert audit._writer_stop.is_set()
    _assert_writer_state_cleared(audit)
    failed_status = audit.writer_status()
    assert failed_status["writer_active"] is False
    assert failed_status["writer_path"] == ""
    assert failed_status["queued_events"] == 0
    assert failed_status["dropped_events"] == 4
    assert failed_status["writer_error_count"] == 1
    assert failed_status["last_writer_error"]["error_type"] == "RuntimeError"
    assert failed_status["last_writer_error"]["message"] == diagnostic_text("RADT-AUDIT-IO")
    assert raw_path not in failed_status["last_writer_error"]["message"]
    assert (
        audit_module._get_writer_startup_error(error)
        == failed_status["last_writer_error"]
    )

    audit.log("memory_only_after_start_failure", detail=failure_stage)
    assert [event["type"] for event in audit.all_events()] == [
        "memory_only_after_start_failure"
    ]
    assert audit.writer_status()["dropped_events"] == 4

    retry_path = tmp_path / f"{failure_stage}_retry.jsonl"
    assert audit.start_writer(str(retry_path)) is True
    audit.log("retry_event", detail=failure_stage)
    audit.stop_writer()

    persisted = FileAuditStore(str(retry_path)).read_all()
    assert [event["type"] for event in persisted] == ["audit_writer_start", "retry_event", "audit_writer_stop"]
    retry_status = audit.writer_status()
    assert retry_status["writer_active"] is False
    assert retry_status["writer_error_count"] == 0
    assert retry_status["last_writer_error"] == {}
    assert retry_status["dropped_events"] == 4


def test_start_writer_pre_live_failure_clears_state_and_rethrows_original(
    tmp_path, monkeypatch
):
    audit = AuditLog()
    raw_path = str(tmp_path / "private" / "pre_live.jsonl")
    error = RuntimeError(f"thread start failed at {raw_path}")
    writer_thread = _StartFailureThread(error, alive_after_failure=False)

    with monkeypatch.context() as patch:
        patch.setattr(audit_module.threading, "Thread", lambda **_kwargs: writer_thread)
        with pytest.raises(RuntimeError) as caught:
            audit.start_writer(raw_path)

    assert caught.value is error
    assert audit._writer_stop.is_set()
    assert writer_thread.join_timeouts == []
    _assert_writer_state_cleared(audit)
    failed_status = audit.writer_status()
    assert failed_status["writer_error_count"] == 1
    assert failed_status["last_writer_error"]["message"] == diagnostic_text("RADT-AUDIT-IO")
    assert raw_path not in failed_status["last_writer_error"]["message"]
    assert (
        audit_module._get_writer_startup_error(error)
        == failed_status["last_writer_error"]
    )

    audit.log("memory_only_after_pre_live_failure")
    retry_path = tmp_path / "pre_live_retry.jsonl"
    assert audit.start_writer(str(retry_path)) is True
    audit.log("retry_event")
    audit.stop_writer()
    assert [event["type"] for event in FileAuditStore(str(retry_path)).read_all()] == [
        "audit_writer_start", "retry_event", "audit_writer_stop"
    ]
    assert audit.writer_status()["writer_error_count"] == 0


def test_start_writer_live_failure_retains_ownership_until_reaped(
    tmp_path, monkeypatch
):
    audit = AuditLog()
    audit.dropped = 2
    raw_path = str(tmp_path / "private" / "live_failure.jsonl")
    error = RuntimeError(f"thread start failed after launch at {raw_path}")
    writer_thread = _StartFailureThread(error, alive_after_failure=True)

    with monkeypatch.context() as patch:
        patch.setattr(audit_module.threading, "Thread", lambda **_kwargs: writer_thread)
        with pytest.raises(RuntimeError) as caught:
            audit.start_writer(raw_path)

    assert caught.value is error
    assert audit._writer_thread is writer_thread
    assert audit._writer_queue is not None
    assert audit._writer_store is not None
    assert audit._writer_path == raw_path
    assert audit._writer_stop.is_set()
    failed_status = audit.writer_status()
    assert failed_status["writer_active"] is True
    assert failed_status["writer_error_count"] == 1
    assert failed_status["last_writer_error"]["message"] == diagnostic_text("RADT-AUDIT-IO")
    assert raw_path not in failed_status["last_writer_error"]["message"]

    retained_queue = audit._writer_queue
    audit.log("memory_only_while_stop_pending")
    assert retained_queue.qsize() == 0
    assert audit.writer_status()["dropped_events"] == 2

    def reject_replacement(_path):
        pytest.fail(
            "replacement store must not be constructed while failed writer remains alive"
        )

    with monkeypatch.context() as patch:
        patch.setattr(audit_module, "FileAuditStore", reject_replacement)
        with pytest.raises(
            TimeoutError, match="Audit writer did not stop within 3 seconds"
        ):
            audit.start_writer(str(tmp_path / "blocked_replacement.jsonl"))

    assert audit._writer_thread is writer_thread
    assert audit._writer_queue is retained_queue
    assert audit.writer_status()["writer_error_count"] == 2
    writer_thread.alive = False

    retry_path = tmp_path / "reaped_retry.jsonl"
    assert audit.start_writer(str(retry_path)) is True
    audit.log("retry_event")
    audit.stop_writer()

    assert writer_thread.join_timeouts == [
        audit_module._WRITER_STOP_TIMEOUT_SECONDS,
        audit_module._WRITER_STOP_TIMEOUT_SECONDS,
    ]
    assert [event["type"] for event in FileAuditStore(str(retry_path)).read_all()] == [
        "audit_writer_start", "retry_event", "audit_writer_stop"
    ]
    retry_status = audit.writer_status()
    assert retry_status["writer_error_count"] == 0
    assert retry_status["last_writer_error"] == {}
    assert retry_status["dropped_events"] == 2


def test_start_writer_unknown_liveness_retains_ownership_and_logs_redacted_warning(
    tmp_path, monkeypatch, caplog
):
    audit = AuditLog()
    raw_path = str(tmp_path / "private" / "unknown_liveness.jsonl")
    start_error = RuntimeError(f"thread start failed at {raw_path}")
    probe_error = OSError(f"liveness probe failed at {raw_path}")
    writer_thread = _StartFailureThread(
        start_error,
        alive_after_failure=True,
        probe_error=probe_error,
    )

    with monkeypatch.context() as patch:
        patch.setattr(audit_module.threading, "Thread", lambda **_kwargs: writer_thread)
        with caplog.at_level("WARNING", logger=audit_module.__name__):
            with pytest.raises(RuntimeError) as caught:
                audit.start_writer(raw_path)

    assert caught.value is start_error
    assert audit._writer_thread is writer_thread
    assert audit._writer_queue is not None
    assert audit._writer_store is not None
    assert audit._writer_path == raw_path
    assert audit._writer_stop.is_set()
    status = audit.writer_status()
    assert status["writer_active"] is True
    assert status["writer_error_count"] == 1
    assert raw_path not in status["last_writer_error"]["message"]

    warning = next(
        record.getMessage()
        for record in caplog.records
        if "thread liveness" in record.getMessage()
    )
    assert diagnostic_text("RADT-AUDIT-IO") in warning
    assert raw_path not in warning

    writer_thread.alive = False
    audit.stop_writer()


def test_start_writer_marker_attachment_failure_rethrows_original_and_warns(
    tmp_path, monkeypatch, caplog
):
    raw_path = str(tmp_path / "private" / "attachment_failure.jsonl")

    class _RejectingStartupMarkerError(RuntimeError):
        def __setattr__(self, name, value):
            if name == audit_module._WRITER_STARTUP_ERROR_ATTR:
                raise AttributeError(f"cannot attach diagnostic at {raw_path}")
            super().__setattr__(name, value)

    audit = AuditLog()
    error = _RejectingStartupMarkerError(f"startup failed at {raw_path}")

    def fail_store(_path):
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(audit_module, "FileAuditStore", fail_store)
        with caplog.at_level("WARNING", logger=audit_module.__name__):
            with pytest.raises(_RejectingStartupMarkerError) as caught:
                audit.start_writer(raw_path)

    assert caught.value is error
    assert audit_module._get_writer_startup_error(error) == {}
    assert audit._writer_stop.is_set()
    _assert_writer_state_cleared(audit)
    status = audit.writer_status()
    assert status["writer_error_count"] == 1
    assert status["last_writer_error"]["message"] == diagnostic_text("RADT-AUDIT-IO")
    assert raw_path not in status["last_writer_error"]["message"]

    warning = next(
        record.getMessage()
        for record in caplog.records
        if "could not be attached" in record.getMessage()
    )
    assert diagnostic_text("RADT-AUDIT-IO") in warning
    assert raw_path not in warning


@pytest.mark.parametrize(
    ("attribute", "reader"),
    [
        (
            audit_module._WRITER_STARTUP_ERROR_ATTR,
            audit_module._get_writer_startup_error,
        ),
        (
            audit_module._WRITER_SHUTDOWN_ERROR_ATTR,
            audit_module._get_writer_shutdown_error,
        ),
    ],
)
def test_writer_error_classifier_rejects_forged_public_marker(attribute, reader):
    error = RuntimeError("unclassified failure")
    setattr(
        error,
        attribute,
        {
            "error_type": "RuntimeError",
            "exception_type": "RuntimeError",
            "message": "forged diagnostic",
        },
    )

    assert reader(error) == {}


def test_start_writer_preserves_unprintable_exception_identity(
    tmp_path, monkeypatch, caplog
):
    raw_path = str(tmp_path / "private" / "unprintable.jsonl")

    class _UnprintableStartupError(RuntimeError):
        def __str__(self):
            raise ValueError(f"cannot format {raw_path}")

    audit = AuditLog()
    error = _UnprintableStartupError("sensitive startup failure")

    def fail_store(_path):
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(audit_module, "FileAuditStore", fail_store)
        with caplog.at_level("WARNING", logger=audit_module.__name__):
            with pytest.raises(_UnprintableStartupError) as caught:
                audit.start_writer(raw_path)

    assert caught.value is error
    _assert_writer_state_cleared(audit)
    status = audit.writer_status()
    assert status["writer_error_count"] == 1
    assert status["last_writer_error"]["message"] == diagnostic_text("RADT-AUDIT-IO")
    assert audit_module._get_writer_startup_error(error) == status["last_writer_error"]
    warnings = "\n".join(record.getMessage() for record in caplog.records)
    assert warnings == ""  # Exception formatting is never attempted.
    assert raw_path not in warnings


def test_stop_writer_timeout_retains_live_state_and_records_error(tmp_path):
    audit = AuditLog()
    writer_path = tmp_path / "active.jsonl"
    writer_thread, writer_queue, writer_store = _install_writer_state(
        audit, writer_path
    )
    writer_queue.put_nowait({"queued": "event"})

    with pytest.raises(
        TimeoutError, match="Audit writer did not stop within 3 seconds"
    ) as caught:
        audit.stop_writer()

    status = audit.writer_status()
    assert audit._writer_thread is writer_thread
    assert audit._writer_queue is writer_queue
    assert audit._writer_store is writer_store
    assert audit._writer_path == str(writer_path)
    assert audit._writer_stop.is_set()
    assert writer_thread.join_timeouts == [audit_module._WRITER_STOP_TIMEOUT_SECONDS]
    assert status["writer_active"] is True
    assert status["writer_path"] == str(writer_path)
    assert status["queued_events"] == 1
    assert status["dropped_events"] == 0
    assert status["writer_error_count"] == 1
    assert status["last_writer_error"]["error_type"] == "TimeoutError"
    assert (
        audit_module._get_writer_shutdown_error(caught.value)
        == status["last_writer_error"]
    )
    assert audit_module._get_writer_startup_error(caught.value) == {}

    # The stop is recorded in the view; the live thread still owns the file.
    (stop,) = audit.all_events()
    assert stop["type"] == "audit_writer_stop"
    assert stop["detail"].startswith("stop requested:")
    assert writer_store.events == []
    audit.log("after_stop_timeout")
    assert [event["type"] for event in audit.all_events()] == ["audit_writer_stop", "after_stop_timeout"]
    assert writer_queue.qsize() == 1
    assert audit.writer_status()["dropped_events"] == 0


@pytest.mark.parametrize("replacement_name", ["active.jsonl", "replacement.jsonl"])
def test_start_writer_does_not_overlap_shutdown_pending_writer(
    tmp_path, monkeypatch, replacement_name
):
    audit = AuditLog()
    active_path = tmp_path / "active.jsonl"
    writer_thread, writer_queue, writer_store = _install_writer_state(
        audit, active_path
    )
    audit._writer_stop.set()

    def reject_replacement(_path):
        pytest.fail(
            "replacement store must not be constructed while the prior writer is alive"
        )

    monkeypatch.setattr(audit_module, "FileAuditStore", reject_replacement)

    with pytest.raises(
        TimeoutError, match="Audit writer did not stop within 3 seconds"
    ):
        audit.start_writer(str(tmp_path / replacement_name))

    assert audit._writer_thread is writer_thread
    assert audit._writer_queue is writer_queue
    assert audit._writer_store is writer_store
    assert audit._writer_path == str(active_path)


def test_start_writer_same_path_is_idempotent_only_without_pending_stop(tmp_path):
    audit = AuditLog()
    active_path = tmp_path / "active.jsonl"
    writer_thread, writer_queue, writer_store = _install_writer_state(
        audit, active_path
    )
    audit.dropped = 3
    audit._writer_error_count = 2
    audit._last_writer_error = {
        "error_type": "ExistingError",
        "exception_type": "ExistingError",
        "message": "preserve me",
    }

    assert audit.start_writer(str(active_path)) is True
    assert writer_thread.join_timeouts == []
    assert audit._writer_thread is writer_thread
    assert audit._writer_queue is writer_queue
    assert audit._writer_store is writer_store
    status = audit.writer_status()
    assert status["writer_error_count"] == 2
    assert status["last_writer_error"]["message"] == "preserve me"
    assert status["dropped_events"] == 3


def test_stop_writer_can_reap_after_prior_timeout(tmp_path):
    audit = AuditLog()
    writer_path = tmp_path / "active.jsonl"
    writer_thread, _, writer_store = _install_writer_state(audit, writer_path)

    with pytest.raises(TimeoutError):
        audit.stop_writer()
    # Finish the controllable thread's work before simulating its exit.
    audit._writer_loop()
    writer_thread.alive = False

    audit.stop_writer()

    # The worker appends the stop request once; the reaping stop adds none.
    assert [event["type"] for event in writer_store.events] == ["audit_writer_stop"]
    assert writer_store.events[0]["detail"].startswith("stop requested:")
    assert [event["type"] for event in audit.all_events()] == ["audit_writer_stop"]

    status = audit.writer_status()
    assert audit._writer_thread is None
    assert audit._writer_queue is None
    assert audit._writer_store is None
    assert audit._writer_path is None
    assert status["writer_active"] is False
    assert status["writer_path"] == ""
    assert status["writer_error_count"] == 1
    assert status["last_writer_error"]["error_type"] == "TimeoutError"
