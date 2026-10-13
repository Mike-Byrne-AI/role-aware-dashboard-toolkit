import errno
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
import role_aware_dashboard_toolkit.case_store as case_store
import role_aware_dashboard_toolkit.caseboard as caseboard
import role_aware_dashboard_toolkit.operator_memory as operator_memory
import role_aware_dashboard_toolkit.store_diagnostics as store_diagnostics
from role_aware_dashboard_toolkit.caseboard import add_case_notes, close_case, link_case_records, reopen_case, summarize_caseboard
from role_aware_dashboard_toolkit.validators import validate_case_record



def test_case_record_validate_compare_and_summary():
    incident_a = operator_memory.build_incident_record("run_a", "Latency spike", incident_id="incident_a")
    incident_b = operator_memory.build_incident_record("run_b", "Latency spike again", incident_id="incident_b")
    narrative_a = operator_memory.build_narrative_handoff_packet({"run_id": "run_a", "last_checkpoint_id": "cp_a"}, narrative_id="narr_a", handoff_to="night")
    case_left = caseboard.build_case_from_records(
        "Latency investigation",
        incidents=[incident_a],
        narratives=[narrative_a],
        actor="mike",
        role="Operator",
        priority="high",
    )
    case_left = link_case_records(case_left, run_ids=["run_a", "run_b"], incident_ids=[incident_b["incident_id"]], actor="mike", role="Operator")
    case_left = add_case_notes(case_left, ["Repeated under elevated temperature."], actor="mike", role="Operator")
    case_right = caseboard.build_case_record("Different case", linked_run_ids=["run_c"], linked_incident_ids=["incident_c"])

    assert validate_case_record(case_left)["ok"] is True
    assert caseboard.case_summary(case_left)["incident_count"] == 2
    comparison = caseboard.compare_cases(case_left, case_right)
    assert "run_b" in comparison["runs_only_in_left"]
    summary = summarize_caseboard([case_left, case_right])
    assert summary["case_count"] == 2
    assert summary["priority_counts"]["high"] >= 1



def test_case_record_preserves_case_distinct_link_ids():
    case_record = caseboard.build_case_record(
        "Case-sensitive links",
        linked_run_ids=["Run_A", "run_a", "Run_A"],
        tags=["Tag", "tag", "Tag"],
    )

    assert case_record["linked_run_ids"] == ["Run_A", "run_a"]
    assert case_record["tags"] == ["Tag", "tag"]


def test_inmemory_case_store_filters_and_reopen_close():
    store = case_store.InMemoryCaseStore()
    case_record = caseboard.build_case_record(
        "Cross-run issue",
        linked_run_ids=["run_a"],
        linked_incident_ids=["incident_a"],
    )
    store.save(case_record)
    assert store.list_by_run("run_a")[0]["case_id"] == case_record["case_id"]
    assert store.list_by_incident("incident_a")[0]["case_id"] == case_record["case_id"]

    reopened = reopen_case(close_case(case_record, actor="ops"), actor="ops")
    assert reopened["state"] == "investigating"
    assert any(item["event_type"] == "closed" for item in reopened["history"])
    assert any(item["event_type"] == "reopened" for item in reopened["history"])


def test_case_store_list_ids_follows_case_sort_order():
    store = case_store.InMemoryCaseStore()
    store.save({"case_id": "z_case", "created_at": "2026-01-01T00:00:00+00:00"})
    store.save({"case_id": "a_case", "created_at": "2026-01-02T00:00:00+00:00"})

    ordered_case_ids = [item["case_id"] for item in store.list_cases()]
    assert ordered_case_ids == ["z_case", "a_case"]
    assert store.list_ids() == ordered_case_ids


def test_file_case_store_direct_load_records_corrupt_json_read_errors(tmp_path):
    store = case_store.FileCaseStore(str(tmp_path / "caseboard"))
    path = store.save(caseboard.build_case_record("Broken", case_id="broken"))
    Path(path).write_text("{not json", encoding="utf-8")

    assert store.load("broken") is None
    assert store.read_errors
    assert store.read_errors[0]["path"].endswith(Path(path).name)
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"


@pytest.mark.parametrize(
    "unsafe_number",
    ["NaN", "Infinity", "-Infinity", "1e9999", "-1e9999"],
)
def test_file_case_store_records_non_finite_json_read_errors(
    tmp_path,
    unsafe_number,
):
    store = case_store.FileCaseStore(str(tmp_path / "caseboard"))
    path = Path(store.save({"case_id": "unsafe-number", "score": 1.0}))
    path.write_text(
        f'{{"case_id": "unsafe-number", "score": {unsafe_number}}}',
        encoding="utf-8",
    )

    assert store.load("unsafe-number") is None
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "ValueError"
    assert "finite" in store.read_errors[0]["message"]


def test_file_case_store_rejects_non_finite_write_before_replacing_good_record(
    tmp_path,
):
    store = case_store.FileCaseStore(str(tmp_path / "caseboard"))
    path = Path(store.save({"case_id": "stable", "score": 1.0}))
    original_bytes = path.read_bytes()

    with pytest.raises(ValueError, match="Out of range float values"):
        store.save({"case_id": "stable", "score": {"nested": float("nan")}})

    assert path.read_bytes() == original_bytes
    assert store.load("stable") == {"case_id": "stable", "score": 1.0}


def test_inmemory_case_store_rejects_non_finite_write_without_mutating_record():
    store = case_store.InMemoryCaseStore()
    store.save({"case_id": "stable", "score": 1.0})

    with pytest.raises(ValueError, match="Out of range float values"):
        store.save({"case_id": "stable", "score": float("inf")})

    assert store.load("stable") == {"case_id": "stable", "score": 1.0}


def test_file_case_store_exact_load_stops_after_authoritative_probe_error(
    tmp_path,
    monkeypatch,
):
    store_dir = tmp_path / "caseboard"
    store_dir.mkdir()
    legacy_path = store_dir / "blocked.json"
    legacy_path.write_text(
        json.dumps({"case_id": "blocked", "title": "stale legacy record"}),
        encoding="utf-8",
    )
    store = case_store.FileCaseStore(str(store_dir))
    hashed_path = Path(store._path_for_write("blocked"))
    original_stat = Path.stat

    def denied_stat(path, *args, **kwargs):
        if path == hashed_path:
            raise PermissionError(
                13,
                r"denied via \\private-server\secret share\record.json",
                str(hashed_path),
            )
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", denied_stat)

    assert store.load("blocked") is None
    assert len(store.read_errors) == 1
    error = store.read_errors[0]
    assert error["error_type"] == "PermissionError"
    assert error["exception_type"] == "PermissionError"
    assert error["path"].endswith(hashed_path.name)
    assert str(tmp_path) not in "\n".join(error.values())
    assert "private-server" not in error["message"]


def test_file_case_store_exact_load_surfaces_broken_symlink_probe(tmp_path, monkeypatch):
    store_dir = tmp_path / "caseboard"
    store_dir.mkdir()
    store = case_store.FileCaseStore(str(store_dir))
    hashed_path = Path(store._path_for_write("broken-link"))
    hashed_path.write_text("{}", encoding="utf-8")
    original_stat = Path.stat
    original_is_symlink = Path.is_symlink
    original_is_file = Path.is_file

    def simulated_stat(path, *args, **kwargs):
        if path == hashed_path:
            return SimpleNamespace(st_mode=stat.S_IFLNK)
        return original_stat(path, *args, **kwargs)

    def simulated_is_symlink(path):
        if path == hashed_path:
            return True
        return original_is_symlink(path)

    def simulated_is_file(path, *args, **kwargs):
        if path == hashed_path:
            return False
        return original_is_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", simulated_stat)
    monkeypatch.setattr(Path, "is_symlink", simulated_is_symlink)
    # Mock the public query as well: Python 3.14 no longer implements
    # is_file() through Path.stat(), and a broken link is never a file.
    monkeypatch.setattr(Path, "is_file", simulated_is_file)

    assert store.resolve_path("broken-link") is None
    assert store.read_errors == []
    legacy_path = store_dir / "broken-link.json"
    legacy_path.write_text(
        json.dumps({"case_id": "broken-link", "title": "legacy"}),
        encoding="utf-8",
    )
    assert store.resolve_path("broken-link") is None
    assert store.read_errors == []
    assert store.load("broken-link") is None
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"


def test_file_case_store_exact_load_rejects_hard_link_without_unhashed_fallback(
    tmp_path,
    monkeypatch,
):
    store_dir = tmp_path / "caseboard"
    store_dir.mkdir()
    store = case_store.FileCaseStore(str(store_dir))
    hashed_path = Path(store._path_for_write("linked"))
    outside = tmp_path / "outside.json"
    outside_payload = '{"case_id": "linked", "title": "outside-secret"}'
    outside.write_text(outside_payload, encoding="utf-8")
    try:
        os.link(outside, hashed_path)
    except (OSError, NotImplementedError):
        pytest.skip("hard-link creation is not available in this environment")
    legacy_path = store_dir / "linked.json"
    legacy_path.write_text(
        json.dumps({"case_id": "linked", "title": "stale legacy"}),
        encoding="utf-8",
    )
    original_open = store_diagnostics.os.open

    def guarded_open(path_to_open, flags):
        if Path(path_to_open) == hashed_path:
            raise AssertionError("multi-link store records must not be opened")
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", guarded_open)

    assert store.load("linked") is None
    assert len(store.read_errors) == 1
    error = store.read_errors[0]
    assert error["error_type"] == "StorePathSecurityError"
    assert error["path"].endswith(hashed_path.name)
    assert "outside-secret" not in "\n".join(error.values())
    assert str(outside) not in "\n".join(error.values())
    assert outside.read_text(encoding="utf-8") == outside_payload


def test_shared_text_reader_preserves_text_and_empty_file(tmp_path):
    path = tmp_path / "record.txt"
    errors = []
    rendered = "plain UTF-8 text \u2603"
    path.write_text(rendered, encoding="utf-8")

    assert (
        store_diagnostics.read_text_record(path, errors, root_dir=tmp_path) == rendered
    )
    path.write_text("", encoding="utf-8")
    assert store_diagnostics.read_text_record(path, errors, root_dir=tmp_path) == ""
    assert errors == []


def test_shared_json_reader_treats_read_disappearance_as_missing(tmp_path, monkeypatch):
    path = tmp_path / "record.json"
    path.write_text('{"case_id": "transient"}', encoding="utf-8")
    errors = []
    original_open = store_diagnostics.os.open

    def disappearing_open(path_to_open, flags):
        if Path(path_to_open) == path:
            path.unlink()
            raise FileNotFoundError(str(path))
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", disappearing_open)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert errors == []


def test_shared_json_reader_records_invalid_path_probe(tmp_path):
    errors = []

    assert (
        store_diagnostics.read_json_record(Path(chr(0)), errors, root_dir=tmp_path)
        is None
    )
    assert len(errors) == 1
    assert errors[0]["error_type"] == "ValueError"
    assert all(chr(0) not in value for value in errors[0].values())


def test_shared_json_reader_does_not_open_non_regular_files(tmp_path, monkeypatch):
    path = tmp_path / "pipe.json"
    errors = []
    original_stat = Path.stat
    original_open = store_diagnostics.os.open

    def simulated_stat(path_to_probe, *args, **kwargs):
        if path_to_probe == path:
            return SimpleNamespace(st_mode=stat.S_IFIFO)
        return original_stat(path_to_probe, *args, **kwargs)

    def guarded_open(path_to_open, flags):
        if Path(path_to_open) == path:
            raise AssertionError("non-regular store records must not be opened")
        return original_open(path_to_open, flags)

    monkeypatch.setattr(Path, "stat", simulated_stat)
    monkeypatch.setattr(store_diagnostics.os, "open", guarded_open)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "StorePathSecurityError"


def test_shared_json_reader_rejects_opened_file_substitution(tmp_path, monkeypatch):
    store_dir = tmp_path / "store"
    store_dir.mkdir()
    path = store_dir / "record.json"
    path.write_text('{"case_id": "inside"}', encoding="utf-8")
    replacement = tmp_path / "replacement.json"
    replacement.write_text('{"case_id": "outside-secret"}', encoding="utf-8")
    errors = []
    opened_fds = []
    captured_flags = []
    original_open = store_diagnostics.os.open
    original_fstat = store_diagnostics.os.fstat
    original_read = store_diagnostics.os.read

    def substituted_open(path_to_open, flags):
        if Path(path_to_open) == path:
            fd = original_open(replacement, flags)
            opened_fds.append(fd)
            captured_flags.append(flags)
            return fd
        return original_open(path_to_open, flags)

    def guarded_read(fd, size):
        if fd in opened_fds:
            raise AssertionError("replacement payload must not be read")
        return original_read(fd, size)

    monkeypatch.setattr(store_diagnostics.os, "open", substituted_open)
    monkeypatch.setattr(store_diagnostics.os, "read", guarded_read)

    assert store_diagnostics.read_json_record(path, errors, root_dir=store_dir) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "StorePathSecurityError"
    assert "outside-secret" not in "\n".join(errors[0].values())
    assert str(replacement) not in "\n".join(errors[0].values())

    assert len(captured_flags) == 1
    for flag_name in (
        "O_BINARY",
        "O_CLOEXEC",
        "O_NOINHERIT",
        "O_NOCTTY",
        "O_NOFOLLOW",
        "O_NONBLOCK",
    ):
        flag = getattr(store_diagnostics.os, flag_name, 0)
        if flag:
            assert captured_flags[0] & flag == flag
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_shared_json_reader_rejects_hard_link_added_during_open(
    tmp_path,
    monkeypatch,
):
    path = tmp_path / "record.json"
    path.write_text('{"case_id": "inside"}', encoding="utf-8")
    capability_probe = tmp_path / "hard-link-probe.json"
    try:
        os.link(path, capability_probe)
    except (OSError, NotImplementedError):
        pytest.skip("hard-link creation is not available in this environment")
    capability_probe.unlink()
    outside_alias = tmp_path / "outside-alias.json"
    outside_payload = '{"case_id": "outside-secret"}'
    errors = []
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_read = store_diagnostics.os.read
    original_fstat = store_diagnostics.os.fstat

    def raced_open(path_to_open, flags):
        if Path(path_to_open) == path:
            os.link(path, outside_alias)
            outside_alias.write_text(outside_payload, encoding="utf-8")
            fd = original_open(path_to_open, flags)
            opened_fds.append(fd)
            return fd
        return original_open(path_to_open, flags)

    def guarded_read(fd, size):
        if fd in opened_fds:
            raise AssertionError("multi-link store records must not be read")
        return original_read(fd, size)

    monkeypatch.setattr(store_diagnostics.os, "open", raced_open)
    monkeypatch.setattr(store_diagnostics.os, "read", guarded_read)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "StorePathSecurityError"
    assert "outside-secret" not in "\n".join(errors[0].values())
    assert str(outside_alias) not in "\n".join(errors[0].values())
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


@pytest.mark.parametrize(
    ("opened_mode", "opened_inode", "opened_link_count"),
    [
        (stat.S_IFIFO, 1, 1),
        (stat.S_IFREG, 0, 1),
        (stat.S_IFREG, 1, 0),
        (stat.S_IFREG, 1, 2),
        (stat.S_IFREG, 1, True),
    ],
)
def test_shared_json_reader_rejects_unsafe_opened_identity(
    tmp_path,
    monkeypatch,
    opened_mode,
    opened_inode,
    opened_link_count,
):
    path = tmp_path / "record.json"
    path.write_text('{"case_id": "inside"}', encoding="utf-8")
    errors = []
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_fstat = store_diagnostics.os.fstat
    original_read = store_diagnostics.os.read

    def tracked_open(path_to_open, flags):
        fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def simulated_fstat(fd):
        if fd in opened_fds:
            return SimpleNamespace(
                st_mode=opened_mode,
                st_ino=opened_inode,
                st_dev=1,
                st_nlink=opened_link_count,
            )
        return original_fstat(fd)

    def guarded_read(fd, size):
        if fd in opened_fds:
            raise AssertionError("unsafe opened objects must not be read")
        return original_read(fd, size)

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "fstat", simulated_fstat)
    monkeypatch.setattr(store_diagnostics.os, "read", guarded_read)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "StorePathSecurityError"
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_shared_json_reader_closes_descriptor_after_read_error(tmp_path, monkeypatch):
    path = tmp_path / "record.json"
    path.write_text('{"case_id": "inside"}', encoding="utf-8")
    errors = []
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_fstat = store_diagnostics.os.fstat
    original_read = store_diagnostics.os.read

    def tracked_open(path_to_open, flags):
        fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def failing_read(fd, size):
        if fd in opened_fds:
            raise PermissionError(
                13,
                r"denied via \\private-server\secret share\record.json",
                str(path),
            )
        return original_read(fd, size)

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "read", failing_read)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "PermissionError"
    assert "private-server" not in errors[0]["message"]
    assert str(tmp_path) not in "\n".join(errors[0].values())
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_shared_json_reader_preserves_primary_error_after_close_failure(
    tmp_path,
    monkeypatch,
    caplog,
):
    path = tmp_path / "record.json"
    path.write_text('{"case_id": "inside"}', encoding="utf-8")
    errors = []
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_read = store_diagnostics.os.read
    original_close = store_diagnostics.os.close
    original_fstat = store_diagnostics.os.fstat

    def tracked_open(path_to_open, flags):
        fd = original_open(path_to_open, flags)
        if Path(path_to_open) == path:
            opened_fds.append(fd)
        return fd

    def failing_read(fd, size):
        if fd in opened_fds:
            raise PermissionError(13, "record read failed")
        return original_read(fd, size)

    def failing_close(fd):
        original_close(fd)
        if fd in opened_fds:
            raise PermissionError(13, "descriptor close failed")

    monkeypatch.setattr(store_diagnostics.os, "open", tracked_open)
    monkeypatch.setattr(store_diagnostics.os, "read", failing_read)
    monkeypatch.setattr(store_diagnostics.os, "close", failing_close)

    with caplog.at_level("WARNING", logger="role_aware_dashboard_toolkit.store_diagnostics"):
        assert (
            store_diagnostics.read_json_record(path, errors, root_dir=tmp_path)
            is None
        )

    assert len(errors) == 1
    assert errors[0]["error_type"] == "PermissionError"
    assert "record read failed" in errors[0]["message"]
    assert any(
        "descriptor cleanup failed after PermissionError: PermissionError"
        in record.getMessage()
        for record in caplog.records
    )
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_shared_json_reader_surfaces_descriptor_close_error(tmp_path, monkeypatch):
    path = tmp_path / "record.json"
    path.write_text('{"case_id": "inside"}', encoding="utf-8")
    errors = []
    opened_fds = []
    original_open = store_diagnostics.os.open
    original_close = store_diagnostics.os.close
    original_fstat = store_diagnostics.os.fstat

    def tracked_open(path_to_open, flags):
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

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "PermissionError"
    for fd in opened_fds:
        with pytest.raises(OSError):
            original_fstat(fd)


def test_shared_json_reader_classifies_open_substitution_failures(tmp_path, monkeypatch):
    path = tmp_path / "record.json"
    path.write_text('{"case_id": "inside"}', encoding="utf-8")
    errors = []
    original_open = store_diagnostics.os.open
    original_stat = Path.stat

    def looping_open(path_to_open, flags):
        if Path(path_to_open) == path:
            raise OSError(errno.ELOOP, "too many symbolic links", str(path))
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", looping_open)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "StorePathSecurityError"

    errors.clear()
    classification_started = False

    def disappearing_open(path_to_open, flags):
        nonlocal classification_started
        if Path(path_to_open) == path:
            classification_started = True
            raise FileNotFoundError(str(path))
        return original_open(path_to_open, flags)

    monkeypatch.setattr(store_diagnostics.os, "open", disappearing_open)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert len(errors) == 1
    assert errors[0]["error_type"] == "StorePathSecurityError"
    errors.clear()
    classification_started = False

    def failing_classification_stat(path_to_check, *args, **kwargs):
        if path_to_check == path and classification_started:
            raise PermissionError(
                13,
                r"denied via \\private-server\secret share\record.json",
                str(path),
            )
        return original_stat(path_to_check, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", failing_classification_stat)

    assert store_diagnostics.read_json_record(path, errors, root_dir=tmp_path) is None
    assert classification_started is True
    assert len(errors) == 1
    assert errors[0]["error_type"] == "PermissionError"
    assert "private-server" not in errors[0]["message"]
    assert str(tmp_path) not in "\n".join(errors[0].values())


def test_file_case_store_records_directory_enumeration_errors(tmp_path, monkeypatch):
    missing_store = case_store.FileCaseStore(str(tmp_path / "missing"))
    assert missing_store.list_cases() == []
    assert missing_store.read_errors == []

    file_root = tmp_path / "not-a-directory"
    file_root.write_text("not a store", encoding="utf-8")
    file_store = case_store.FileCaseStore(str(file_root))
    assert file_store.list_cases() == []
    assert len(file_store.read_errors) == 1
    assert file_store.read_errors[0]["error_type"] == "NotADirectoryError"

    invalid_store = case_store.FileCaseStore(chr(0))
    assert invalid_store.list_cases() == []
    assert invalid_store.read_errors == [
        {
            "path": "<invalid-store-path>",
            "error_type": "ValueError",
            "exception_type": "ValueError",
            "message": "ValueError: JSON store directory enumeration failed",
        }
    ]

    store_dir = tmp_path / "caseboard"
    store = case_store.FileCaseStore(str(store_dir))
    store.save(caseboard.build_case_record("Visible", case_id="visible"))
    original_scandir = store_diagnostics.os.scandir

    def denied_scandir(path):
        if Path(path) == store_dir:
            raise PermissionError(
                13,
                r"denied via \\private-server\secret share\record.json",
                str(store_dir),
            )
        return original_scandir(path)

    with monkeypatch.context() as scoped:
        scoped.setattr(store_diagnostics.os, "scandir", denied_scandir)
        assert store.list_cases() == []

    assert store.read_errors == [
        {
            "path": "caseboard",
            "error_type": "PermissionError",
            "exception_type": "PermissionError",
            "message": "PermissionError: JSON store directory enumeration failed (errno 13)",
        }
    ]
    assert str(store_dir) not in store.read_errors[0]["message"]
    assert "private-server" not in store.read_errors[0]["message"]


def test_file_case_store_records_symlink_loop_enumeration_error(tmp_path):
    loop_store = tmp_path / "loop-store"
    try:
        loop_store.symlink_to(loop_store, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is not available in this environment")

    store = case_store.FileCaseStore(str(loop_store))
    assert store.list_cases() == []
    assert len(store.read_errors) == 1

    error = store.read_errors[0]
    assert error["path"] == "loop-store"
    assert error["error_type"] == error["exception_type"]
    assert error["message"].startswith(
        f'{error["error_type"]}: JSON store directory enumeration failed'
    )
    assert str(tmp_path) not in "\n".join(error.values())


def test_file_case_store_uses_hashed_writes_and_ignores_unhashed_lookup(tmp_path):
    store_dir = tmp_path / "caseboard"
    store = case_store.FileCaseStore(str(store_dir))
    left_id = "case/a"
    right_id = "case:a"

    left_path = Path(store.save({"case_id": left_id, "title": "left"}))
    right_path = Path(store.save({"case_id": right_id, "title": "right"}))

    assert left_path != right_path
    assert left_path.name.startswith("casea-")
    assert right_path.name.startswith("casea-")
    assert store.load(left_id)["title"] == "left"
    assert store.load(right_id)["title"] == "right"

    legacy_id = "legacy/case"
    legacy_path = store_dir / "legacycase.json"
    legacy_path.write_text(json.dumps({"case_id": legacy_id, "title": "legacy"}), encoding="utf-8")
    assert store.load(legacy_id) is None


def test_validate_case_record_catches_bad_priority():
    case_record = caseboard.build_case_record("Bad priority")
    case_record["priority"] = "urgent"
    result = validate_case_record(case_record)
    assert result["ok"] is False
    assert any("Invalid case priority" in error for error in result["errors"])


def test_caseboard_docs_preserve_review_artifact_boundary():
    docs = (Path(__file__).resolve().parents[1] / "docs" / "caseboard.md").read_text(encoding="utf-8")
    assert "Caseboard records are review artifacts, not execution triggers." in docs
    assert "always an explicit operator action" in docs

