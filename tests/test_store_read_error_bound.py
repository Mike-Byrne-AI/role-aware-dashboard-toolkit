"""Read diagnostics stay bounded while new errors remain detectable."""
from __future__ import annotations

from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import DashboardConfig
from role_aware_dashboard_toolkit.profile_store import FileProfileStore
from role_aware_dashboard_toolkit.security import get_role, make_security_context
from role_aware_dashboard_toolkit import sidebar


def _store_with_corrupt_profile(root: Path) -> FileProfileStore:
    store = FileProfileStore(str(root))
    store.save({"profile_id": "prod", "values": {"limit": 42}})
    path = Path(store.resolve_path("prod"))
    path.write_text("{oops", encoding="utf-8")
    return FileProfileStore(str(root))


def test_read_errors_are_bounded_and_counted(tmp_path):
    store = _store_with_corrupt_profile(tmp_path)
    for _ in range(1000):
        store.list_ids()
    assert len(store.read_errors) <= 200
    assert store.read_error_count == 1000
    from role_aware_dashboard_toolkit.store_diagnostics import store_read_error_total

    assert store_read_error_total(store) == 1000
    # The newest errors are the ones kept.
    assert store.read_errors[-1]["error_type"] == "JSONDecodeError"


def test_clear_read_errors_keeps_the_running_total(tmp_path):
    store = _store_with_corrupt_profile(tmp_path)
    store.list_ids()
    store.clear_read_errors()
    assert store.read_errors == []
    assert store.read_error_count == 1


def test_total_falls_back_to_length_for_custom_stores():
    from role_aware_dashboard_toolkit.store_diagnostics import store_read_error_total

    class CustomStore:
        read_errors = [{"error_type": "X"}, {"error_type": "Y"}]

    assert store_read_error_total(CustomStore()) == 2
    assert store_read_error_total(object()) == 0


def test_full_window_still_refuses_to_overwrite_an_unreadable_profile(tmp_path):
    store = _store_with_corrupt_profile(tmp_path)
    for _ in range(500):  # fill the retained window
        store.list_ids()
    config = DashboardConfig(auth_mode="demo", profile_dir=str(tmp_path), profile_store=store)
    ctx = make_security_context("Admin", dict(get_role("Admin").perms))
    with pytest.raises(sidebar._ProfileStorageFailure):
        sidebar._read_profile_save_target(config, ctx, store, "prod", known_profiles=[])


# Every caller that detects "this read failed" compares a before/after count.
# Once the retained window is full, len(read_errors) stops growing, so each
# caller must compare store_read_error_total instead.


def _run_store_with_full_window(root: Path):
    from role_aware_dashboard_toolkit.run_store import FileRunStore
    from role_aware_dashboard_toolkit.runs import build_run

    store = FileRunStore(str(root))
    run = build_run({"limit": 1}, actor="test")
    store.save(run)
    run_id = run["run_id"]
    Path(store.resolve_path(run_id)).write_text("{oops", encoding="utf-8")
    store = FileRunStore(str(root))
    for _ in range(300):  # fill the retained window
        store.list_ids()
    assert len(store.read_errors) == 200
    return store, run_id


def test_full_window_run_read_is_still_reported_as_failed(tmp_path):
    from role_aware_dashboard_toolkit.runbook_panels import _read_run_store

    store, run_id = _run_store_with_full_window(tmp_path)
    assert _read_run_store(store, store.load, run_id, validate_run=True) == (None, True)
    assert _read_run_store(store, store.list_ids) == ([], True)


def test_full_window_evidence_read_is_failed_not_missing(tmp_path):
    from role_aware_dashboard_toolkit._evidence_reads import read_evidence

    store, run_id = _run_store_with_full_window(tmp_path)
    result = read_evidence(store, "load", run_id, record_type="run", single=True)
    assert result.status == "failed"


def test_full_window_api_listing_counts_each_unreadable_profile(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from role_aware_dashboard_toolkit import ControlRegistry
    from role_aware_dashboard_toolkit.api import create_app
    from role_aware_dashboard_toolkit.profiles import save_profile

    key = "synthetic-read-error-window-key"
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", key)
    registry = ControlRegistry()
    registry.register("Limit", kind="number", key="limit", default=5, min_value=0, max_value=100, step=1)
    store = FileProfileStore(str(tmp_path))
    for name in ("one", "two", "three", "kept"):
        save_profile(name, registry, {"limit": 1}, store=store)
    for name in ("one", "two", "three"):
        Path(store.resolve_path(name)).write_text("{oops", encoding="utf-8")
    store = FileProfileStore(str(tmp_path))
    for _ in range(100):  # 300 errors: the window is full before the request
        store.list_ids()
    assert len(store.read_errors) == 200
    with TestClient(create_app(registry, api_role="Admin", profile_store=store)) as client:
        listing = client.get("/profiles", headers={"X-API-Key": key})
    assert listing.status_code == 200
    assert listing.json() == ["kept"]
    assert listing.headers["X-Unreadable-Records"] == "3"


def test_full_window_api_read_save_and_activate_report_the_unreadable_profile(tmp_path, monkeypatch):
    # Read and activation answer 500 and save answers 409, not 404 and an
    # overwrite, even when the window was already full before the request.
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from role_aware_dashboard_toolkit import AuditLog, ControlRegistry
    from role_aware_dashboard_toolkit.api import create_app
    from role_aware_dashboard_toolkit.profiles import save_profile

    key = "synthetic-read-error-window-key"
    headers = {"X-API-Key": key}
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", key)
    registry = ControlRegistry()
    registry.register("Limit", kind="number", key="limit", default=5, min_value=0, max_value=100, step=1)
    store = FileProfileStore(str(tmp_path))
    save_profile("prod", registry, {"limit": 42}, store=store)
    path = Path(store.resolve_path("prod"))
    path.write_text("{oops", encoding="utf-8")
    store = FileProfileStore(str(tmp_path))
    for _ in range(300):  # the window is full before any request
        store.list_ids()
    assert len(store.read_errors) == 200
    audit = AuditLog()
    with TestClient(create_app(registry, audit=audit, api_role="Admin", profile_store=store)) as client:
        read = client.get("/profiles/prod", headers=headers)
        save = client.post("/profiles", headers=headers, json={"profile_id": "prod"})
        activate = client.post("/profiles/prod/activate", headers=headers)
        missing = client.get("/profiles/absent", headers=headers)
        limit = client.get("/controls/limit", headers=headers).json()["value"]

    assert (read.status_code, save.status_code, activate.status_code) == (500, 409, 500)
    assert missing.status_code == 404
    assert path.read_text(encoding="utf-8") == "{oops"
    assert limit == 5
    assert audit.all_events() == []


def test_copies_keep_the_total_and_every_way_of_adding_counts():
    import copy
    import pickle

    from role_aware_dashboard_toolkit.store_diagnostics import _ReadErrorLog

    log = _ReadErrorLog()
    for number in range(250):
        log.append({"error_type": "X", "n": number})
    assert (log.total, len(log)) == (250, 200)

    # deepcopy rebuilt the deque by appending its items onto the copied total.
    for clone in (copy.copy(log), copy.deepcopy(log), pickle.loads(pickle.dumps(log))):
        assert type(clone) is _ReadErrorLog
        assert (clone.total, clone.maxlen, list(clone)) == (250, 200, list(log))

    log += [{"error_type": "Y"}, {"error_type": "Z"}]  # deque's += skipped append
    log.extend([{"error_type": "W"}])
    log.appendleft({"error_type": "V"})
    log.extendleft([{"error_type": "U"}])
    assert log.total == 255
    assert len(log) == 200
