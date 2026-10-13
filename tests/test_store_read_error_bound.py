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
