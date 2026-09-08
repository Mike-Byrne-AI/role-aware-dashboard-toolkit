from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import ControlRegistry, FileProfileStore, InMemoryProfileStore, build_profile, load_profile, save_profile, list_profiles, delete_profile
from role_aware_dashboard_toolkit.store_diagnostics import StorePathSecurityError, build_read_error as build_store_read_error


def test_inmemory_profile_store_round_trip():
    reg = ControlRegistry()
    reg.register("Temperature", kind="slider", key="temperature", default=0.7)
    store = InMemoryProfileStore()
    session = {"temperature": 1.2}
    save_profile("prod", reg, session, store=store, role="Admin", app_name="Test")
    loaded = store.load("prod")
    assert loaded is not None
    assert loaded["profile_id"] == "prod"
    assert loaded["schema_version"] >= 3
    assert loaded["app_name"] == "Test"


def test_build_profile_includes_contract_fields():
    reg = ControlRegistry()
    reg.register("Enabled", kind="toggle", key="enabled", default=False)
    profile = build_profile("baseline", reg, {"enabled": True}, source="api", session_id="abc")
    assert profile["source"] == "api"
    assert profile["session_id"] == "abc"
    assert "schema_version" in profile


def test_load_profile_from_inmemory_store_restores_values():
    reg = ControlRegistry()
    reg.register("Count", kind="number", key="count", default=1, min_value=0, max_value=10, step=1)
    store = InMemoryProfileStore()
    save_profile("ops", reg, {"count": 5}, store=store)
    session = {}
    loaded = load_profile("ops", reg, session, store=store)
    assert loaded is not None
    assert session["count"] == 5


def test_profile_store_helpers_prefer_explicit_store():
    reg = ControlRegistry()
    reg.register("Mode", kind="select", key="mode", options=["fast", "safe"], default="safe")
    store = InMemoryProfileStore()
    session = {"mode": "fast"}

    save_profile("store-backed", reg, session, profile_dir="unused_profiles", store=store)

    assert list_profiles("unused_profiles", store=store) == ["store-backed"]
    assert load_profile("store-backed", reg, {}, profile_dir="unused_profiles", store=store) is not None
    assert delete_profile("store-backed", profile_dir="unused_profiles", store=store) is True


def test_file_profile_store_records_corrupt_json_read_errors(tmp_path):
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    (profile_dir / "broken.json").write_text("[not an object]", encoding="utf-8")
    store = FileProfileStore(str(profile_dir))

    assert store.list_ids() == []
    assert store.read_errors
    assert store.read_errors[0]["path"].endswith("broken.json")
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"
    assert store.read_errors[0]["exception_type"] == "JSONDecodeError"


def test_file_profile_store_direct_load_records_corrupt_json_read_errors(tmp_path):
    profile_dir = tmp_path / "profiles"
    store = FileProfileStore(str(profile_dir))
    path = store.save({"profile_id": "broken", "values": {}})
    Path(path).write_text("{not json", encoding="utf-8")

    assert store.load("broken") is None
    assert store.read_errors
    assert store.read_errors[0]["path"].endswith(Path(path).name)
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"
    assert store.read_errors[0]["exception_type"] == "JSONDecodeError"


def test_file_profile_store_preserves_special_id_with_safe_filename_path(tmp_path):
    profile_dir = tmp_path / "profiles"
    store = FileProfileStore(str(profile_dir))
    profile_id = "prod/api v1"
    store.save({"profile_id": profile_id, "values": {"mode": "safe"}})

    loaded = store.load(profile_id)
    assert loaded is not None
    assert loaded["profile_id"] == profile_id
    assert store.list_ids() == [profile_id]


def test_store_read_error_redacts_embedded_local_paths(tmp_path):
    path = (tmp_path / "profiles" / "broken.json").resolve()
    windows_path = r"C:\Users\dev\secret.json"
    error = build_store_read_error(path, OSError(f"cannot open {path} or {windows_path}"), root_dir=path.parent)

    assert error["path"] == "broken.json"
    assert "<redacted-local-path>" in error["message"]
    assert str(path) not in error["message"]
    assert windows_path not in error["message"]


def test_file_profile_store_rejects_symlink_escape_records(tmp_path):
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"profile_id": "escape"}', encoding="utf-8")
    link = profile_dir / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    store = FileProfileStore(str(profile_dir))
    assert store.list_ids() == []
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"
    assert store.read_errors[0]["exception_type"] == "StorePathSecurityError"
    assert "symlinked store record" in store.read_errors[0]["message"]


def test_file_profile_store_save_rejects_symlink_target(tmp_path):
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    store = FileProfileStore(str(profile_dir))

    profile_id = "escape"
    target_path = Path(store._path_for_write(profile_id))
    outside = tmp_path / "outside_profile.json"
    outside.write_text('{"profile_id":"outside"}', encoding="utf-8")
    try:
        target_path.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    with pytest.raises(StorePathSecurityError):
        store.save({"profile_id": profile_id, "values": {"mode": "safe"}})
