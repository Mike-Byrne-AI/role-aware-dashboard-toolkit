"""Long logical identifiers must not exceed filesystem component limits."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote

import pytest

from role_aware_dashboard_toolkit import ControlRegistry, create_app
from role_aware_dashboard_toolkit.profile_store import FileProfileStore, InMemoryProfileStore
from role_aware_dashboard_toolkit import store_diagnostics
from role_aware_dashboard_toolkit.store_diagnostics import (
    StorePathSecurityError,
    atomic_write_text_record,
    hashed_store_filename,
    safe_store_filename,
)
from tests.test_store_identifier_contract import COLLECTION_STORES, RECORD_STORES


LONG_IDS = ["x" * 240, "x" * 300, "界" * 240, "é" * 300]
LONG_ID_LABELS = ["ascii240", "ascii300", "cjk240", "accent300"]


def _previous_filename(identifier):
    digest = hashlib.sha1(identifier.encode("utf-8")).hexdigest()[:10]
    return f"{safe_store_filename(identifier)}-{digest}.json"


@pytest.mark.parametrize("identifier", LONG_IDS, ids=LONG_ID_LABELS)
@pytest.mark.parametrize("field,file_class,memory_class", RECORD_STORES)
@pytest.mark.parametrize("file_backed", [False, True])
def test_long_record_ids_roundtrip_without_changing_logical_identity(
    tmp_path, identifier, field, file_class, memory_class, file_backed,
):
    store = file_class(str(tmp_path)) if file_backed else memory_class()
    original = {field: identifier, "version": 1}
    before = deepcopy(original)
    path = store.save(original)
    assert original == before
    assert store.list_ids() == [identifier]
    assert store.load(identifier) == original
    if file_backed:
        assert len(Path(path).name.encode("utf-8")) <= 255
        assert Path(store.resolve_path(identifier)) == Path(path)
    assert store.save({**original, "version": 2}) == path
    assert store.load(identifier)["version"] == 2
    assert store.list_ids() == [identifier]
    if hasattr(store, "delete"):
        assert store.delete(identifier)
        assert store.load(identifier) is None
        assert store.list_ids() == []


@pytest.mark.parametrize("identifier", LONG_IDS, ids=LONG_ID_LABELS)
@pytest.mark.parametrize("field,save_method,list_method,file_class,memory_class", COLLECTION_STORES)
@pytest.mark.parametrize("file_backed", [False, True])
def test_long_collection_ids_update_the_same_record(
    tmp_path, identifier, field, save_method, list_method, file_class, memory_class,
    file_backed,
):
    store = file_class(str(tmp_path)) if file_backed else memory_class()
    save = getattr(store, save_method)
    listing = getattr(store, list_method)
    original = {field: identifier, "run_id": "reference", "version": 1}
    path = save(original)
    assert listing() == [original]
    assert save({**original, "version": 2}) == path
    assert listing() == [{**original, "version": 2}]
    if file_backed:
        assert len(Path(path).name.encode("utf-8")) <= 255
        assert len(list(tmp_path.rglob("*.json"))) == 1


@pytest.mark.parametrize("prefix", ["a" * 300, "界" * 300], ids=["ascii", "cjk"])
def test_identifier_hash_includes_characters_beyond_the_truncated_prefix(tmp_path, prefix):
    store = FileProfileStore(str(tmp_path))
    first, second = prefix + "first", prefix + "second"
    first_path = store.save({"profile_id": first, "value": 1})
    second_path = store.save({"profile_id": second, "value": 2})
    assert first_path != second_path
    assert set(store.list_ids()) == {first, second}
    assert store.load(first)["value"] == 1
    assert store.load(second)["value"] == 2


@pytest.mark.parametrize("identifier", ["short", "my profile", "审查/α", "a" * 239])
def test_fitting_filenames_remain_unchanged(identifier):
    assert f"{hashed_store_filename(identifier)}.json" == _previous_filename(identifier)


def test_atomic_writes_update_a_maximal_existing_filename_without_leftover_temps(tmp_path):
    target = tmp_path / ("x" * 250 + ".json")
    target.write_text("old", encoding="utf-8")
    assert atomic_write_text_record(target, "updated", root_dir=tmp_path) == target
    assert target.read_text(encoding="utf-8") == "updated"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(os.name != "nt", reason="NTFS permits legacy names exceeding 255 UTF-8 bytes")
@pytest.mark.parametrize("field,file_class,memory_class", RECORD_STORES)
def test_existing_long_unicode_record_filename_is_reused_without_migration(
    tmp_path, field, file_class, memory_class,
):
    identifier = "界" * 100
    legacy = tmp_path / _previous_filename(identifier)
    original = {field: identifier, "version": 1}
    legacy.write_text(json.dumps(original), encoding="utf-8")
    store = file_class(str(tmp_path))
    assert store.list_ids() == [identifier]
    assert store.load(identifier) == original
    assert Path(store.resolve_path(identifier)) == legacy
    assert Path(store.save({**original, "version": 2})) == legacy
    assert store.load(identifier)["version"] == 2
    assert list(tmp_path.iterdir()) == [legacy]
    if hasattr(store, "delete"):
        assert store.delete(identifier)
        assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="NTFS permits legacy names exceeding 255 UTF-8 bytes")
@pytest.mark.parametrize("field,save_method,list_method,file_class,memory_class", COLLECTION_STORES)
def test_existing_long_unicode_collection_filename_is_reused_without_duplicates(
    tmp_path, field, save_method, list_method, file_class, memory_class,
):
    identifier = "界" * 100
    store = file_class(str(tmp_path))
    save = getattr(store, save_method)
    short_path = Path(save({field: "short"}))
    short_path.unlink()
    legacy = short_path.parent / _previous_filename(identifier)
    original = {field: identifier, "version": 1}
    legacy.write_text(json.dumps(original), encoding="utf-8")
    assert getattr(store, list_method)() == [original]
    assert Path(save({**original, "version": 2})) == legacy
    assert getattr(store, list_method)() == [{**original, "version": 2}]
    assert list(short_path.parent.iterdir()) == [legacy]


def _create_ambiguous_record_files(directory, field, identifier):
    legacy = directory / _previous_filename(identifier)
    bounded = directory / f"{hashed_store_filename(identifier)}.json"
    assert legacy != bounded
    legacy.write_text(json.dumps({field: identifier, "version": "legacy"}), encoding="utf-8")
    bounded.write_text(json.dumps({field: identifier, "version": "bounded"}), encoding="utf-8")
    return {path: path.read_bytes() for path in (legacy, bounded)}


@pytest.mark.parametrize("field,file_class,memory_class", RECORD_STORES)
def test_ambiguous_record_filenames_fail_closed_and_preserve_both_versions(
    tmp_path, monkeypatch, field, file_class, memory_class,
):
    # A smaller budget exercises the same migration conflict on every filesystem.
    monkeypatch.setattr(store_diagnostics, "_STORE_FILENAME_MAX_BYTES", 64)
    identifier = "x" * 80
    original = _create_ambiguous_record_files(tmp_path, field, identifier)
    store = file_class(str(tmp_path))
    assert store.load(identifier) is None
    assert store.read_errors[-1]["error_type"] == "StorePathSecurityError"
    assert "ambiguous" in store.read_errors[-1]["message"]
    store.clear_read_errors()
    assert store.list_ids() == []
    assert store.read_errors
    assert all(error["error_type"] == "StorePathSecurityError" for error in store.read_errors)
    with pytest.raises(StorePathSecurityError, match="ambiguous"):
        store.resolve_path(identifier)
    with pytest.raises(StorePathSecurityError, match="ambiguous"):
        store.save({field: identifier, "version": "updated"})
    if hasattr(store, "delete"):
        with pytest.raises(StorePathSecurityError, match="ambiguous"):
            store.delete(identifier)
    assert {path: path.read_bytes() for path in tmp_path.iterdir()} == original


@pytest.mark.parametrize("field,save_method,list_method,file_class,memory_class", COLLECTION_STORES)
def test_ambiguous_collection_filenames_fail_closed_and_preserve_both_versions(
    tmp_path, monkeypatch, field, save_method, list_method, file_class, memory_class,
):
    monkeypatch.setattr(store_diagnostics, "_STORE_FILENAME_MAX_BYTES", 64)
    identifier = "x" * 80
    store = file_class(str(tmp_path))
    save = getattr(store, save_method)
    short_path = Path(save({field: "short"}))
    short_path.unlink()
    original = _create_ambiguous_record_files(short_path.parent, field, identifier)
    assert getattr(store, list_method)() == []
    assert store.read_errors
    assert all(error["error_type"] == "StorePathSecurityError" for error in store.read_errors)
    assert all("ambiguous" in error["message"] for error in store.read_errors)
    with pytest.raises(StorePathSecurityError, match="ambiguous"):
        save({field: identifier, "version": "updated"})
    assert {path: path.read_bytes() for path in short_path.parent.iterdir()} == original


@pytest.mark.skipif(os.name != "nt", reason="NTFS permits legacy names exceeding 255 UTF-8 bytes")
def test_legacy_long_unicode_symlink_cannot_redirect_write_or_create_duplicate(tmp_path):
    root = tmp_path / "profiles"
    root.mkdir()
    identifier = "界" * 100
    outside = tmp_path / "outside.json"
    outside.write_text('{"untouched": true}', encoding="utf-8")
    legacy = root / _previous_filename(identifier)
    try:
        legacy.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    store = FileProfileStore(str(root))
    with pytest.raises(StorePathSecurityError):
        store.save({"profile_id": identifier})
    assert outside.read_text(encoding="utf-8") == '{"untouched": true}'
    assert list(root.iterdir()) == [legacy]


@pytest.mark.parametrize("identifier", LONG_IDS, ids=LONG_ID_LABELS)
@pytest.mark.parametrize("file_backed", [False, True])
def test_api_long_profile_ids_support_complete_lifecycle(tmp_path, monkeypatch, identifier, file_backed):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-review-key")
    store = FileProfileStore(str(tmp_path)) if file_backed else InMemoryProfileStore()
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=1)
    client = TestClient(create_app(registry, profile_store=store, api_role="Admin"))
    headers = {"X-API-Key": "synthetic-review-key"}
    url = "/profiles/" + quote(identifier, safe="")
    for _ in range(2):
        saved = client.post("/profiles", json={"profile_id": identifier}, headers=headers)
        assert saved.status_code == 200
        assert saved.json()["profile_id"] == identifier
    assert client.get("/profiles", headers=headers).json() == [identifier]
    assert client.get(url, headers=headers).status_code == 200
    assert client.post(url + "/activate", headers=headers).status_code == 200
    assert client.delete(url, headers=headers).status_code == 200
    assert client.get("/profiles", headers=headers).json() == []
