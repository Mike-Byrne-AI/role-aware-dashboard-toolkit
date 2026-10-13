"""An unreadable stored profile is reported as unreadable, never as missing."""
from __future__ import annotations

from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.profile_store import FileProfileStore
from role_aware_dashboard_toolkit.profiles import save_profile

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
HEADERS = {"X-API-Key": "synthetic-unreadable-profile-key"}


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", HEADERS["X-API-Key"])


def _registry() -> ControlRegistry:
    registry = ControlRegistry()
    registry.register("Limit", kind="number", key="limit", default=5, min_value=0, max_value=100, step=1)
    return registry


def _corrupt_store(root: Path) -> tuple[ControlRegistry, Path, bytes]:
    registry = _registry()
    store = FileProfileStore(str(root))
    save_profile("prod", registry, {"limit": 42}, store=store)
    save_profile("staging", registry, {"limit": 7}, store=store)
    path = Path(store.resolve_path("prod"))
    damaged = path.read_bytes()[: len(path.read_bytes()) // 2]
    path.write_bytes(damaged)
    return registry, path, damaged


@pytest.mark.parametrize("shared_store", [True, False])
def test_api_reports_an_unreadable_profile_and_refuses_to_overwrite_it(tmp_path, shared_store):
    from fastapi.testclient import TestClient

    registry, path, damaged = _corrupt_store(tmp_path / "profiles")
    store_kwargs = ({"profile_store": FileProfileStore(str(tmp_path / "profiles"))} if shared_store
                    else {"profile_dir": str(tmp_path / "profiles")})
    audit = AuditLog()
    with TestClient(create_app(registry, audit=audit, api_role="Admin", **store_kwargs)) as client:
        read = client.get("/profiles/prod", headers=HEADERS)
        listing = client.get("/profiles", headers=HEADERS)
        overwrite = client.post("/profiles", headers=HEADERS, json={"profile_id": "prod"})
        activate = client.post("/profiles/prod/activate", headers=HEADERS)
        limit = client.get("/controls/limit", headers=HEADERS).json()["value"]

    assert read.status_code == 500
    assert read.json() == {"detail": (
        "Profile 'prod' exists but could not be read. Nothing was changed; "
        "repair or delete the stored record."
    )}
    assert listing.status_code == 200
    assert listing.json() == ["staging"]
    assert listing.headers["X-Unreadable-Records"] == "1"
    assert overwrite.status_code == 409
    assert "could not be read" in overwrite.json()["detail"]
    assert activate.status_code == 500
    assert path.read_bytes() == damaged
    assert limit == 5
    assert audit.all_events() == []
    for response in (read, overwrite, activate):
        assert str(tmp_path) not in response.text


def test_a_missing_profile_is_still_not_found_and_can_be_created(tmp_path):
    from fastapi.testclient import TestClient

    registry, _path, _damaged = _corrupt_store(tmp_path / "profiles")
    with TestClient(create_app(registry, profile_dir=str(tmp_path / "profiles"),
                               api_role="Admin")) as client:
        assert client.get("/profiles/absent", headers=HEADERS).status_code == 404
        assert client.post("/profiles/absent/activate", headers=HEADERS).status_code == 404
        assert client.post("/profiles", headers=HEADERS, json={"profile_id": "absent"}).status_code == 200
        assert client.post("/profiles", headers=HEADERS, json={"profile_id": "staging"}).status_code == 200
        assert client.get("/profiles/absent", headers=HEADERS).status_code == 200


def test_deleting_an_unreadable_profile_remains_the_repair_path(tmp_path):
    from fastapi.testclient import TestClient

    registry, path, _damaged = _corrupt_store(tmp_path / "profiles")
    with TestClient(create_app(registry, profile_dir=str(tmp_path / "profiles"),
                               api_role="Admin")) as client:
        deleted = client.request("DELETE", "/profiles/prod", headers=HEADERS)
        recreated = client.post("/profiles", headers=HEADERS, json={"profile_id": "prod"})

    assert deleted.status_code == 200
    assert recreated.status_code == 200
    assert path.exists()


def test_stores_without_read_diagnostics_keep_not_found():
    from fastapi.testclient import TestClient

    with TestClient(create_app(_registry(), profile_store=InMemoryProfileStore(),
                               api_role="Admin")) as client:
        response = client.get("/profiles/absent", headers=HEADERS)
        listing = client.get("/profiles", headers=HEADERS)

    assert response.status_code == 404
    assert "X-Unreadable-Records" not in listing.headers


def test_deleting_a_profile_whose_file_holds_another_record_is_refused_cleanly(tmp_path):
    # A wrong-backup copy: staging's file now holds prod's record. The store
    # refuses to delete it (that would remove prod's record); the API must
    # say so instead of failing with an unhandled server error.
    from fastapi.testclient import TestClient

    registry = _registry()
    store = FileProfileStore(str(tmp_path / "profiles"))
    save_profile("prod", registry, {"limit": 42}, store=store)
    save_profile("staging", registry, {"limit": 7}, store=store)
    staging = Path(store.resolve_path("staging"))
    staging.write_bytes(Path(store.resolve_path("prod")).read_bytes())
    audit = AuditLog()
    app = create_app(registry, audit=audit, api_role="Admin", profile_dir=str(tmp_path / "profiles"))
    with TestClient(app, raise_server_exceptions=False) as client:
        read = client.get("/profiles/staging", headers=HEADERS)
        deleted = client.request("DELETE", "/profiles/staging", headers=HEADERS)

    assert read.status_code == 500
    assert deleted.status_code == 409
    assert deleted.json() == {"detail": (
        "Profile 'staging' was not deleted: its stored file failed a safety check "
        "(for example, it holds a different record). Nothing was changed; repair the stored record."
    )}
    assert str(tmp_path) not in deleted.text
    assert staging.exists() and Path(store.resolve_path("prod")).exists()
    assert audit.all_events() == []
