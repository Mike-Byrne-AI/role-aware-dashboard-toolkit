"""HTTP live state is durable, revisioned, and isolated from failed writes."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app
from role_aware_dashboard_toolkit.state_store import (
    InMemoryStateStore, SQLiteStateStore, StateSnapshot, StateStoreError,
)


pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
HEADERS = {"X-API-Key": "synthetic-state-tests-only"}


@pytest.fixture(autouse=True)
def api_key(monkeypatch):
    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", HEADERS["X-API-Key"])


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryStateStore()
    return SQLiteStateStore.create(tmp_path / "state.sqlite3")


def _registry():
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8,
                      min_value=1, max_value=40, step=1)
    registry.register("Label", kind="text", key="label", default="Day")
    registry.register("API token", kind="text", key="api_token", default="SYNTHETIC-SECRET",
                      sensitive=True)
    return registry


@contextmanager
def _client(store=None, *, registry=None, profiles=None):
    from fastapi.testclient import TestClient

    audit = AuditLog()
    if profiles is None:
        profiles = InMemoryProfileStore()
    app = create_app(
        _registry() if registry is None else registry,
        audit=audit, state_store=store, profile_store=profiles, api_role="Admin",
    )
    with TestClient(app) as client:
        yield client, audit, profiles


def _headers(revision):
    return {**HEADERS, "If-Match": f'"{revision}"'}


def test_backend_requires_revision_and_publishes_current_etag(store):
    with _client(store) as (client, audit, _profiles):
        response = client.get("/controls", headers=HEADERS)
        assert response.status_code == 200
        assert response.headers["ETag"] == '"0"'
        assert client.get("/controls/workers", headers=HEADERS).headers["ETag"] == '"0"'
        refused = client.patch("/controls", headers=HEADERS, json={"values": {"workers": 5}})
        assert refused.status_code == 428
        assert store.read() == StateSnapshot({}, 0)
        assert audit.all_events() == []
        updated = client.patch("/controls", headers=_headers(0), json={"values": {"workers": 5}})
        assert updated.status_code == 200, updated.text
        assert updated.headers["ETag"] == '"1"'
        assert store.read() == StateSnapshot({"workers": 5, "label": "Day"}, 1)
        assert "api_token" not in store.read().values
        assert client.get("/controls/workers", headers=HEADERS).headers["ETag"] == '"1"'


@pytest.mark.parametrize("etag", ['"0"', '*', 'W/"1"', '1', '"1", "2"'])
def test_conflicting_batch_cannot_change_any_value_or_audit(store, etag):
    store.compare_and_set({"workers": 4, "label": "Retained"}, 0)
    with _client(store) as (client, audit, _profiles):
        before = store.read()
        response = client.patch("/controls", headers={**HEADERS, "If-Match": etag},
                                json={"values": {"workers": 20, "label": "Wrong"}})
        assert response.status_code == 409
        assert store.read() == before
        assert audit.all_events() == []


def test_two_apps_and_restart_read_new_sqlite_values(tmp_path):
    path = tmp_path / "state.sqlite3"
    first = SQLiteStateStore.create(path)
    second = SQLiteStateStore(path)
    with _client(first) as (one, _audit_one, _profiles_one), _client(second) as (
        two, _audit_two, _profiles_two,
    ):
        assert two.get("/controls/workers", headers=HEADERS).json()["value"] == 8
        assert one.patch("/controls", headers=_headers(0),
                         json={"values": {"workers": 12}}).status_code == 200
        fresh = two.get("/controls/workers", headers=HEADERS)
        assert fresh.json()["value"] == 12
        assert fresh.headers["ETag"] == '"1"'
        assert two.patch("/controls", headers=_headers(1),
                         json={"values": {"label": "Evening"}}).status_code == 200
        assert one.get("/controls/label", headers=HEADERS).json()["value"] == "Evening"
    with _client(SQLiteStateStore(path)) as (restarted, _audit, _profiles):
        response = restarted.get("/controls", headers=HEADERS)
        assert response.headers["ETag"] == '"2"'
        assert {item["key"]: item["value"] for item in response.json()} == {
            "workers": 12, "label": "Evening", "api_token": "<redacted-secret>",
        }


def test_competing_apps_with_same_etag_have_one_commit_and_one_audit(tmp_path):
    path = tmp_path / "state.sqlite3"
    first = SQLiteStateStore.create(path)
    second = SQLiteStateStore(path)
    barrier = Barrier(2)

    class RacingStore:
        def __init__(self, backend):
            self.backend = backend

        def read(self):
            return self.backend.read()

        def compare_and_set(self, values, expected_revision):
            barrier.wait(timeout=5)
            return self.backend.compare_and_set(values, expected_revision)

    with _client(RacingStore(first)) as (one, audit_one, _profiles_one), _client(
        RacingStore(second)
    ) as (two, audit_two, _profiles_two):
        def update(client, workers):
            return client.patch("/controls", headers=_headers(0),
                                json={"values": {"workers": workers}})

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(update, one, 10), pool.submit(update, two, 20)]
            responses = [future.result(timeout=10) for future in futures]
        assert sorted(response.status_code for response in responses) == [200, 409]
        assert first.read().revision == 1
        winner = next(response for response in responses if response.status_code == 200)
        assert first.read().values["workers"] == winner.json()[0]["value"]
        events = audit_one.all_events() + audit_two.all_events()
        assert len(events) == 1
        assert events[0]["type"] == "control_change"


def test_failed_state_commit_does_not_change_live_values_or_emit_success(store, monkeypatch):
    with _client(store) as (client, audit, _profiles):
        before = store.read()

        def fail(*_args, **_kwargs):
            raise StateStoreError()

        with monkeypatch.context() as patch:
            patch.setattr(store, "compare_and_set", fail)
            response = client.patch("/controls", headers=_headers(0),
                                    json={"values": {"workers": 12, "label": "Wrong"}})
        assert response.status_code == 503
        assert response.json() == {"detail": "Control state is unavailable."}
        assert store.read() == before
        assert client.get("/controls/workers", headers=HEADERS).json()["value"] == 8
        assert audit.all_events() == []


@pytest.mark.parametrize("values", [
    {"unknown": 1}, {"workers": "invalid-number"}, {"api_token": "SYNTHETIC-PRIVATE"},
    {"label": {"token": "SYNTHETIC-PRIVATE"}},
])
def test_stored_values_outside_public_control_schema_fail_closed(store, values):
    store.compare_and_set(values, 0)
    with _client(store) as (client, audit, _profiles):
        response = client.get("/controls", headers=HEADERS)
        assert response.status_code == 503
        assert response.json() == {"detail": "Control state is unavailable."}
        assert "SYNTHETIC-PRIVATE" not in response.text
        assert audit.all_events() == []


def test_missing_backend_is_not_recreated_by_a_request(tmp_path):
    path = tmp_path / "state.sqlite3"
    store = SQLiteStateStore.create(path)
    with _client(store) as (client, audit, _profiles):
        assert client.get("/controls", headers=HEADERS).status_code == 200
        path.unlink()
        response = client.get("/controls", headers=HEADERS)
        assert response.status_code == 503
        assert not path.exists()
        assert str(path) not in response.text
        assert audit.all_events() == []


def test_sensitive_update_refusal_is_atomic_and_not_persisted(store):
    with _client(store) as (client, audit, _profiles):
        response = client.patch("/controls", headers=_headers(0), json={"values": {
            "workers": 12, "api_token": "SYNTHETIC-NEW-SECRET",
        }})
        assert response.status_code == 422
        assert "SYNTHETIC-NEW-SECRET" not in response.text
        assert store.read() == StateSnapshot({}, 0)
        assert audit.all_events() == []


def test_structured_secret_field_is_not_written_to_public_state(store):
    registry = _registry()
    public = {"label": "public"}
    private = {"label": "private", "token": "SYNTHETIC-NESTED-SECRET"}
    registry.register("Settings", kind="select", key="settings", default=public,
                      options=[public, private])
    with _client(store, registry=registry) as (client, audit, _profiles):
        response = client.patch("/controls", headers=_headers(0),
                                json={"values": {"workers": 12, "settings": private}})
        assert response.status_code == 422
        assert "SYNTHETIC-NESTED-SECRET" not in response.text
        assert store.read() == StateSnapshot({}, 0)
        assert audit.all_events() == []


def test_profile_activation_requires_current_revision_and_commits_once(store):
    profiles = InMemoryProfileStore()
    profiles.save({"profile_id": "night", "values": {"workers": 2, "label": "Night"}})
    with _client(store, profiles=profiles) as (client, audit, _profiles):
        assert client.post("/profiles/night/activate", headers=HEADERS).status_code == 428
        store.compare_and_set({"workers": 6, "label": "Current"}, 0)
        stale = client.post("/profiles/night/activate", headers=_headers(0))
        assert stale.status_code == 409
        assert store.read() == StateSnapshot({"workers": 6, "label": "Current"}, 1)
        assert audit.all_events() == []
        activated = client.post("/profiles/night/activate", headers=_headers(1))
        assert activated.status_code == 200, activated.text
        assert activated.headers["ETag"] == '"2"'
        assert store.read() == StateSnapshot({"workers": 2, "label": "Night"}, 2)
        assert [event["type"] for event in audit.all_events()] == ["profile_load"]


def test_profile_save_refreshes_current_backend_values(store):
    with _client(store) as (client, _audit, profiles):
        assert client.get("/controls", headers=HEADERS).headers["ETag"] == '"0"'
        store.compare_and_set({"workers": 17, "label": "External change"}, 0)
        response = client.post("/profiles", headers=HEADERS, json={"profile_id": "latest"})
        assert response.status_code == 200, response.text
        assert profiles.load("latest")["values"] == {"workers": 17, "label": "External change"}
        assert store.read().revision == 1  # Saving a profile does not change live state.


def test_legacy_memory_api_keeps_sensitive_updates_and_optional_revision():
    with _client() as (client, audit, _profiles):
        response = client.patch("/controls", headers=HEADERS,
                                json={"values": {"api_token": "SYNTHETIC-NEW-SECRET"}})
        assert response.status_code == 200
        assert response.json()[0]["value"] == "<redacted-secret>"
        assert response.headers["ETag"] == '"1"'
        before = audit.all_events()
        stale = client.patch("/controls", headers=_headers(0), json={"values": {"workers": 10}})
        assert stale.status_code == 409
        assert audit.all_events() == before
        fresh = client.patch("/controls", headers=_headers(1), json={"values": {"workers": 10}})
        assert fresh.status_code == 200
        assert fresh.headers["ETag"] == '"2"'
