"""Generated host HTTP checks inspect independently committed records/history."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import sqlite3
import sys

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "role_aware_dashboard_toolkit/resources/web_host_starter"
ORIGIN = "http://127.0.0.1:8093"


@pytest.fixture
def host(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    destination = tmp_path / "app"
    shutil.copytree(SOURCE, destination)
    monkeypatch.syspath_prepend(str(destination))
    names = [name for name in sys.modules if name == "host" or name.startswith("host.")]
    for name in names:
        monkeypatch.delitem(sys.modules, name)
    spec = importlib.util.spec_from_file_location("_generated_web_host_app", destination / "app.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    from host.storage import initialize

    directory = initialize(tmp_path / "private")
    service = module.WorkItems(directory)
    tokens = {subject: service.issue_token(subject, role) for subject, role in (
        ("manager", "Manager"), ("alex", "Operator"), ("viewer", "Viewer"),
    )}
    app = module.create_app(data_dir=directory, public_origin=ORIGIN)
    with TestClient(app, base_url=ORIGIN) as client:
        yield module, client, service, tokens, directory
    for name in list(sys.modules):
        if name == "host" or name.startswith("host."):
            sys.modules.pop(name, None)


def authorization(token):
    return {"Authorization": "Bearer " + token}


def observe(directory):
    with sqlite3.connect(directory / "records.sqlite3") as connection:
        return tuple(connection.execute("SELECT * FROM items ORDER BY id")), tuple(
            connection.execute("SELECT * FROM history ORDER BY id"))


def unfreeze(client, tokens, revision=0):
    response = client.post("/api/freeze", headers=authorization(tokens["manager"]),
                           json={"frozen": False, "expected_revision": revision})
    assert response.status_code == 200, response.text
    return response.json()


def create_item(client, tokens, owner="alex"):
    response = client.post("/api/items", headers=authorization(tokens["manager"]),
                           json={"label": "Prepare welcome pack", "starts_at": "2030-06-10T09:00:00-04:00",
                                 "owner": owner})
    assert response.status_code == 201, response.text
    return response.json()["item"]


def change(client, token, item, **updates):
    payload = {"expected_revision": item["revision"], "status": "completed", **updates}
    return client.post(f"/api/items/{item['id']}/status", headers=authorization(token), json=payload)


def test_starts_empty_frozen_and_requires_current_bearer(host):
    _, client, _, tokens, directory = host
    for headers in ({}, authorization("A" * 43), {"Cookie": "session=manager"},
                    {"Authorization": "Bearer manager"}):
        assert client.get("/api/session", headers=headers).status_code == 401
    response = client.get("/api/session", headers=authorization(tokens["manager"]))
    assert response.json() == {"subject": "manager", "role": "Manager", "can_edit": True,
                               "can_manage": True, "freeze": {"frozen": True, "revision": 0}}
    before = observe(directory)
    response = client.post("/api/items", headers=authorization(tokens["manager"]),
                           json={"label": "Blocked", "starts_at": "2030-01-01T12:00:00Z", "owner": "alex"})
    assert response.status_code == 403
    assert observe(directory) == before == ((), ())


def test_changes_history_and_unexpired_token_survive_new_host_instance(host):
    module, client, _, tokens, directory = host
    unfreeze(client, tokens)
    item = create_item(client, tokens)
    response = change(client, tokens["alex"], item)
    assert response.status_code == 200
    assert response.json()["item"]["revision"] == 1
    from fastapi.testclient import TestClient

    with TestClient(module.create_app(data_dir=directory, public_origin=ORIGIN), base_url=ORIGIN) as restarted:
        rows = restarted.get("/api/items", headers=authorization(tokens["alex"])).json()["items"]
        assert rows[0]["status"] == "completed" and rows[0]["revision"] == 1
        events = restarted.get("/api/history", headers=authorization(tokens["manager"])).json()["history"]
        assert [event["action"] for event in events] == ["created", "status_changed"]
        assert events[1]["before"]["revision"] == 0 and events[1]["after"]["revision"] == 1
    assert tokens["alex"].encode() not in (directory / "records.sqlite3").read_bytes()


@pytest.mark.parametrize("denial", ["viewer", "scope", "grant", "revoke", "freeze", "expiry"])
def test_loaded_form_loses_authority_without_changing_records_or_history(host, denial):
    _, client, service, tokens, directory = host
    unfreeze(client, tokens)
    item = create_item(client, tokens, owner="other" if denial == "scope" else "alex")
    token = tokens["viewer"] if denial == "viewer" else tokens["alex"]
    if denial == "grant":
        service.grant("alex", "Viewer")
    elif denial == "revoke":
        service.revoke("alex")
    elif denial == "freeze":
        response = client.post("/api/freeze", headers=authorization(tokens["manager"]),
                               json={"frozen": True, "expected_revision": 1})
        assert response.status_code == 200
    elif denial == "expiry":
        with service.transaction() as connection:
            connection.execute("UPDATE tokens SET expires_at = 1 WHERE subject = 'alex'")
    before = observe(directory)
    assert change(client, token, item).status_code == (401 if denial in {"revoke", "expiry"} else 403)
    assert observe(directory) == before


def test_operator_list_scope_and_manager_only_endpoints(host):
    _, client, _, tokens, directory = host
    unfreeze(client, tokens)
    owned = create_item(client, tokens)
    create_item(client, tokens, owner="other")
    assert client.get("/api/items", headers=authorization(tokens["alex"])).json()["items"] == [owned]
    assert len(client.get("/api/items", headers=authorization(tokens["viewer"])).json()["items"]) == 2
    before = observe(directory)
    for subject in ("alex", "viewer"):
        headers = authorization(tokens[subject])
        assert client.get("/api/history", headers=headers).status_code == 403
        assert client.post("/api/freeze", headers=headers,
                           json={"frozen": True, "expected_revision": 1}).status_code == 403
        assert client.post("/api/items", headers=headers,
                           json={"label": "Forged", "starts_at": owned["starts_at"], "owner": subject}).status_code == 403
    assert observe(directory) == before


def test_stale_and_repeated_submissions_conflict_and_noop_does_not_add_history(host):
    _, client, _, tokens, directory = host
    unfreeze(client, tokens)
    item = create_item(client, tokens)
    before = observe(directory)
    response = change(client, tokens["alex"], item, status="scheduled")
    assert response.status_code == 200 and response.json()["changed"] is False
    assert observe(directory) == before
    response = change(client, tokens["manager"], item)
    assert response.status_code == 200
    saved = observe(directory)
    assert change(client, tokens["alex"], item, status="cancelled", reason="Other plan").status_code == 409
    assert change(client, tokens["manager"], item).status_code == 409
    assert observe(directory) == saved
    assert client.post("/api/freeze", headers=authorization(tokens["manager"]),
                       json={"frozen": True, "expected_revision": 0}).status_code == 409


def test_reschedule_and_cancellation_rules_are_server_enforced(host):
    _, client, _, tokens, directory = host
    unfreeze(client, tokens)
    item = create_item(client, tokens)
    url = f"/api/items/{item['id']}/reschedule"
    headers = authorization(tokens["alex"])
    before = observe(directory)
    for value in ("tomorrow", "2030-06-10T12:00"):
        assert client.post(url, headers=headers,
                           json={"expected_revision": 0, "starts_at": value}).status_code == 422
    assert change(client, tokens["alex"], item, status="cancelled").status_code == 422
    assert observe(directory) == before
    response = client.post(url, headers=headers,
                           json={"expected_revision": 0, "starts_at": "2030-06-11T10:00:00+02:00"})
    assert response.status_code == 200
    item = response.json()["item"]
    assert item["starts_at"] == "2030-06-11T08:00:00+00:00"
    response = change(client, tokens["alex"], item, status="cancelled", reason="Customer unavailable")
    assert response.status_code == 200
    item = response.json()["item"]
    saved = observe(directory)
    assert change(client, tokens["alex"], item).status_code == 422
    assert client.post(url, headers=headers,
                       json={"expected_revision": item["revision"], "starts_at": "2030-06-12T10:00:00Z"}).status_code == 422
    assert observe(directory) == saved
    assert change(client, tokens["alex"], item, status="scheduled").status_code == 200


@pytest.mark.parametrize("operation", ["create", "change"])
def test_history_failure_rolls_back_records_and_returns_safe_storage_error(host, operation):
    _, client, service, tokens, directory = host
    unfreeze(client, tokens)
    item = create_item(client, tokens)
    with service.transaction() as connection:
        connection.execute("CREATE TRIGGER reject_history BEFORE INSERT ON history "
                           "BEGIN SELECT RAISE(ABORT, 'PRIVATE_DATABASE_DETAIL'); END")
    before = observe(directory)
    if operation == "create":
        response = client.post("/api/items", headers=authorization(tokens["manager"]),
                               json={"label": "Second", "starts_at": item["starts_at"], "owner": "alex"})
    else:
        response = change(client, tokens["alex"], item)
    assert response.status_code == 503
    assert "PRIVATE_DATABASE_DETAIL" not in response.text
    assert observe(directory) == before


@pytest.mark.parametrize("payload", [
    {"expected_revision": True, "status": "completed"},
    {"expected_revision": 0, "status": "completed", "role": "Manager"},
    {"expected_revision": "0", "status": "completed"},
    {"expected_revision": -1, "status": "completed"},
    {"expected_revision": 0, "status": "completed", "reason": "SECRET_INPUT" * 100},
])
def test_strict_request_validation_does_not_echo_inputs_or_write(host, payload):
    _, client, _, tokens, directory = host
    unfreeze(client, tokens)
    item = create_item(client, tokens)
    before = observe(directory)
    response = client.post(f"/api/items/{item['id']}/status", headers=authorization(tokens["alex"]), json=payload)
    assert response.status_code == 422 and "SECRET_INPUT" not in response.text
    assert observe(directory) == before


def test_host_origin_body_and_static_boundaries(host):
    _, client, _, tokens, _ = host
    assert client.get("/healthz").status_code == 200
    response = client.get("/healthz", headers={"Host": "attacker.invalid"})
    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/api/items", headers={**authorization(tokens["manager"]),
                                             "Origin": "https://attacker.invalid"}).status_code == 403
    assert client.get("/api/items", headers={**authorization(tokens["manager"]),
                                             "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/items", headers=authorization(tokens["manager"]), content=b"x" * 16385).status_code == 413
    for path in ("/assets/identity.key", "/assets/records.sqlite3", "/assets/app.py", "/docs", "/openapi.json"):
        assert client.get(path).status_code == 404


@pytest.mark.parametrize("body", [
    '{"label":"First","label":"Second","starts_at":"2030-06-10T12:00:00Z","owner":"alex"}',
    '{"label":"First","starts_at":"2030-06-10T12:00:00Z","owner":"alex","extra":NaN}',
    '{"label":"First","starts_at":"2030-06-10T12:00:00Z","owner":"alex","extra":Infinity}',
    '{"label":"First","starts_at":"2030-06-10T12:00:00Z","owner":"alex","extra":1e999}',
    '{"label":"First","starts_at":"2030-06-10T12:00:00Z","owner":"alex","nested":{"x":1,"x":2}}',
])
def test_ambiguous_or_nonfinite_json_is_rejected_before_mutation(host, body):
    _, client, _, tokens, directory = host
    unfreeze(client, tokens)
    before = observe(directory)
    response = client.post("/api/items", headers={**authorization(tokens["manager"]),
                                                  "Content-Type": "application/json"}, content=body)
    assert response.status_code == 422 and "distinct fields" in response.json()["detail"]
    assert observe(directory) == before


def test_missing_storage_wrong_schema_changed_key_and_in_source_data_are_refused(host, tmp_path):
    module, _, _, _, directory = host
    with pytest.raises((ValueError, module.StorageUnavailable)):
        module.create_app(data_dir=tmp_path / "missing")
    from host.storage import APP_ROOT, initialize

    with pytest.raises(ValueError):
        initialize(APP_ROOT / "private")
    with pytest.raises(FileExistsError):
        initialize(directory)
    key = (directory / "identity.key").read_bytes()
    (directory / "identity.key").write_bytes(b"x" * 32)
    with pytest.raises(module.StorageUnavailable):
        module.create_app(data_dir=directory)
    (directory / "identity.key").write_bytes(key)
    with sqlite3.connect(directory / "records.sqlite3") as connection:
        connection.execute("UPDATE metadata SET version = 99")
    with pytest.raises(module.StorageUnavailable):
        module.create_app(data_dir=directory)


@pytest.mark.parametrize("origin", ["http://example.com", "https://example.com/", "https://user:pass@example.com",
                                    "https://example.com?x=1", "https://example.com:bad", "javascript:alert(1)"])
def test_origin_configuration_refuses_unsafe_or_ambiguous_values(host, origin):
    module, _, _, _, directory = host
    with pytest.raises(ValueError):
        module.create_app(data_dir=directory, public_origin=origin)


def test_copied_action_recipe_remains_identical():
    root = Path(__file__).resolve().parents[1]
    assert (SOURCE / "host/actions.py").read_bytes() == (root / "examples/record_workflows/actions.py").read_bytes()
