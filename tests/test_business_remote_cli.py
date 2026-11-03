"""Explicit remote activation, safe status and actual application lifespan ownership."""

from tools.business_login_client import login_post

import asyncio
import importlib.util
import json
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from tests.test_business_remote_obligations import (
    COLLECTOR, DESCRIPTOR, REMOTE, enable, fingerprint, record, source as source, sources as sources,
)
from tests.test_business_remote_delivery import (
    answer, configured_transport, forbid_real_network as forbid_real_network, private_configuration,
)
from business.app import create_app
from business.event_destinations import destination_status
from business.event_wire import load_transport
from business.secret_store import default_key_path
from tools.business_dashboard_browser import prepare_fixture, synthetic_mfa_clock

SCRIPT = Path(__file__).resolve().parents[1] / "examples/business_dashboard/configure_security_delivery.py"
SPEC = importlib.util.spec_from_file_location("business_remote_cli_test", SCRIPT)
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)
ORIGIN = "http://127.0.0.1:8091"


def arguments(source, command, *extra):
    return [command, "--data-dir", str(source.directory), "--mfa-key-file", str(source.key), *extra]


def activation(source, config_file, *extra):
    return arguments(source, "enable", "--collector-id", COLLECTOR, "--destination-id", REMOTE,
                     "--endpoint", DESCRIPTOR.endpoint, "--config-file", str(config_file), *extra)


def test_activation_requires_maintenance_assertion_before_any_database_change(source, capsys):
    path, _, token = private_configuration(source)
    before = fingerprint(source)
    with pytest.raises(SystemExit) as caught:
        cli.main(activation(source, path))
    assert caught.value.code == 2 and fingerprint(source) == before
    assert token not in capsys.readouterr().err


def test_activation_with_valid_private_configuration_backfills_and_reports_no_delivery_claim(source, capsys):
    path, _, token = private_configuration(source)
    record(source)
    assert cli.main(activation(source, path, "--maintenance-confirmed")) == 0
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert result["scope"] == "all_retained_events_queued" and result["delivery_verified"] is False
    assert result["backfill_retained_count"] == 1 and result["destination_id"] == REMOTE
    assert token not in output.out and DESCRIPTOR.endpoint not in output.out and output.err == ""
    with source.database.readonly_snapshot() as connection:
        assert destination_status(connection, REMOTE)["pending"] == 2
    before = fingerprint(source)
    assert cli.main(activation(source, path, "--maintenance-confirmed")) == 1
    assert fingerprint(source) == before


@pytest.mark.parametrize("updates", [{"source_id": "a" * 32}, {"destination_id": "a" * 32}, {"endpoint": "https://wrong.invalid/v1/events"}])
def test_mismatched_private_configuration_cannot_activate_or_change_the_database(source, capsys, updates):
    path, _, token = private_configuration(source, updates=updates)
    before = fingerprint(source)
    assert cli.main(activation(source, path, "--maintenance-confirmed")) == 1
    assert fingerprint(source) == before
    output = capsys.readouterr()
    assert output.out == "" and "refused" in output.err
    assert token not in output.err and str(path) not in output.err and "wrong.invalid" not in output.err


def test_status_is_read_only_and_separates_local_and_remote_acknowledgements(source, capsys):
    from business.security_events import dispatch_pending

    enable(source)
    dispatch_pending(source.database)
    before = fingerprint(source)
    assert cli.main(arguments(source, "status")) == 0
    result = json.loads(capsys.readouterr().out)
    local = next(row for row in result["destinations"] if row["kind"] == "local")
    remote_status = next(row for row in result["destinations"] if row["kind"] == "https")
    assert local["pending"] == 0 and local["acknowledged"] == 1
    assert remote_status["pending"] == 1 and remote_status["acknowledged"] == 0
    assert DESCRIPTOR.endpoint not in json.dumps(result) and fingerprint(source) == before


def test_protected_remote_status_discloses_no_endpoints_or_tokens_and_denies_other_roles(sources, monkeypatch):
    seed = sources()
    directory = seed.directory.parent / "enrolled-api"
    credentials, app = prepare_fixture(directory, ORIGIN)
    database = app.state.database
    path, _, token = private_configuration(SimpleNamespace(directory=directory, database=database))
    loaded = Event()

    async def fail_remote(self, body, *, heartbeat=False):
        assert self.token == token
        loaded.set()
        raise load_transport().DeliveryFailure("remote_unavailable")

    monkeypatch.setattr(load_transport().HttpsTransport, "post", fail_remote)
    app = create_app(directory, public_origin=ORIGIN, mfa_key_file=default_key_path(directory),
                     security_delivery_config=path)
    with database.transaction() as connection:
        from business.event_destinations import enable_remote_destination

        enable_remote_destination(connection, DESCRIPTOR)
    with synthetic_mfa_clock(database) as code, TestClient(app, base_url=ORIGIN) as client:
        assert loaded.wait(timeout=5)
        assert client.get("/api/admin/security/events").status_code == 401
        response = login_post(client, "/api/login", headers={"Origin": ORIGIN}, json={
            "username": "alex", "password": credentials["alex"], "otp": code("alex"),
        })
        assert response.status_code == 200
        assert client.get("/api/admin/security/events").status_code == 403
        response = login_post(client, "/api/login", headers={"Origin": ORIGIN}, json={
            "username": "admin", "password": credentials["admin"], "otp": code("admin"),
        })
        assert response.status_code == 200
        response = client.get("/api/admin/security/events")
        assert response.status_code == 200
        result = response.json()
        assert result["delivery"]["semantics"] == "at_least_once_idempotent_local_consumer"
        assert result["remote_delivery"]["destinations"][0]["destination_id"] == REMOTE
        assert result["remote_delivery"]["destinations"][0]["pending"] > 0
        assert DESCRIPTOR.endpoint not in response.text and str(default_key_path(directory)) not in response.text
        assert token not in response.text and str(path) not in response.text
        assert all(password not in response.text for password in credentials.values())


def test_application_final_lifespan_stop_joins_the_actual_remote_worker(source, monkeypatch):
    enable(source)
    entered, cancelled = Event(), Event()

    class Transport:
        async def post(self, body, *, heartbeat=False):
            if heartbeat:
                return answer(body, heartbeat=True)
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

    configured_transport(monkeypatch, Transport())
    app = create_app(source.directory, public_origin=ORIGIN, mfa_key_file=source.key)
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.get("/healthz").status_code == 200
        assert entered.wait(timeout=5)
        assert app.state.remote_security_dispatcher.snapshot()["running"]
    assert cancelled.is_set()
    assert not app.state.remote_security_dispatcher.snapshot()["running"]
    assert not app.state.security_dispatcher.snapshot()["running"]
    with source.database.transaction() as connection:
        assert destination_status(connection, REMOTE)["pending"] == 1
