"""Control identity stays a string before JSON/API state is constructed."""
import json

import pytest

from role_aware_dashboard_toolkit import ControlDef, ControlRegistry
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app


@pytest.mark.parametrize("key", [0, 1, True, False, 1.5, b"workers", ("workers",), [], {}])
def test_nonstring_registration_does_not_change_existing_controls_or_order(key):
    registry = ControlRegistry()
    first = registry.register("Workers", kind="number", key="1", default=3)
    before = registry.export_metadata()
    with pytest.raises(TypeError, match="Control key must be a string") as raised:
        registry.register("Invalid", kind="toggle", key=key, sensitive=False)
    assert raised.value.diagnostic["code"] == "RADT-CONTROL-DEFINITION"
    assert registry.export_metadata() == before
    assert registry.get("1") is first
    assert registry.register("Next", kind="toggle", key="next").order == first.order + 1


@pytest.mark.parametrize("key", [None, 1, False, b"workers", (), [], {}])
def test_direct_control_definitions_require_string_keys(key):
    with pytest.raises(TypeError, match="Control key must be a string"):
        ControlDef(name="Workers", kind="number", key=key)


@pytest.mark.parametrize("key", ["", "plant/rate", "plant//rate/", "café/測定"])
def test_string_keys_keep_their_exact_json_and_snapshot_identity(key):
    registry = ControlRegistry()
    control = registry.register("Workers", kind="number", key=key, default=3)
    state = {}
    registry.ensure_defaults(state)
    assert control.key == key
    assert state == {key: 3}
    assert json.loads(json.dumps(registry.snapshot(state))) == {key: 3}
    assert json.loads(json.dumps(registry.export_metadata()))[0]["key"] == key
    assert ControlDef(name="Workers", kind="number", key=key).key == key


def test_none_key_still_derives_a_string_from_the_name():
    registry = ControlRegistry()
    assert registry.register("Requests Per/Second", key=None).key == "requests_per/second"


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
def test_rejected_numeric_key_cannot_collide_with_an_existing_api_control(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", raising=False)
    registry = ControlRegistry()
    for key in ("1", "", "plant/rate", "café/測定"):
        registry.register("Workers", kind="number", key=key, default=3)
    with pytest.raises(TypeError):
        registry.register("Collision", kind="number", key=1, default=99)
    with TestClient(create_app(registry, allow_anonymous=True)) as client:
        response = client.get("/controls")
    assert response.status_code == 200
    assert {item["key"]: item["value"] for item in response.json()} == {
        "1": 3, "": 3, "plant/rate": 3, "café/測定": 3,
    }
