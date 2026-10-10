"""Native profile loading preserves the confidentiality promised by its preview."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from role_aware_dashboard_toolkit import ControlRegistry, FileProfileStore, InMemoryProfileStore, load_profile
from role_aware_dashboard_toolkit.profiles import _load_ui_profile
from tests.test_authenticated_ui import _healthy, _host


AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _legacy_profile(nested):
    return {
        "profile_id": "legacy",
        "values": {
            "workers": 8, "connection": "HISTORICAL-CANARY", "note": nested,
            "private_value": "SAVED-CANARY", "removed": "REMOVED-CANARY",
            "settings": {"region": "west", "labels": ["public"]},
        },
        "control_meta": [{"key": "connection", "sensitive": True}],
    }


def _registry():
    registry = ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=3,
                      min_value=0, max_value=20, step=1)
    registry.register("Connection", kind="text", key="connection", default="live-connection")
    registry.register("Note", kind="text", key="note", default="live-note")
    registry.register("Private value", kind="text", key="private_value",
                      default="CURRENT-CANARY", sensitive=True)
    registry.register("Settings", kind="select", key="settings", default={},
                      options=[{}, {"region": "west", "labels": ["public"]}])
    return registry


def _consumer(host):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt
    from tests.test_native_profile_confidentiality import _registry

    if "config" not in st.session_state:
        registry = _registry()
        for control in registry.all():
            control.callback = lambda key, value: host.calls.append((key, value))
        st.session_state["config"] = radt.DashboardConfig(
            registry=registry, audit=host.audit, profile_store=host.profiles,
            access=host.policy,
            sections=radt.DashboardSections(runbook=False, audit_writer=False,
                                           audit_log=False, observability=False),
        )
    st.session_state["ctx"] = radt.render(st.session_state["config"])


def _app(profile):
    host = _host(("Operator",))
    host.store.compare_and_set_freeze(False, 0, host.principal)
    host.profiles = InMemoryProfileStore()
    host.profiles.save(profile)
    app = _healthy(AppTest.from_function(_consumer, args=(host,), default_timeout=15).run())
    _healthy(app.selectbox(key="_radt_profile_choice").select("legacy").run())
    return app, host


def _visible(app):
    return "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))


@pytest.mark.parametrize("nested", [
    {"password": "NESTED-CANARY"},
    {"settings": [{"api_key": "NESTED-CANARY"}]},
    [{"Authorization": "NESTED-CANARY"}],
])
def test_authenticated_operator_load_cannot_reveal_hidden_legacy_profile_values(nested):
    original = _legacy_profile(nested)
    app, host = _app(original)
    assert "CANARY" not in _visible(app)
    rows = app.dataframe[0].value.set_index("Control")
    assert rows.loc["Connection", "Result"] == "Sensitive value not restored"
    assert rows.loc["Note", "Result"] == "Sensitive value not restored"
    # Excluded fields must not require write permission when their live values
    # are unchanged. Safe fields in the same profile still apply.
    registry = app.session_state["config"].registry
    registry.get("connection").permission = "can_edit_connection"
    registry.get("note").permission = "can_edit_note"

    _healthy(app.button(key="_radt_profile_load").click().run())

    assert app.session_state["ctx"].role == "Operator"
    assert app.session_state["workers"] == 8
    assert app.session_state["settings"] == original["values"]["settings"]
    assert app.session_state["connection"] == "live-connection"
    assert app.session_state["note"] == "live-note"
    assert app.session_state["private_value"] == "CURRENT-CANARY"
    assert "CANARY" not in _visible(app)
    assert host.profiles.load("legacy") == original
    assert {key for key, _ in host.calls} == {"workers", "settings"}
    assert [event["type"] for event in host.audit.all_events()
            if event["type"].startswith("profile_")] == ["profile_load"]


@pytest.mark.parametrize("boundary", ["freeze", "role", "field_permission"])
def test_native_projection_keeps_load_permission_and_freeze_preflight(boundary):
    original = _legacy_profile({"password": "NESTED-CANARY"})
    app, host = _app(original)
    registry = app.session_state["config"].registry
    # AppTest exposes keyed access, not the Mapping interface used by a real
    # Streamlit session. Capture the actual values without relying on .get().
    before = {control.key: app.session_state[control.key] for control in registry.all()}
    if boundary == "freeze":
        freeze = host.store.read_freeze()
        host.store.compare_and_set_freeze(True, freeze.revision, host.principal)
    elif boundary == "role":
        host.store.replace_grants(host.principal, ("Viewer",))
    else:
        app.session_state["config"].registry.get("workers").permission = "can_edit_workers"

    _healthy(app.button(key="_radt_profile_load").click().run())

    assert {control.key: app.session_state[control.key] for control in registry.all()} == before
    assert host.profiles.load("legacy") == original
    assert not host.calls
    assert not any(event["type"] == "profile_load" for event in host.audit.all_events())
    assert "CANARY" not in _visible(app)


@pytest.mark.parametrize("change", ["stored_secret", "current_sensitive"])
def test_load_rechecks_saved_values_and_current_sensitivity_after_preview(change):
    original = {"profile_id": "legacy", "values": {"workers": 8, "note": "public-note"}}
    app, host = _app(original)
    assert app.dataframe[0].value.set_index("Control").loc["Note", "Saved"] == "public-note"
    if change == "stored_secret":
        host.profiles.save({**original, "values": {"workers": 8, "note": {"password": "LATE-CANARY"}}})
    else:
        app.session_state["config"].registry.get("note").sensitive = True
    saved = deepcopy(host.profiles.load("legacy"))

    _healthy(app.button(key="_radt_profile_load").click().run())

    assert app.session_state["workers"] == 8
    assert app.session_state["note"] == "live-note"
    assert host.profiles.load("legacy") == saved
    assert "CANARY" not in _visible(app)
    assert {key for key, _ in host.calls} == {"workers"}


def test_projection_preserves_ordinary_text_and_structured_public_values():
    original = {"profile_id": "legacy", "values": {
        "workers": 8, "connection": "public-connection", "note": {"region": "west"},
        "settings": {"region": "west", "labels": ["public"]},
    }}
    app, host = _app(original)

    _healthy(app.button(key="_radt_profile_load").click().run())

    assert app.session_state["connection"] == "public-connection"
    assert app.session_state["note"] == "{'region': 'west'}"
    assert app.session_state["workers"] == 8
    assert app.session_state["settings"] == original["values"]["settings"]
    assert host.profiles.load("legacy") == original


def test_native_projection_leaves_file_evidence_and_core_restore_contract_unchanged(tmp_path):
    registry = _registry()
    store = FileProfileStore(str(tmp_path))
    original = _legacy_profile({"password": "NESTED-CANARY"})
    path = Path(store.save(original))
    saved_bytes = path.read_bytes()
    native_state = registry.snapshot({})

    _load_ui_profile("legacy", registry, native_state, store=store)

    assert native_state["connection"] == "live-connection"
    assert native_state["note"] == "live-note"
    assert native_state["workers"] == 8
    assert path.read_bytes() == saved_bytes
    # The public dictionary helper remains a trusted host API. Its historical
    # restoration contract is not silently changed by the browser projection.
    core_state = registry.snapshot({})
    load_profile("legacy", registry, core_state, store=store)
    assert core_state["connection"] == original["values"]["connection"]
    assert core_state["note"] == str(original["values"]["note"])
    assert core_state["private_value"] == "CURRENT-CANARY"
    assert path.read_bytes() == saved_bytes
