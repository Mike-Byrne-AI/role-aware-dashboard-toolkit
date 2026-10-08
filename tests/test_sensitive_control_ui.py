"""Stored sensitive values never enter outgoing Streamlit widget payloads."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from tests.test_authenticated_ui import _healthy, _host

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
INPUT_KEY = "_radt_sensitive_replacement__protected_value"
SUBMIT_KEY = "_radt_sensitive_submit__protected_value"
CASES = [
    ("text", "SYNTHETIC-OLD-CREDENTIAL", {}, "SYNTHETIC-NEW-CREDENTIAL", "SYNTHETIC-NEW-CREDENTIAL"),
    ("number", 731, {"min_value": 0, "max_value": 1000, "step": 1}, "732", 732),
    ("slider", 73.125, {"min_value": 0.0, "max_value": 100.0, "step": 0.125}, "74.25", 74.25),
    ("toggle", True, {}, "false", False),
    ("color", "#a1b2c3", {}, "#d4e5f6", "#d4e5f6"),
    ("select", "SYNTHETIC-OLD-CHOICE", {"options": ["SYNTHETIC-OLD-CHOICE", "SYNTHETIC-NEW-CHOICE"]},
     '"SYNTHETIC-NEW-CHOICE"', "SYNTHETIC-NEW-CHOICE"),
]


def _consumer(host, kind, default, settings):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register(
            "Protected value", kind=kind, key="protected_value", default=default,
            sensitive=True, callback=lambda *args: host.control_calls.append(args), **settings,
        )
        st.session_state["config"] = radt.DashboardConfig(
            registry=registry, audit=host.audit, access=host.policy,
            on_change=lambda *args: host.global_calls.append(args),
            sections=radt.DashboardSections(profiles=False, runbook=False, audit_writer=False,
                                           audit_log=False, observability=False, plugin_details=False),
        )
    st.session_state["test_context"] = radt.render(st.session_state["config"])


def _app(kind, default, settings, *, role="Admin", frozen=False):
    host = _host((role,))
    host.control_calls = []
    host.global_calls = []
    if not frozen:
        host.store.compare_and_set_freeze(False, 0, host.principal)
    app = _healthy(AppTest.from_function(
        _consumer, args=(host, kind, default, settings), default_timeout=15,
    ).run())
    return app, host


def _client_payload(app):
    return "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))


def _assert_blank_client(app):
    for widget in app.text_input:
        assert widget.proto.default == ""
        assert widget.proto.value == ""
        assert widget.value == ""
        assert widget.key != "protected_value"
    for kind in ("number_input", "slider", "toggle", "color_picker", "selectbox"):
        assert all(widget.label != "Protected value" for widget in app.get(kind))


@pytest.mark.parametrize("kind,default,settings,replacement,expected", CASES)
@pytest.mark.parametrize("role,frozen", [("Viewer", False), ("Admin", True), ("Admin", False)])
def test_all_sensitive_kinds_keep_values_options_and_defaults_out_of_client_payloads(
    kind, default, settings, replacement, expected, role, frozen,
):
    app, host = _app(kind, default, settings, role=role, frozen=frozen)
    _assert_blank_client(app)
    if isinstance(default, str):
        assert default not in _client_payload(app)
    for option in settings.get("options", []):
        assert option not in _client_payload(app)
    assert app.session_state["protected_value"] == default
    assert not host.control_calls
    assert not host.global_calls
    assert len(app.text_input) == (1 if role == "Admin" and not frozen else 0)


@pytest.mark.parametrize("kind,default,settings,replacement,expected", CASES)
def test_explicit_replacement_clears_draft_and_calls_callbacks_once_without_disclosure(
    kind, default, settings, replacement, expected,
):
    app, host = _app(kind, default, settings)
    original_widget_id = app.text_input(key=INPUT_KEY).id
    app.text_input(key=INPUT_KEY).set_value(replacement)
    _healthy(app.button(key=SUBMIT_KEY).click().run())
    assert app.session_state["protected_value"] == expected
    assert type(app.session_state["protected_value"]) is type(expected)
    _assert_blank_client(app)
    assert app.text_input(key=INPUT_KEY).id == original_widget_id
    assert host.control_calls == [("protected_value", expected)]
    assert host.global_calls == [("protected_value", default, expected)]
    changes = [event for event in host.audit.all_events() if event["type"] == "control_change"]
    assert len(changes) == 1
    assert changes[0]["old"] == changes[0]["new"] == "<redacted-secret>"
    _healthy(app.run())
    _assert_blank_client(app)
    assert len(host.control_calls) == len(host.global_calls) == 1
    assert app.session_state["protected_value"] == expected


def test_text_clear_requires_explicit_submission_and_remains_empty_after_rerun():
    app, host = _app("text", "SYNTHETIC-OLD", {})
    _healthy(app.run())
    assert app.session_state["protected_value"] == "SYNTHETIC-OLD"
    _healthy(app.button(key=SUBMIT_KEY).click().run())
    assert app.session_state["protected_value"] == ""
    _healthy(app.run())
    assert app.session_state["protected_value"] == ""
    assert host.control_calls == [("protected_value", "")]


@pytest.mark.parametrize("denial", ["freeze", "downgrade", "revoke"])
def test_denied_stale_submission_discards_draft_and_does_not_call_host(denial):
    app, host = _app("text", "SYNTHETIC-OLD", {})
    app.text_input(key=INPUT_KEY).set_value("SYNTHETIC-DENIED-DRAFT")
    submit = app.button(key=SUBMIT_KEY)
    if denial == "freeze":
        state = host.store.read_freeze()
        host.store.compare_and_set_freeze(True, state.revision, host.principal)
    else:
        host.store.replace_grants(host.principal, ("Viewer",) if denial == "downgrade" else ())
    _healthy(submit.click().run())
    assert "SYNTHETIC-DENIED-DRAFT" not in _client_payload(app)
    assert not host.control_calls
    assert not host.global_calls
    host.store.replace_grants(host.principal, ("Admin",))
    state = host.store.read_freeze()
    host.store.compare_and_set_freeze(False, state.revision, host.principal)
    _healthy(app.run())
    assert app.session_state["protected_value"] == "SYNTHETIC-OLD"
    _assert_blank_client(app)


@pytest.mark.parametrize("kind,default,settings,bad", [
    ("number", 9, {}, ""), ("slider", 0.5, {}, "nan"),
    ("toggle", True, {}, "not-a-boolean"), ("color", "#123456", {}, "bad-color"),
    ("select", "first", {"options": ["first", "second"]}, '"unassigned"'),
    ("select", "first", {"options": ["first", "second"]}, "[" * 2000 + "0" + "]" * 2000),
])
def test_invalid_replacements_are_generic_and_preserve_state(kind, default, settings, bad):
    app, host = _app(kind, default, settings)
    app.text_input(key=INPUT_KEY).set_value(bad)
    _healthy(app.button(key=SUBMIT_KEY).click().run())
    assert app.session_state["protected_value"] == default
    assert [error.value for error in app.error] == ["Replacement is invalid; the stored value was preserved."]
    assert not host.control_calls
    _assert_blank_client(app)


@pytest.mark.parametrize("selected", [1, "1", True, [1], [True], {"a": 1}, {"a": True}])
def test_json_select_replacements_preserve_types_without_option_disclosure(selected):
    options = ["initial", 1, "1", True, [1], [True], {"a": 1}, {"a": True}]
    app, host = _app("select", "initial", {"options": deepcopy(options)})
    app.text_input(key=INPUT_KEY).set_value(json.dumps(selected))
    _healthy(app.button(key=SUBMIT_KEY).click().run())
    assert type(app.session_state["protected_value"]) is type(selected)
    assert json.dumps(app.session_state["protected_value"]) == json.dumps(selected)
    assert host.control_calls == [("protected_value", selected)]
    _assert_blank_client(app)


@pytest.mark.parametrize("initial,selected", [
    (1, True), (True, 1), ([1], [True]), ([True], [1]),
    ({"a": 1}, {"a": True}), ({"a": True}, {"a": 1}),
])
def test_equal_comparing_select_types_still_emit_real_changes(initial, selected):
    app, host = _app("select", initial, {"options": [initial, selected]})
    app.text_input(key=INPUT_KEY).set_value(json.dumps(selected))
    _healthy(app.button(key=SUBMIT_KEY).click().run())
    assert json.dumps(app.session_state["protected_value"]) == json.dumps(selected)
    assert host.global_calls == [("protected_value", initial, selected)]
    assert len([event for event in host.audit.all_events() if event["type"] == "control_change"]) == 1
    _assert_blank_client(app)


def test_same_replacement_does_not_duplicate_audit_or_callback():
    app, host = _app("text", "SYNTHETIC-SAME", {})
    app.text_input(key=INPUT_KEY).set_value("SYNTHETIC-SAME")
    _healthy(app.button(key=SUBMIT_KEY).click().run())
    assert not host.control_calls
    assert not [event for event in host.audit.all_events() if event["type"] == "control_change"]
    _assert_blank_client(app)


def test_live_permission_is_rechecked_after_submission_before_mutation():
    from types import SimpleNamespace
    from role_aware_dashboard_toolkit import AuditLog, ControlRegistry
    from role_aware_dashboard_toolkit.dashboard_panels import _render_sensitive_control
    from role_aware_dashboard_toolkit.security import SecurityContext
    from tests.test_role_aware_dashboard_toolkit import RecordingStreamlit

    allowed = {"write": True}
    calls = []
    registry = ControlRegistry()
    control = registry.register("Protected", kind="text", key="protected_value",
                                sensitive=True, default="SYNTHETIC-OLD", callback=lambda *args: calls.append(args))
    runtime = RecordingStreamlit()
    runtime.session_state[INPUT_KEY] = "SYNTHETIC-DENIED-DRAFT"

    def submit(*args, **kwargs):
        allowed["write"] = False
        return True

    runtime.form_submit_button = submit
    ctx = SecurityContext(authenticated=True, perms={"can_edit_controls": True},
                          _authorize=lambda *_: allowed["write"])
    audit = AuditLog()
    _render_sensitive_control(runtime, control, ctx, SimpleNamespace(registry=registry, audit=audit))
    assert runtime.session_state.get("protected_value", control.default) == "SYNTHETIC-OLD"
    assert runtime.session_state[INPUT_KEY] == ""
    assert not calls and not audit.all_events()
    assert runtime.messages["warning"]
