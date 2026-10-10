"""Partial presets explain retained settings without treating secrets as missing."""

import pytest

from tests.test_authenticated_ui import _healthy, _host


AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def _partial_profile_consumer(host, include_restricted_control):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    if "config" not in st.session_state:
        registry = radt.ControlRegistry()
        registry.register("Capacity", kind="number", key="capacity", default=10,
                          min_value=0, max_value=100, step=1)
        if include_restricted_control:
            registry.register("Quality", kind="number", key="quality", default=95,
                              min_value=0, max_value=100, step=1,
                              permission="can_edit_quality")
        registry.register("Private value", kind="text", key="private_value",
                          default="retained-secret-canary", sensitive=True,
                          permission="can_edit_private_value")
        store = radt.InMemoryProfileStore()
        store.save({"profile_id": "planning", "values": {"capacity": 25}})
        st.session_state["config"] = radt.DashboardConfig(
            registry=registry, profile_store=store, audit=host.audit,
            auth_mode="authenticated", access=host.policy,
            sections=radt.DashboardSections(runbook=False, audit_writer=False,
                                           audit_log=False, observability=False),
        )
    st.session_state["ctx"] = radt.render(st.session_state["config"])


@pytest.mark.parametrize("include_restricted_control", [True, False])
def test_partial_load_preserves_restricted_values_and_uses_neutral_feedback(include_restricted_control):
    host = _host(("Operator",))
    host.store.compare_and_set_freeze(False, 0, host.principal)
    app = _healthy(AppTest.from_function(
        _partial_profile_consumer, args=(host, include_restricted_control), default_timeout=15,
    ).run())
    secret_before = app.session_state["private_value"]
    _healthy(app.selectbox(key="_radt_profile_choice").select("planning").run())

    _healthy(app.button(key="_radt_profile_load").click().run())

    assert app.session_state["ctx"].role == "Operator"
    assert app.number_input(key="capacity").value == 25
    assert app.session_state["private_value"] == secret_before
    if include_restricted_control:
        assert app.session_state["quality"] == 95
        assert app.number_input(key="_radt_read_only_control__quality").disabled
    assert [toast.value for toast in app.get("toast")] == ["Loaded profile: planning"]
    assert [event["type"] for event in host.audit.all_events()
            if event["type"].startswith("profile_")] == ["profile_load"]
    captions = " ".join(item.value for item in app.caption)
    neutral = "This preset updates only the settings it includes."
    assert (neutral in captions) is include_restricted_control
    assert not any("missing" in item.value.lower() for item in app.warning)
    visible = "\n".join(str(element.proto) for element in app if hasattr(element, "proto"))
    assert secret_before not in visible
