"""Adopter boundary regressions, including real Streamlit reruns."""
from __future__ import annotations

import pytest

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit import dashboard


@pytest.mark.parametrize("bounds", [
    {"min_value": 5, "max_value": 5},
    {"min_value": 10},
    {"max_value": -5},
    {"min_value": 1},
    {"max_value": 0},
    {"min_value": float("inf")},
    {"max_value": "invalid"},
])
def test_slider_rejects_invalid_effective_bounds_before_registration(bounds):
    registry = radt.ControlRegistry()
    original = registry.register("Retained", kind="toggle", key="retained")
    with pytest.raises(ValueError) as caught:
        registry.register("Slider", kind="slider", key="slider", **bounds)
    assert caught.value.diagnostic["code"] == "RADT-CONTROL-DEFINITION"
    assert registry.all() == [original]


@pytest.mark.parametrize("name,key", [
    ("Host label", "_radt_role"),
    ("Host label", "_radt_read_only_control__value"),
    ("_radt_role", None),
])
def test_reserved_state_namespace_is_rejected_without_registration(name, key):
    registry = radt.ControlRegistry()
    with pytest.raises(ValueError, match="reserved") as caught:
        registry.register(name, kind="text", key=key)
    assert caught.value.diagnostic["code"] == "RADT-CONTROL-DEFINITION"
    assert registry.all() == []


@pytest.mark.parametrize("bounds,initial,clamped,updated", [
    ({}, 8, 1.0, 0.25),
    ({"min_value": -5}, 8, 1.0, -2.0),
    ({"max_value": 5}, -8, 0.0, 2.0),
])
def test_slider_restore_and_widget_share_implicit_bounds(bounds, initial, clamped, updated):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    registry = radt.ControlRegistry()
    registry.register("Value", kind="slider", key="value", **bounds)
    state = {}
    registry.restore(state, {"value": initial})
    assert state["value"] == clamped
    source = (
        "import streamlit as st\n"
        "import role_aware_dashboard_toolkit as r\n"
        "registry = r.ControlRegistry()\n"
        f"registry.register('Value', kind='slider', key='value', **{bounds!r})\n"
        f"if 'value' not in st.session_state: st.session_state['value'] = {initial!r}\n"
        "r.render(r.DashboardConfig(auth_mode='demo', registry=registry))\n"
    )
    app = AppTest.from_string(source).run()
    assert not app.exception
    assert app.slider(key="value").value == clamped
    app.slider(key="value").set_value(updated).run()
    assert not app.exception
    assert app.slider(key="value").value == updated


@pytest.mark.parametrize("field,value", [
    ("max_value", 10**20),
    ("min_value", -(10**20)),
    ("step", 1 << 53),
])
def test_wide_integer_core_definition_fails_ui_preflight_before_side_effects(monkeypatch, field, value):
    registry = radt.ControlRegistry()
    options = {"min_value": 0, "max_value": 10, "step": 1, "default": 1, field: value}
    registry.register("Count", kind="number", key="count", **options)
    assert registry.get("count") is not None  # Still supported in the core.
    effects = []
    plugins = radt.PluginRegistry()
    plugins.register(radt.DashboardPlugin(name="setup", setup=lambda _: effects.append("setup")))

    class NoUI:
        def __getattr__(self, name):
            effects.append(name)
            raise AssertionError("UI was accessed before numeric preflight")

    monkeypatch.setattr(dashboard, "_require_streamlit", lambda: NoUI())
    with pytest.raises(ValueError, match=r"2\*\*53") as caught:
        dashboard.render(radt.DashboardConfig(auth_mode="demo", registry=registry, plugins=plugins))
    assert caught.value.diagnostic["code"] == "RADT-CONTROL-RENDER"
    assert caught.value.diagnostic["guide_topic"] == "controls"
    assert effects == []


def test_plugin_added_integer_definition_is_checked_before_native_widgets(monkeypatch):
    from types import SimpleNamespace

    registry = radt.ControlRegistry()
    effects = []

    def setup(_context):
        effects.append("setup")
        registry.register("Count", kind="number", key="count", default=1,
                          min_value=0, max_value=10**20, step=1)

    plugins = radt.PluginRegistry()
    plugins.register(radt.DashboardPlugin(name="setup", setup=setup))
    monkeypatch.setattr(dashboard, "_require_streamlit", lambda: SimpleNamespace(session_state={}))
    with pytest.raises(ValueError) as caught:
        dashboard.render(radt.DashboardConfig(auth_mode="demo", registry=registry, plugins=plugins))
    assert caught.value.diagnostic["code"] == "RADT-CONTROL-RENDER"
    assert effects == ["setup"]


def test_safe_integer_limits_and_sensitive_wide_number_render_and_edit():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    source = """
import role_aware_dashboard_toolkit as r
registry = r.ControlRegistry()
maximum = (1 << 53) - 1
registry.register('Count', kind='number', key='count', default=maximum,
                  min_value=-maximum, max_value=maximum, step=1)
registry.register('Protected count', kind='number', key='protected_count', default=1,
                  min_value=0, max_value=10**20, step=1, sensitive=True)
r.render(r.DashboardConfig(auth_mode='demo', registry=registry))
"""
    app = AppTest.from_string(source).run()
    assert not app.exception
    maximum = (1 << 53) - 1
    assert app.number_input(key="count").value == maximum
    app.number_input(key="count").set_value(-maximum).run()
    assert not app.exception
    assert app.number_input(key="count").value == -maximum
    app.text_input(key="_radt_sensitive_replacement__protected_count").set_value("2")
    app.button(key="_radt_sensitive_submit__protected_count").click().run()
    assert not app.exception
    assert app.session_state["protected_count"] == 2


def test_equal_number_bounds_remain_supported():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_string("""
import role_aware_dashboard_toolkit as r
registry = r.ControlRegistry()
registry.register('Fixed count', kind='number', key='count', default=5,
                  min_value=5, max_value=5, step=1)
r.render(r.DashboardConfig(auth_mode='demo', registry=registry))
""").run()
    assert not app.exception
    assert app.number_input(key="count").value == 5
