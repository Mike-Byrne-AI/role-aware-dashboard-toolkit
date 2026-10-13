"""Appearance contracts, injection boundaries, and real Streamlit rendering."""
from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit.appearance import (
    build_streamlit_theme_toml,
    group_background_color,
    styled_group_container,
    validate_dashboard_appearance,
    validate_dashboard_colors,
)
from role_aware_dashboard_toolkit.controls import ControlRegistry
from role_aware_dashboard_toolkit.dashboard_panels import render_groups
from role_aware_dashboard_toolkit.security import make_security_context
from tests.demo_role_helpers import start_as_admin

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def test_official_theme_snippet_has_distinct_page_widget_text_accent_and_sidebar_options():
    text = build_streamlit_theme_toml(
        base="dark", background_color="#101a20",
        secondary_background_color="#203040", text_color="#f5f6f7",
        primary_color="#aa6600", sidebar_background_color="#253545",
        sidebar_secondary_background_color="#354555", sidebar_text_color="#e0e0e0",
    )
    parsed = tomllib.loads(text)
    assert parsed == {"theme": {
        "base": "dark", "backgroundColor": "#101A20",
        "secondaryBackgroundColor": "#203040", "textColor": "#F5F6F7",
        "primaryColor": "#AA6600", "sidebar": {
            "backgroundColor": "#253545", "secondaryBackgroundColor": "#354555",
            "textColor": "#E0E0E0",
        },
    }}
    assert "Streamlit >=1.44" in text
    assert "config.toml before starting" in text
    assert "rather than adding a duplicate" in text


def test_minimal_theme_snippet_omits_unset_options_and_sidebar_requirement():
    text = build_streamlit_theme_toml()
    assert tomllib.loads(text) == {"theme": {"base": "light"}}
    assert ">=1.30" in text
    assert ">=1.44" not in text
    assert "[theme.sidebar]" not in text


@pytest.mark.parametrize("name", [
    "background_color", "secondary_background_color", "text_color", "primary_color",
    "sidebar_background_color", "sidebar_secondary_background_color", "sidebar_text_color",
])
@pytest.mark.parametrize("value", ["red", "#123", "#123456; color:red", "#000000\n[server]", False])
def test_theme_generator_rejects_invalid_colors_and_config_injection(name, value):
    with pytest.raises(ValueError, match="#RRGGBB"):
        build_streamlit_theme_toml(**{name: value})


@pytest.mark.parametrize("base", ["auto", "LIGHT", 'light"\n[server]', None, False])
def test_theme_generator_rejects_invalid_base(base):
    with pytest.raises(ValueError, match="base"):
        build_streamlit_theme_toml(base=base)


def test_color_validation_normalizes_and_detaches_mapping_without_mutating_input():
    original = {"Operations": "#aabbcc"}
    default, groups = validate_dashboard_colors("#ddeeff", original)
    assert default == "#DDEEFF"
    assert groups == {"Operations": "#AABBCC"}
    assert original == {"Operations": "#aabbcc"}
    original["Operations"] = "#112233"
    assert groups["Operations"] == "#AABBCC"
    assert validate_dashboard_colors(None, None) == (None, {})


@pytest.mark.parametrize("default, overrides", [
    ("transparent", None), ("#000000}</style><script>", {}),
    (None, {"Ops": "#fff"}), (None, {"Ops": None}), (None, {"": "#112233"}),
    (None, {3: "#112233"}), (None, []),
])
def test_dashboard_colors_reject_invalid_types_and_css_injection(default, overrides):
    with pytest.raises((TypeError, ValueError)):
        validate_dashboard_colors(default, overrides)


def test_group_override_falls_back_to_default_and_unset_preserves_existing_theme():
    config = SimpleNamespace(card_background_color="#aabbcc",
                             group_background_colors={"Ops": "#112233"})
    assert group_background_color(config, "Ops") == "#112233"
    assert group_background_color(config, "Other") == "#AABBCC"
    assert group_background_color(SimpleNamespace(), "Ops") is None


def test_group_validation_accepts_registered_hidden_groups_and_rejects_typos():
    registry = ControlRegistry()
    registry.register("One", kind="text", group="Ops")
    registry.register("Two", kind="text", group="Hidden", visible=False)
    config = SimpleNamespace(registry=registry, card_background_color=None,
                             group_background_colors={"Hidden": "#112233"})
    validate_dashboard_appearance(config)
    config.group_background_colors["Typo"] = "#445566"
    with pytest.raises(ValueError, match="unknown control groups: Typo"):
        validate_dashboard_appearance(config)


class _StyledStreamlit:
    def __init__(self):
        self.events = []

    def html(self, text):
        self.events.append(("html", text))

    def container(self, *, key=None, border=None):
        self.events.append(("container", key, border))
        return nullcontext()

    def expander(self, label, *, expanded=False):
        self.events.append(("expander", label, expanded))
        return nullcontext()

    def columns(self, count):
        self.events.append(("columns", count))
        return [nullcontext() for _ in range(count)]

    def markdown(self, text):
        self.events.append(("markdown", text))


class _OlderStreamlit(_StyledStreamlit):
    def container(self, *, border=None):
        self.events.append(("container", None, border))
        return nullcontext()


@pytest.mark.parametrize("layout", ["stacked", "columns"])
def test_unstyled_rendering_preserves_legacy_container_and_expander_semantics(layout):
    st = _OlderStreamlit()
    config = SimpleNamespace(layout=layout, columns_per_row=2)
    render_groups(st, [("Ops", []), ("Safety", [])], make_security_context("Viewer"), config)
    if layout == "stacked":
        assert st.events == [("expander", "Ops", True), ("expander", "Safety", True)]
    else:
        assert st.events == [
            ("columns", 2), ("container", None, True), ("markdown", "**Ops**"),
            ("container", None, True), ("markdown", "**Safety**"),
        ]


@pytest.mark.parametrize("layout", ["stacked", "columns"])
def test_styled_groups_use_scoped_stable_keys_and_keep_borders_or_expanders(layout):
    st = _StyledStreamlit()
    config = SimpleNamespace(layout=layout, columns_per_row=2,
                             card_background_color="#AABBCC",
                             group_background_colors={"Safety": "#DDEEFF"})
    render_groups(st, [("Ops", []), ("Safety", [])], make_security_context("Viewer"), config)
    containers = [event for event in st.events if event[0] == "container"]
    assert len(containers) == 2
    assert containers[0][1] != containers[1][1]
    assert all(event[2] is (layout == "columns") for event in containers)
    css = [event[1] for event in st.events if event[0] == "html"]
    assert len(css) == 2
    assert css[0] == f"<style>.st-key-{containers[0][1]} {{ background-color: #AABBCC; }}</style>"
    assert "#DDEEFF" in css[1]
    assert all("data-testid" not in text and "body" not in text for text in css)
    if layout == "stacked":
        assert [event for event in st.events if event[0] == "expander"] == [
            ("expander", "Ops", True), ("expander", "Safety", True)]
    else:
        assert not any(event[0] == "expander" for event in st.events)
    again = _StyledStreamlit()
    styled_group_container(again, "Ops", "#112233", border=True)
    assert again.events[-1][1] == containers[0][1]


def test_group_name_cannot_inject_css_and_unicode_names_are_supported():
    st = _StyledStreamlit()
    group = 'Operations 東京 } </style><script>alert(1)</script>'
    styled_group_container(st, group, "#aabbcc", border=True)
    css = st.events[0][1]
    assert group not in css
    assert "<script>" not in css
    assert "#AABBCC" in css


def test_requesting_fill_on_old_container_api_fails_before_emitting_any_css():
    st = _OlderStreamlit()
    with pytest.raises(RuntimeError, match="Streamlit >=1.39"):
        styled_group_container(st, "Ops", "#112233", border=True)
    assert st.events == []


def test_appearance_module_import_and_theme_generation_need_no_optional_runtime(tmp_path):
    root = str(Path(__file__).resolve().parents[1])
    program = f"""
import sys
sys.path.insert(0, {root!r})
from role_aware_dashboard_toolkit.appearance import build_streamlit_theme_toml
assert 'backgroundColor = "#112233"' in build_streamlit_theme_toml(background_color='#112233')
assert not any(name in sys.modules for name in ['streamlit', 'pandas', 'fastapi'])
"""
    result = subprocess.run(
        [sys.executable, "-B", "-S", "-c", program], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def _appearance_consumer(layout):
    import role_aware_dashboard_toolkit as radt

    registry = radt.ControlRegistry()
    registry.register("Workers", kind="number", key="workers", group="Operations",
                      default=8, min_value=1, max_value=40, step=1)
    registry.register("Maintenance", kind="toggle", key="maintenance", group="Safety",
                      default=False)
    radt.render(radt.DashboardConfig(
        registry=registry, profile_store=radt.InMemoryProfileStore(), layout=layout,
        card_background_color="#DDEEFF", group_background_colors={"Safety": "#FFEEDD"},
    ))


@pytest.mark.parametrize("layout", ["stacked", "columns"])
def test_real_streamlit_styled_groups_keep_controls_working_across_reruns(layout):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = start_as_admin(AppTest.from_function(_appearance_consumer, args=(layout,))).run()
    assert not app.exception, [item.message for item in app.exception]
    app.number_input(key="workers").set_value(24)
    app.toggle(key="maintenance").set_value(True)
    app.run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.number_input(key="workers").value == 24
    assert app.toggle(key="maintenance").value is True


def _plugin_group_consumer():
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    registry = radt.ControlRegistry()
    plugins = radt.PluginRegistry()

    def setup(context):
        context["config"].registry.register(
            "Plugin status", kind="text", key="plugin_status", group="Plugin group",
            default="ready")

    plugins.register(radt.DashboardPlugin(name="group-provider", setup=setup))
    radt.render(radt.DashboardConfig(
        registry=registry, plugins=plugins, profile_store=radt.InMemoryProfileStore(),
        group_background_colors={"Plugin group": "#DDEEFF"}))
    st.caption("Plugin setup complete")


def test_real_render_validates_group_names_after_plugin_registration():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = start_as_admin(AppTest.from_function(_plugin_group_consumer)).run()
    assert not app.exception, [item.message for item in app.exception]
    assert app.text_input(key="plugin_status").value == "ready"
    assert any(item.value == "Plugin setup complete" for item in app.caption)


def test_runtime_preflight_requires_new_api_only_when_appearance_is_requested():
    config = SimpleNamespace(card_background_color=None, group_background_colors={})
    old = _OlderStreamlit()
    validate_dashboard_appearance(config, st=old)
    config.card_background_color = "#112233"
    with pytest.raises(RuntimeError, match="Streamlit >=1.39"):
        validate_dashboard_appearance(config, st=old)
    assert old.events == []


def _unsupported_style_consumer():
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    config = radt.DashboardConfig(
        card_background_color="#112233", profile_store=radt.InMemoryProfileStore())
    original = st.container

    def older_container(*, border=None):
        return original(border=border)

    st.container = older_container
    try:
        radt.render(config)
    finally:
        st.container = original


def test_unsupported_runtime_reports_configuration_error_before_sidebar_actions():
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = start_as_admin(AppTest.from_function(_unsupported_style_consumer)).run()
    assert len(app.exception) == 1
    assert "Streamlit >=1.39" in app.exception[0].message
    assert not app.button
    assert not app.selectbox


def _failed_plugin_group_consumer(auth_result):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    plugins = radt.PluginRegistry()

    def setup(_context):
        raise RuntimeError("synthetic-plugin-secret in private setup")

    def auth():
        st.session_state["auth_calls"] = st.session_state.get("auth_calls", 0) + 1
        return auth_result

    plugins.register(radt.DashboardPlugin(name="private-plugin-name", setup=setup))
    radt.render(radt.DashboardConfig(
        plugins=plugins, auth_hook=auth, profile_store=radt.InMemoryProfileStore(),
        group_background_colors={"Plugin group": "#DDEEFF"},
    ))


@pytest.mark.parametrize("auth_result", ["Admin", "unknown-role"])
def test_failed_styled_plugin_preserves_safe_failure_cause_before_auth_or_widgets(auth_result):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = AppTest.from_function(_failed_plugin_group_consumer, args=(auth_result,)).run()
    assert len(app.exception) == 1
    message = app.exception[0].message
    assert "unknown control groups: Plugin group" in message
    assert "Plugin setup also failed for 1 plugin(s)" in message
    assert "check plugin setup configuration and retry" in message
    assert "synthetic-plugin-secret" not in message
    assert "private-plugin-name" not in message
    assert not app.warning
    assert not app.button
    assert not app.selectbox
    assert "auth_calls" not in app.session_state


def _plugin_control_lifecycle_consumer(styled):
    import streamlit as st
    import role_aware_dashboard_toolkit as radt

    # Definitions are intentionally rebuilt on every script run, as in an
    # ordinary installed-package consumer. Only durable evidence survives.
    registry = radt.ControlRegistry()
    plugins = radt.PluginRegistry()

    def setup(context):
        controls = context["config"].registry
        controls.register("Plugin workers", kind="number", key="plugin_workers",
                          default=8, min_value=1, max_value=40, step=1, group="Plugin group")
        controls.register("Plugin weight", kind="slider", key="plugin_weight",
                          default=0.5, min_value=0.0, max_value=1.0, step=0.05, group="Plugin group")
        controls.register("Plugin mode", kind="select", key="plugin_mode",
                          default="safe", options=["safe", "fast"], group="Plugin group")
        controls.register("Plugin enabled", kind="toggle", key="plugin_enabled",
                          default=False, group="Plugin group")
        controls.register("Plugin note", kind="text", key="plugin_note",
                          default="baseline", group="Plugin group")
        controls.register("Plugin color", kind="color", key="plugin_color",
                          default="#112233", group="Plugin group")
        controls.register("Plugin token", kind="text", key="plugin_token",
                          default="synthetic-default-token", sensitive=True, group="Plugin group")

    plugins.register(radt.DashboardPlugin(name="control-provider", setup=setup))
    if "lifecycle_runs" not in st.session_state:
        st.session_state["lifecycle_runs"] = radt.InMemoryRunStore()
    radt.render(radt.DashboardConfig(
        registry=registry, plugins=plugins, profile_store=radt.InMemoryProfileStore(),
        run_store=st.session_state["lifecycle_runs"],
        group_background_colors={"Plugin group": "#DDEEFF"} if styled else None,
    ))


@pytest.mark.parametrize("styled", [False, True])
def test_plugin_registered_controls_survive_start_checkpoint_and_end_reruns(styled):
    AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
    app = start_as_admin(AppTest.from_function(_plugin_control_lifecycle_consumer, args=(styled,))).run()
    assert not app.exception, [item.message for item in app.exception]

    def set_values(workers):
        values = {
            "plugin_workers": workers, "plugin_weight": 0.75, "plugin_mode": "fast",
            "plugin_enabled": True, "plugin_note": f"workers-{workers}",
            "plugin_color": "#AABBCC", "plugin_token": "synthetic-live-token",
        }
        app.number_input(key="plugin_workers").set_value(values["plugin_workers"])
        app.slider(key="plugin_weight").set_value(values["plugin_weight"])
        app.selectbox(key="plugin_mode").select(values["plugin_mode"])
        app.toggle(key="plugin_enabled").set_value(values["plugin_enabled"])
        app.text_input(key="plugin_note").set_value(values["plugin_note"])
        app.color_picker(key="plugin_color").set_value(values["plugin_color"])
        app.text_input(key="_radt_sensitive_replacement__plugin_token").set_value(values["plugin_token"])
        app.button(key="_radt_sensitive_submit__plugin_token").click().run()
        assert not app.exception, [item.message for item in app.exception]
        return values

    def assert_live_values(expected):
        assert not app.exception, [item.message for item in app.exception]
        assert {key: app.session_state[key] for key in expected} == expected

    first = set_values(20)
    app.button(key="_radt_run_start").click().run()
    assert_live_values(first)
    run_id = app.session_state["_radt_active_run_id"]
    store = app.session_state["lifecycle_runs"]
    assert store.load(run_id)["initial_controls"] == {
        key: value for key, value in first.items() if key != "plugin_token"
    }

    second = set_values(24)
    app.button(key="_radt_run_checkpoint").click().run()
    assert_live_values(second)
    assert store.load(run_id)["checkpoints"][-1]["controls"] == {
        key: value for key, value in second.items() if key != "plugin_token"
    }

    third = set_values(30)
    app.button(key="_radt_run_end").click().run()
    assert_live_values(third)
    assert store.load(run_id)["status"] == "completed"
    assert app.session_state["_radt_active_run_id"] == ""
