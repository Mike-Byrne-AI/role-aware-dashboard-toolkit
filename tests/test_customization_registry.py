"""Definition-removal behavior for dashboard customization."""

from copy import deepcopy

import pytest

from role_aware_dashboard_toolkit import (
    ControlRegistry,
    DashboardPlugin,
    InMemoryProfileStore,
    PluginRegistry,
    build_profile,
)
from role_aware_dashboard_toolkit.plugins import PluginSourceRecord


def test_control_removal_updates_all_definition_views_and_keeps_other_groups():
    registry = ControlRegistry()
    first = registry.register("First", kind="toggle", key="first", group="Retained")
    removed = registry.register("Old", kind="text", key="old", group="Removed")
    third = registry.register("Third", kind="color", key="third", group="Retained")
    assert registry.unregister("old") is removed
    assert registry.get("old") is None
    assert "old" not in registry
    assert registry.keys() == ["first", "third"]
    assert list(registry) == ["first", "third"]
    assert registry.all() == [first, third]
    assert len(registry) == 2
    assert registry.iter_groups() == [("Retained", [first, third])]
    assert [item["key"] for item in registry.export_metadata()] == ["first", "third"]
    assert registry.snapshot({"first": True, "old": "old value"}) == {
        "first": True, "third": third.default,
    }


def test_control_removal_preserves_session_and_previously_saved_profile():
    registry = ControlRegistry()
    registry.register("Old", kind="number", key="old", default=1, min_value=0, max_value=10)
    registry.register("Retained", kind="toggle", key="retained", default=False)
    state = {"old": 8, "retained": True, "_radt_user_set__old": True}
    store = InMemoryProfileStore()
    store.save(build_profile("before-removal", registry, state))
    before = deepcopy(store.load("before-removal"))
    registry.unregister("old")
    assert state == {"old": 8, "retained": True, "_radt_user_set__old": True}
    assert store.load("before-removal") == before
    assert registry.persistable_snapshot(state) == {"retained": True}
    registry.restore(state, {"old": 3, "retained": False})
    assert state["old"] == 8
    assert state["retained"] is False
    fresh_state = {}
    assert registry.ensure_defaults(fresh_state) == 1
    assert fresh_state == {"retained": False}


def test_control_unknown_removal_is_atomic_and_key_can_be_registered_again():
    registry = ControlRegistry()
    old = registry.register("Old", kind="toggle", key="setting", default=False, group="Old")
    retained = registry.register("Other", kind="toggle", key="other")
    before = registry.export_metadata()
    with pytest.raises(KeyError, match="missing"):
        registry.unregister("missing")
    assert registry.export_metadata() == before
    assert registry.get("setting") is old
    assert registry.unregister("setting") is old
    replacement = registry.register("New", kind="text", key="setting", default="new", group="New")
    assert replacement is not old
    assert registry.all() == [retained, replacement]
    assert registry.iter_groups() == [("Controls", [retained]), ("New", [replacement])]
    state = {}
    assert registry.ensure_defaults(state) == 2
    assert state == {"other": False, "setting": "new"}


def _recording_plugin(name, calls):
    return DashboardPlugin(
        name=name, capabilities=["setup", "panel", "sidebar"],
        setup=lambda context: calls.append((name, "setup", context)),
        render_panel=lambda context: calls.append((name, "panel", context)),
        render_sidebar=lambda context: calls.append((name, "sidebar", context)),
    )


def test_plugin_removal_stops_callbacks_and_removes_source_without_affecting_other_entries():
    calls = []
    registry = PluginRegistry()
    removed = _recording_plugin("removed", calls)
    retained = _recording_plugin("retained", calls)
    source = PluginSourceRecord("removed", "entry_point", "example:removed", True)
    registry.register(removed, source=source)
    registry.register(retained)
    assert registry.initialize("before") == []
    assert registry.unregister("removed") is removed
    assert registry.all() == [retained]
    assert [item["name"] for item in registry.describe()] == ["retained"]
    assert [item["plugin_name"] for item in registry.describe_sources()] == ["retained"]
    calls.clear()
    assert registry.initialize("after") == []
    assert registry.render_panels("after") == []
    assert registry.render_sidebar("after") == []
    assert calls == [("retained", "panel", "after"), ("retained", "sidebar", "after")]


@pytest.mark.parametrize("reuse_same_object", [True, False])
def test_plugin_reregistration_initializes_fresh_once_and_replaces_old_source(reuse_same_object):
    calls = []
    registry = PluginRegistry()
    plugin = _recording_plugin("replaceable", calls)
    registry.register(
        plugin, source=PluginSourceRecord("replaceable", "entry_point", "example:old", True),
    )
    assert registry.render_panels("first") == []
    assert registry.unregister("replaceable") is plugin
    replacement = plugin if reuse_same_object else _recording_plugin("replaceable", calls)
    assert registry.register(replacement) is replacement
    # Explicitly skipping initialization must not inherit the old registration.
    assert registry.render_panels("uninitialized", initialize_plugins=False) == []
    assert registry.render_sidebar("uninitialized", initialize_plugins=False) == []
    assert registry.initialize("second") == []
    assert registry.initialize("second") == []
    assert registry.render_panels("second") == []
    assert registry.render_sidebar("second") == []
    assert calls == [
        ("replaceable", "setup", "first"), ("replaceable", "panel", "first"),
        ("replaceable", "setup", "second"), ("replaceable", "panel", "second"),
        ("replaceable", "sidebar", "second"),
    ]
    assert registry.describe_sources()[0]["source_type"] == "manual"
    assert registry.describe_sources()[0]["source_ref"] == "manual_registration"


def test_unknown_plugin_removal_is_atomic_and_does_not_restart_setup():
    calls = []
    registry = PluginRegistry()
    plugin = registry.register(_recording_plugin("kept", calls))
    assert registry.initialize("first") == []
    before = deepcopy(registry.describe())
    sources = deepcopy(registry.describe_sources())
    errors = registry.discovery_errors()
    with pytest.raises(KeyError, match="missing"):
        registry.unregister("missing")
    assert registry.all() == [plugin]
    assert registry.describe() == before
    assert registry.describe_sources() == sources
    assert registry.discovery_errors() == errors
    assert registry.initialize("second") == []
    assert calls == [("kept", "setup", "first")]


def test_shared_plugin_object_is_initialized_independently_and_removal_is_local():
    calls = []
    plugin = _recording_plugin("shared", calls)
    first = PluginRegistry()
    second = PluginRegistry()
    assert first.register(plugin) is plugin
    assert second.register(plugin) is plugin
    assert first.initialize("A") == []
    assert second.render_panels("B", initialize_plugins=False) == []
    assert second.initialize("B") == []
    assert first.unregister("shared") is plugin
    assert second.initialize("B") == []
    assert second.render_panels("B") == []
    assert first.register(plugin) is plugin
    assert first.initialize("A again") == []
    assert second.initialize("B") == []
    assert second.render_sidebar("B") == []
    assert calls == [
        ("shared", "setup", "A"), ("shared", "setup", "B"),
        ("shared", "panel", "B"), ("shared", "setup", "A again"),
        ("shared", "sidebar", "B"),
    ]


def test_plugin_removal_preserves_prior_setup_effects():
    registry = PluginRegistry()
    context = {"saved_records": ["existing"]}
    plugin = DashboardPlugin(
        name="setup-effect",
        setup=lambda state: state["saved_records"].append("provisioned"),
    )
    registry.register(plugin)
    assert registry.initialize(context) == []
    registry.unregister("setup-effect")
    assert context == {"saved_records": ["existing", "provisioned"]}
    assert registry.initialize(context) == []
    assert context == {"saved_records": ["existing", "provisioned"]}


@pytest.mark.parametrize("initialize_plugins", [True, False])
def test_plugin_removed_during_dispatch_has_no_later_callback(initialize_plugins):
    calls = []
    registry = PluginRegistry()
    removed = _recording_plugin("z-removed", calls)
    registry.register(DashboardPlugin(
        name="a-remover",
        render_panel=lambda _context: registry.unregister("z-removed"),
    ))
    registry.register(removed)
    if not initialize_plugins:
        assert registry.initialize("before") == []
        calls.clear()
    assert registry.render_panels("after", initialize_plugins=initialize_plugins) == []
    assert calls == []
    assert [plugin.name for plugin in registry.all()] == ["a-remover"]


def test_plugin_removed_during_setup_does_not_render_or_mark_registration_initialized():
    calls = []
    registry = PluginRegistry()
    plugin = DashboardPlugin(
        name="self-remover",
        setup=lambda _context: registry.unregister("self-remover"),
        render_panel=lambda _context: calls.append("rendered"),
    )
    registry.register(plugin)
    assert registry.render_panels({}) == []
    assert calls == []
    assert registry.all() == []
    # A new registration receives setup even if the old setup removed itself.
    plugin.setup = lambda _context: calls.append("new setup")
    registry.register(plugin)
    assert registry.render_panels({}) == []
    assert calls == ["new setup", "rendered"]


def test_reregistration_inside_setup_does_not_inherit_old_setup_completion():
    calls = []
    registry = PluginRegistry()
    plugin = DashboardPlugin(
        name="self-replacing", render_panel=lambda _context: calls.append("panel"),
    )

    def replace_registration(_context):
        calls.append("original setup")
        registry.unregister(plugin.name)
        plugin.setup = lambda _context: calls.append("replacement setup")
        registry.register(plugin)

    plugin.setup = replace_registration
    registry.register(plugin)
    assert registry.render_panels({}) == []
    assert calls == ["original setup"]
    assert registry.render_panels({}) == []
    assert registry.render_panels({}) == []
    assert calls == ["original setup", "replacement setup", "panel", "panel"]
