import pytest

from role_aware_dashboard_toolkit import DashboardPlugin, PluginRegistry
from role_aware_dashboard_toolkit.plugins import PluginErrorRecord
from role_aware_dashboard_toolkit.diagnostics import diagnostic_text


def test_plugin_metadata_and_describe():
    registry = PluginRegistry()
    registry.register(DashboardPlugin(name="health", version="1.2.0", description="health plugin", capabilities=["panel"]))
    described = registry.describe()
    assert described[0]["name"] == "health"
    assert described[0]["version"] == "1.2.0"


def test_plugin_invalid_capability_rejected():
    registry = PluginRegistry()
    with pytest.raises(ValueError):
        registry.register(DashboardPlugin(name="broken", capabilities=["remote-install"]))


def test_plugin_setup_runs_once():
    calls = []
    registry = PluginRegistry()
    registry.register(
        DashboardPlugin(
            name="setup-test",
            capabilities=["setup", "panel"],
            setup=lambda context: calls.append("setup"),
            render_panel=lambda context: calls.append("render"),
        )
    )
    registry.render_panels({})
    registry.render_panels({})
    assert calls.count("setup") == 1
    assert calls.count("render") == 2


def test_plugin_render_errors_are_structured_records():
    registry = PluginRegistry()

    def boom(_context):
        raise RuntimeError("bad plugin")

    registry.register(DashboardPlugin(name="bad", render_panel=boom))
    errors = registry.render_panels({})

    assert len(errors) == 1
    error = errors[0]
    assert isinstance(error, PluginErrorRecord)
    assert str(error) == "bad (RuntimeError): " + diagnostic_text("RADT-PLUGIN")
    assert error.to_dict() == {
        "plugin_name": "bad",
        "stage": "render_panel",
        "source": "bad.render_panel",
        "exception_type": "RuntimeError",
        "message": "Plugin operation failed (RuntimeError).",
        "diagnostic": error.diagnostic,
    }


def test_plugin_error_records_redact_local_paths(tmp_path):
    registry = PluginRegistry()
    secret_path = tmp_path / "private" / "token.txt"

    def boom(_context):
        raise RuntimeError(f"failed reading {secret_path}")

    registry.register(DashboardPlugin(name="path-bad", render_panel=boom))
    errors = registry.render_panels({})

    assert len(errors) == 1
    assert errors[0].message == "Plugin operation failed (RuntimeError)."
    assert str(secret_path) not in errors[0].message


def test_plugin_setup_errors_are_structured_records():
    registry = PluginRegistry()

    def boom(_context):
        raise ValueError("setup failed")

    registry.register(DashboardPlugin(name="setup-bad", capabilities=["setup"], setup=boom))
    errors = registry.initialize({})

    assert len(errors) == 1
    assert errors[0].stage == "setup"
    assert errors[0].source == "setup-bad.setup"
    assert errors[0].exception_type == "ValueError"
    assert errors[0].message == "Plugin operation failed (ValueError)."


def test_plugin_setup_failure_is_not_marked_initialized():
    calls = []
    registry = PluginRegistry()

    def boom(_context):
        calls.append("setup")
        raise RuntimeError("setup still failing")

    registry.register(DashboardPlugin(name="retry-setup", capabilities=["setup"], setup=boom))

    first_errors = registry.initialize({})
    second_errors = registry.initialize({})

    assert calls == ["setup", "setup"]
    assert [error.stage for error in first_errors] == ["setup"]
    assert [error.stage for error in second_errors] == ["setup"]
    assert second_errors[0].message == "Plugin operation failed (RuntimeError)."


def test_explicit_initialization_can_own_failed_setup_attempt():
    calls = []
    registry = PluginRegistry()

    def boom(_context):
        calls.append("setup")
        raise RuntimeError("setup failed")

    registry.register(
        DashboardPlugin(
            name="setup-once",
            capabilities=["setup", "sidebar", "panel"],
            setup=boom,
            render_sidebar=lambda _context: calls.append("sidebar"),
            render_panel=lambda _context: calls.append("panel"),
        )
    )

    setup_errors = registry.initialize({})
    sidebar_errors = registry.render_sidebar({}, initialize_plugins=False)
    panel_errors = registry.render_panels({}, initialize_plugins=False)

    assert calls == ["setup"]
    assert [error.stage for error in setup_errors] == ["setup"]
    assert sidebar_errors == []
    assert panel_errors == []


def test_plugin_render_skips_hook_when_setup_fails():
    calls = []
    registry = PluginRegistry()

    def boom(_context):
        calls.append("setup")
        raise RuntimeError("setup failed")

    registry.register(
        DashboardPlugin(
            name="setup-gated",
            capabilities=["setup", "panel"],
            setup=boom,
            render_panel=lambda _context: calls.append("render"),
        )
    )

    errors = registry.render_panels({})

    assert calls == ["setup"]
    assert len(errors) == 1
    assert errors[0].stage == "setup"
    assert errors[0].source == "setup-gated.setup"


def test_plugin_discovery_requires_explicit_trust_opt_in(monkeypatch):
    class EntryPoint:
        name = "panel_ep"

        def load(self):
            return DashboardPlugin(name="from-entry-point", capabilities=["panel"])

    monkeypatch.setattr("role_aware_dashboard_toolkit.plugins._iter_entry_points", lambda _group: [EntryPoint()])
    registry = PluginRegistry()

    with pytest.raises(PermissionError):
        registry.discover()


def test_plugin_discovery_uses_allowlist_and_records_source_metadata(monkeypatch):
    class Dist:
        metadata = {"Name": "role_aware_dashboard_toolkit-plugin-fixture"}

    class EntryPoint:
        name = "panel_ep"
        dist = Dist()

        def load(self):
            return DashboardPlugin(name="from-entry-point", capabilities=["panel"])

    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.plugins._iter_entry_points",
        lambda group: [EntryPoint()] if group == "role_aware_dashboard_toolkit.panels" else [],
    )
    registry = PluginRegistry()
    loaded = registry.discover(trusted_entry_points=["role_aware_dashboard_toolkit.panels:panel_ep"])

    assert loaded == ["from-entry-point"]
    described = registry.describe()[0]
    assert described["source"]["source_type"] == "entry_point"
    assert described["source"]["source_ref"] == "role_aware_dashboard_toolkit.panels:panel_ep"
    assert described["source"]["trusted"] is True
    assert described["source"]["distribution"] == "role_aware_dashboard_toolkit-plugin-fixture"
    assert registry.describe_sources()[0]["plugin_name"] == "from-entry-point"


def test_plugin_discovery_skips_broken_entry_points_and_records_warning(monkeypatch):
    class BrokenEntryPoint:
        name = "broken_ep"

        def load(self):
            raise RuntimeError("entry point exploded")

    class GoodEntryPoint:
        name = "good_ep"

        def load(self):
            return DashboardPlugin(name="good-plugin", capabilities=["panel"])

    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.plugins._iter_entry_points",
        lambda group: [BrokenEntryPoint(), GoodEntryPoint()] if group == "role_aware_dashboard_toolkit.panels" else [],
    )
    registry = PluginRegistry()

    with pytest.warns(RuntimeWarning, match="Role-Aware Dashboard Toolkit plugin discovery skipped role_aware_dashboard_toolkit.panels:broken_ep"):
        loaded = registry.discover(
            trusted_entry_points=["role_aware_dashboard_toolkit.panels:broken_ep", "role_aware_dashboard_toolkit.panels:good_ep"]
        )

    assert loaded == ["good-plugin"]
    errors = registry.discovery_errors()
    assert len(errors) == 1
    assert errors[0].plugin_name == "broken_ep"
    assert errors[0].stage == "discover"
    assert errors[0].source == "role_aware_dashboard_toolkit.panels:broken_ep"
    assert errors[0].exception_type == "RuntimeError"
    assert errors[0].message == "Plugin operation failed (RuntimeError)."


def test_plugin_discovery_errors_redact_local_paths(monkeypatch, tmp_path):
    secret_path = tmp_path / "plugin.py"

    class BrokenEntryPoint:
        name = "broken_ep"

        def load(self):
            raise RuntimeError(f"cannot import {secret_path}")

    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.plugins._iter_entry_points",
        lambda group: [BrokenEntryPoint()] if group == "role_aware_dashboard_toolkit.panels" else [],
    )
    registry = PluginRegistry()

    with pytest.warns(RuntimeWarning, match="Role-Aware Dashboard Toolkit plugin discovery skipped role_aware_dashboard_toolkit.panels:broken_ep"):
        loaded = registry.discover(trusted_entry_points=["role_aware_dashboard_toolkit.panels:broken_ep"])

    assert loaded == []
    errors = registry.discovery_errors()
    assert len(errors) == 1
    assert errors[0].message == "Plugin operation failed (RuntimeError)."
    assert str(secret_path) not in errors[0].message
