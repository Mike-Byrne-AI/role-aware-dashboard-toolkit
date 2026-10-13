"""Plugin discovery trusts an entry point only from the distribution named for it."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit.plugins import DashboardPlugin, PluginRegistry

PANELS = "role_aware_dashboard_toolkit.panels"


class _Dist:
    def __init__(self, name):
        self.metadata = {"Name": name}
        self.name = name


class _EntryPoint:
    def __init__(self, name, distribution, plugin_name, loads):
        self.name = name
        self.dist = _Dist(distribution) if distribution else None
        self._plugin_name = plugin_name
        self._loads = loads

    def load(self):
        self._loads.append(self._plugin_name)
        return DashboardPlugin(name=self._plugin_name, capabilities=["panel"])


def _install(monkeypatch, entry_points):
    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.plugins._iter_entry_points",
        lambda group: list(entry_points) if group == PANELS else [],
    )


def test_same_named_entry_point_from_another_distribution_is_not_loaded(monkeypatch):
    loads = []
    _install(monkeypatch, [
        _EntryPoint("panel_ep", "evil-panels", "impostor", loads),
        _EntryPoint("panel_ep", "acme-panels", "acme-panel", loads),
    ])
    registry = PluginRegistry()

    loaded = registry.discover(trusted_entry_points=[f"acme-panels:{PANELS}:panel_ep"])

    assert loaded == ["acme-panel"]
    assert loads == ["acme-panel"], "the impostor's code must never be imported"
    (source,) = registry.describe_sources()
    assert source["distribution"] == "acme-panels"
    assert source["source_ref"] == f"{PANELS}:panel_ep"
    assert source["trusted"] is True


def test_distribution_names_compare_in_normalized_form(monkeypatch):
    loads = []
    _install(monkeypatch, [_EntryPoint("panel_ep", "Acme.Panels", "acme-panel", loads)])

    loaded = PluginRegistry().discover(trusted_entry_points=[f"acme_panels:{PANELS}:panel_ep"])

    assert loaded == ["acme-panel"]


@pytest.mark.parametrize("entry", [f"{PANELS}:panel_ep", f"{PANELS}:panel:ep"])
def test_an_entry_without_a_distribution_is_refused_before_loading(monkeypatch, entry):
    loads = []
    _install(monkeypatch, [_EntryPoint("panel_ep", "acme-panels", "acme-panel", loads)])

    with pytest.raises(ValueError, match="distribution:group:name"):
        PluginRegistry().discover(trusted_entry_points=[entry])
    assert loads == []


@pytest.mark.parametrize(
    "entry",
    [f":{PANELS}:panel_ep", "acme-panels::panel_ep", f"acme-panels:{PANELS}:",
     "acme-panels:unknown.group:panel_ep", f"-acme:{PANELS}:panel_ep"],
)
def test_malformed_allowlist_entries_are_refused(monkeypatch, entry):
    _install(monkeypatch, [])

    with pytest.raises(ValueError):
        PluginRegistry().discover(trusted_entry_points=[entry])


def test_entry_point_without_distribution_metadata_needs_allow_untrusted(monkeypatch):
    loads = []
    _install(monkeypatch, [_EntryPoint("panel_ep", None, "orphan", loads)])

    assert PluginRegistry().discover(trusted_entry_points=[f"acme-panels:{PANELS}:panel_ep"]) == []
    assert loads == []
    registry = PluginRegistry()
    assert registry.discover(allow_untrusted=True) == ["orphan"]
    assert registry.describe_sources()[0]["trusted"] is True


def test_unreadable_distribution_metadata_is_not_trusted(monkeypatch):
    class BrokenDist:
        @property
        def metadata(self):
            raise OSError("unreadable METADATA")

        name = "acme-panels"

    loads = []
    entry_point = _EntryPoint("panel_ep", "acme-panels", "acme-panel", loads)
    entry_point.dist = BrokenDist()
    _install(monkeypatch, [entry_point])

    assert PluginRegistry().discover(trusted_entry_points=[f"acme-panels:{PANELS}:panel_ep"]) == []
    assert loads == []


def test_discovery_without_trust_names_the_allowlist_form(monkeypatch):
    _install(monkeypatch, [])

    with pytest.raises(PermissionError, match="distribution:group:name"):
        PluginRegistry().discover()
