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

    with pytest.warns(RuntimeWarning, match=f"skipped {PANELS}:panel_ep"):
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


def test_an_allowlisted_name_from_the_wrong_distribution_is_reported(monkeypatch):
    loads = []
    _install(monkeypatch, [
        _EntryPoint("panel_ep", "evil-panels", "impostor", loads),
        _EntryPoint("other_ep", "evil-panels", "unrelated", loads),
    ])
    registry = PluginRegistry()

    with pytest.warns(RuntimeWarning, match=f"skipped {PANELS}:panel_ep"):
        loaded = registry.discover(trusted_entry_points=[f"acme-panels:{PANELS}:panel_ep"])

    assert loaded == [] and loads == []
    (error,) = registry.discovery_errors()
    assert error.source == f"{PANELS}:panel_ep"
    assert error.stage == "discover"
    assert error.exception_type == "PermissionError"


def test_a_refused_entry_point_is_not_reported_as_a_failed_callback(monkeypatch):
    # Nothing from a refused entry point runs: "A plugin callback failed" and
    # "host effects may be partial" would send the operator looking for one.
    from role_aware_dashboard_toolkit.diagnostics import diagnostic_text

    _install(monkeypatch, [_EntryPoint("panel_ep", "evil-panels", "impostor", [])])
    registry = PluginRegistry()

    with pytest.warns(RuntimeWarning, match="RADT-PLUGIN-TRUST"):
        registry.discover(trusted_entry_points=[f"acme-panels:{PANELS}:panel_ep"])

    (error,) = registry.discovery_errors()
    assert "callback failed" not in str(error)
    assert str(error).endswith(diagnostic_text("RADT-PLUGIN-TRUST"))
    assert error.diagnostic["code"] == "RADT-PLUGIN-TRUST"
    assert "not allowlisted" in error.message


def test_two_distributions_with_an_allowlisted_name_are_both_refused(monkeypatch):
    # A distribution's name is whatever its own METADATA says, so a second
    # installed distribution can claim the allowlisted one's name.
    loads = []
    _install(monkeypatch, [
        _EntryPoint("panel_ep", "acme-panels", "impostor", loads),
        _EntryPoint("panel_ep", "acme-panels", "acme-panel", loads),
    ])
    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.plugins._installed_entry_point_targets",
        lambda: [("acme-panels", PANELS, "panel_ep", "acme_panels:panel"),
                 ("Acme_Panels", PANELS, "panel_ep", "impostor_mod:panel"),
                 ("other", PANELS, "panel_ep", "other:panel")],
    )
    registry = PluginRegistry()

    with pytest.warns(RuntimeWarning, match="RADT-PLUGIN-TRUST"):
        loaded = registry.discover(trusted_entry_points=[f"acme-panels:{PANELS}:panel_ep"])

    assert loaded == [] and loads == []
    errors = registry.discovery_errors()
    assert len(errors) == 2
    assert all("point it at different code" in error.message for error in errors)


def test_a_self_declared_distribution_name_on_disk_is_refused(tmp_path, monkeypatch):
    # The review's p5/spoof.py: a second dist-info whose METADATA declares the
    # allowlisted name loaded marked trusted, with no warning.
    import importlib
    import sys

    site = tmp_path / "site"
    site.mkdir()
    for directory, module, marker in (
        ("good_plugin-1.0.dist-info", "radt_good_mod", "GOOD"),
        ("aaa_evil-1.0.dist-info", "radt_evil_mod", "EVIL"),
    ):
        info = site / directory
        info.mkdir()
        (info / "METADATA").write_text("Metadata-Version: 2.1\nName: good-plugin\nVersion: 1.0\n")
        (info / "entry_points.txt").write_text(f"[{PANELS}]\nstatus = {module}:panel\n")
        (site / f"{module}.py").write_text(
            "raise AssertionError('a refused entry point must not be imported')\n"
        )
    monkeypatch.syspath_prepend(str(site))
    importlib.invalidate_caches()
    registry = PluginRegistry()

    with pytest.warns(RuntimeWarning, match="RADT-PLUGIN-TRUST"):
        loaded = registry.discover(trusted_entry_points=[f"good-plugin:{PANELS}:status"])

    assert loaded == []
    assert registry.describe_sources() == []
    assert "radt_good_mod" not in sys.modules and "radt_evil_mod" not in sys.modules


def _write_distribution(directory, metadata_file, module):
    directory.mkdir()
    (directory / metadata_file).write_text("Metadata-Version: 2.1\nName: good-plugin\nVersion: 1.0\n")
    (directory / "entry_points.txt").write_text(f"[{PANELS}]\nstatus = {module}:panel\n")


def test_an_editable_install_with_its_egg_info_still_loads(tmp_path, monkeypatch):
    # `pip install -e .` with setuptools leaves src/<name>.egg-info on the
    # path its .pth adds, beside the .dist-info in site-packages: two
    # distributions with one name, pointing at the same code.
    import importlib
    import sys

    site, src = tmp_path / "site", tmp_path / "src"
    site.mkdir()
    src.mkdir()
    _write_distribution(site / "good_plugin-1.0.dist-info", "METADATA", "radt_editable_mod")
    _write_distribution(src / "good_plugin.egg-info", "PKG-INFO", "radt_editable_mod")
    (src / "radt_editable_mod.py").write_text(
        "from role_aware_dashboard_toolkit.plugins import DashboardPlugin\n"
        "panel = DashboardPlugin(name='editable-panel', capabilities=['panel'])\n"
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.syspath_prepend(str(src))
    monkeypatch.delitem(sys.modules, "radt_editable_mod", raising=False)
    importlib.invalidate_caches()
    registry = PluginRegistry()

    loaded = registry.discover(trusted_entry_points=[f"good-plugin:{PANELS}:status"])

    assert loaded == ["editable-panel"]
    assert registry.discovery_errors() == []
    assert registry.describe_sources()[0]["trusted"] is True


def test_same_named_distributions_pointing_at_the_same_code_count_as_one(monkeypatch):
    loads = []
    _install(monkeypatch, [_EntryPoint("panel_ep", "acme-panels", "acme-panel", loads)])
    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.plugins._installed_entry_point_targets",
        lambda: [("acme-panels", PANELS, "panel_ep", "acme_panels:panel"),
                 ("Acme_Panels", PANELS, "panel_ep", "acme_panels : panel")],
    )

    assert PluginRegistry().discover(trusted_entry_points=[f"acme-panels:{PANELS}:panel_ep"]) == ["acme-panel"]
