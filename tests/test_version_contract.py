import importlib
import sys
import types

from role_aware_dashboard_toolkit import __version__
from role_aware_dashboard_toolkit.api import create_app
from role_aware_dashboard_toolkit.controls import ControlRegistry


def test_visible_version_defaults_stay_aligned(monkeypatch):
    fake_streamlit = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)
    dashboard_mod = importlib.import_module("role_aware_dashboard_toolkit.dashboard")
    config = dashboard_mod.DashboardConfig(auth_mode="demo")
    registry = ControlRegistry()
    app = create_app(registry)
    assert __version__ == config.version
    assert app.version == __version__
