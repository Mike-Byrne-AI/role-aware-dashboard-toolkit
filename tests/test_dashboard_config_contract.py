"""DashboardConfig defaults that hosts see without configuring them."""
from __future__ import annotations

from streamlit.testing.v1 import AppTest


def _render_minimal_dashboard():
    import role_aware_dashboard_toolkit as radt

    registry = radt.ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8,
                      min_value=1, max_value=40, step=1)
    radt.render(radt.DashboardConfig(
        title="Service controls", registry=registry, auth_mode="demo",
    ))


def test_default_icon_does_not_prefix_the_title():
    import role_aware_dashboard_toolkit as radt

    assert radt.DashboardConfig(auth_mode="demo").icon == ""

    app = AppTest.from_function(_render_minimal_dashboard).run()

    assert not app.exception
    assert [title.value for title in app.title] == ["Service controls"]
    assert "Control Panel" not in [header.value for header in app.sidebar.header]
