"""DashboardConfig defaults that hosts see without configuring them."""
from __future__ import annotations

def _render_minimal_dashboard():
    import role_aware_dashboard_toolkit as radt

    registry = radt.ControlRegistry()
    registry.register("Workers", kind="number", key="workers", default=8,
                      min_value=1, max_value=40, step=1)
    radt.render(radt.DashboardConfig(
        title="Service controls", registry=registry, auth_mode="demo",
    ))


def test_default_icon_does_not_prefix_the_title():
    try:
        from streamlit.testing.v1 import AppTest
    except ModuleNotFoundError as error:
        if error.name != "streamlit":
            raise
        import pytest
        pytest.skip("Streamlit UI requires the optional workbench extra on Python 3.11+.")
    import role_aware_dashboard_toolkit as radt

    assert radt.DashboardConfig(auth_mode="demo").icon == ""

    app = AppTest.from_function(_render_minimal_dashboard).run()

    assert not app.exception
    assert [title.value for title in app.title] == ["Service controls"]
    assert "Control Panel" not in [header.value for header in app.sidebar.header]


def test_omitting_auth_mode_no_longer_selects_the_demo():
    import pytest

    import role_aware_dashboard_toolkit as radt

    # access=None models a policy built from a missing environment variable.
    for kwargs in ({}, {"access": None}, {"auth_hook": None},
                   {"registry": radt.ControlRegistry(), "custom_roles": {}}):
        with pytest.raises(ValueError, match="auth_mode='demo'") as raised:
            radt.DashboardConfig(**kwargs)
        assert "auth_mode='authenticated'" in str(raised.value)
        assert raised.value.diagnostic["code"] == "RADT-AUTH"


def test_explicit_or_unambiguous_modes_still_construct():
    from role_aware_dashboard_toolkit import DashboardConfig
    from role_aware_dashboard_toolkit.access import AccessPolicy
    from role_aware_dashboard_toolkit.access_store import InMemoryAccessStore

    policy = AccessPolicy(lambda: None, InMemoryAccessStore(), b"synthetic-config-key-0123456789ab")

    assert DashboardConfig(auth_mode="demo").auth_mode == "demo"
    assert DashboardConfig(auth_hook=lambda: "Viewer").auth_mode == "host"
    assert DashboardConfig(access=policy).auth_mode == "authenticated"
    assert DashboardConfig(auth_mode="authenticated", access=policy).auth_mode == "authenticated"
