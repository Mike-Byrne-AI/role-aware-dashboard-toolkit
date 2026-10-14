"""Configuration mistakes lead to installed, version-matched help."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import ControlRegistry, DashboardConfig, DashboardSections, __version__
from role_aware_dashboard_toolkit.appearance import build_streamlit_theme_toml, validate_dashboard_appearance
from role_aware_dashboard_toolkit.guidance import read_guide
from role_aware_dashboard_toolkit.sections import section_visible


def assert_guided(exc, code, topic):
    record = exc.diagnostic
    assert record["code"] == code
    assert record["guide_topic"] == topic
    assert record["toolkit_version"] == __version__
    assert record["operation"] and record["effect"]
    assert record["guide_command"] in str(exc)
    assert read_guide(topic)["content"]


@pytest.mark.parametrize("construct,exception,code,topic", [
    (lambda: DashboardConfig(auth_mode="demo", card_background_color="secret-value /private/token"), ValueError,
     "RADT-APPEARANCE", "appearance"),
    (lambda: DashboardConfig(auth_mode="demo", group_background_colors=[]), TypeError,
     "RADT-APPEARANCE", "appearance"),
    (lambda: build_streamlit_theme_toml(base="invalid"), ValueError,
     "RADT-APPEARANCE", "appearance"),
    (lambda: DashboardSections(profiles="False"), TypeError,
     "RADT-SECTIONS", "sections"),
    (lambda: section_visible(SimpleNamespace(), "missing"), ValueError,
     "RADT-SECTIONS", "sections"),
    (lambda: DashboardConfig(auth_mode="demo", sections={}), TypeError,
     "RADT-SECTIONS", "sections"),
])
def test_configuration_exception_keeps_base_type_and_points_to_real_guide(construct, exception, code, topic):
    with pytest.raises(exception) as caught:
        construct()
    assert type(caught.value) is exception
    assert_guided(caught.value, code, topic)
    assert "secret-value" not in str(caught.value)
    assert "/private/token" not in str(caught.value)


@pytest.mark.parametrize("options", [
    {"kind": "secret-value"},
    {"kind": "number", "min_value": 9, "max_value": 2},
    {"kind": "number", "step": 0},
])
def test_bad_definition_does_not_mutate_registry(options):
    registry = ControlRegistry()
    with pytest.raises(ValueError) as caught:
        registry.register("Target", key="target", **options)
    assert registry.all() == []
    assert_guided(caught.value, "RADT-CONTROL-DEFINITION", "controls")
    assert "secret-value" not in str(caught.value)


def test_duplicate_definition_keeps_original_definition():
    registry = ControlRegistry()
    original = registry.register("Target", kind="number", key="target", default=8)
    with pytest.raises(KeyError) as caught:
        registry.register("Replacement", kind="number", key="target", default=20)
    assert registry.get("target") is original
    assert original.default == 8
    assert_guided(caught.value, "RADT-CONTROL-DEFINITION", "controls")


def test_unknown_styled_group_fails_with_guidance_before_render():
    registry = ControlRegistry()
    registry.register("Target", kind="number", key="target", group="Plan")
    config = DashboardConfig(auth_mode="demo", registry=registry, group_background_colors={"Unknown": "#FFFFFF"})
    with pytest.raises(ValueError) as caught:
        validate_dashboard_appearance(config)
    assert_guided(caught.value, "RADT-APPEARANCE", "appearance")
