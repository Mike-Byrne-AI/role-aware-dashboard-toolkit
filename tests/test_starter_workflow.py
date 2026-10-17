"""Real starter navigation must retain values, profiles and role boundaries."""
from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest

APP = Path(__file__).resolve().parents[1] / "role_aware_dashboard_toolkit/resources/starter/app.py"


def healthy(app):
    assert not app.exception, [item.message for item in app.exception]
    assert not app.error, [item.value for item in app.error]


def metrics(app):
    return {item.label: item.value for item in app.metric}


def view(app, name):
    app.radio(key="pulse_view").set_value(name).run()
    healthy(app)


def control(app, kind, key):
    return next(item for item in app.get(kind)
                if item.key in (key, "_radt_read_only_control__" + key))


def test_starter_navigation_keeps_plan_and_plain_text_project_name():
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    healthy(app)
    assert app.selectbox(key="_radt_role").value == "Viewer"
    assert app.radio(key="pulse_view").value == "Overview"
    assert metrics(app) == {
        "Planned tasks": "40", "Completed": "24", "Remaining": "16", "Completion rate": "60%",
    }
    assert not any(item.label == "Weekly target" for item in app.number_input)

    app.selectbox(key="_radt_role").select("Admin").run()
    view(app, "Plan")
    name = "[Project](https://example.invalid) ![image](https://example.invalid/image.png)"
    app.number_input(key="weekly_target").set_value(48)
    app.slider(key="completion_percent").set_value(25)
    app.text_input(key="project_name").set_value(name).run()
    view(app, "Overview")
    assert metrics(app) == {
        "Planned tasks": "48", "Completed": "12", "Remaining": "36", "Completion rate": "25%",
    }
    assert name in [item.value for item in app.get("text")]
    view(app, "Progress")
    assert len([*app.get("arrow_vega_lite_chart"), *app.get("vega_lite_chart")]) == 1
    view(app, "Activity")
    assert any(item.label == "Audit Log" for item in app.expander)
    view(app, "Plan")
    assert app.number_input(key="weekly_target").value == 48
    assert app.text_input(key="project_name").value == name


def test_starter_access_explanations_match_live_controls_and_freeze():
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    view(app, "Plan")
    assert "Read-only access" in [item.value for item in app.caption]
    assert control(app, "number_input", "weekly_target").disabled
    app.selectbox(key="_radt_role").select("Planner").run()
    healthy(app)
    assert "Planning access" in [item.value for item in app.caption]
    assert not control(app, "number_input", "weekly_target").disabled
    assert control(app, "toggle", "intake_open").disabled
    app.selectbox(key="_radt_role").select("Admin").run()
    assert "Administrative access" in [item.value for item in app.caption]
    assert not control(app, "toggle", "intake_open").disabled
    app.toggle(key="_radt_writable").set_value(False).run()
    healthy(app)
    assert "Changes paused" in [item.value for item in app.warning]
    for kind, key in (("number_input", "weekly_target"), ("slider", "completion_percent"),
                      ("selectbox", "priority"), ("text_input", "project_name"),
                      ("toggle", "intake_open"), ("color_picker", "chart_color")):
        assert control(app, kind, key).disabled
    view(app, "Overview")
    assert metrics(app)["Planned tasks"] == "40"
    assert "Changes paused" in [item.value for item in app.warning]


def test_profile_restoration_works_while_plan_controls_are_hidden():
    app = AppTest.from_file(str(APP), default_timeout=15).run()
    app.selectbox(key="_radt_role").select("Admin").run()
    view(app, "Plan")
    app.number_input(key="weekly_target").set_value(60).run()
    app.text_input(key="_radt_profile_name").set_value("Baseline").run()
    app.button(key="_radt_profile_save").click().run()
    app.number_input(key="weekly_target").set_value(90).run()
    view(app, "Overview")
    assert metrics(app)["Planned tasks"] == "90"
    app.selectbox(key="_radt_profile_choice").select("Baseline").run()
    app.button(key="_radt_profile_load").click().run()
    healthy(app)
    assert metrics(app)["Planned tasks"] == "60"
    view(app, "Plan")
    assert app.number_input(key="weekly_target").value == 60
