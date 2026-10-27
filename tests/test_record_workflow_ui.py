"""Exercise the editable record recipe through real Streamlit reruns."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

from streamlit.testing.v1 import AppTest


APP = Path(__file__).resolve().parents[1] / "examples/record_workflows/app.py"
# Match the other example UI tests' bound for the initial Streamlit render.
INITIAL_RENDER_TIMEOUT = 15


def control(elements, label):
    return next(element for element in elements if element.label == label)


def test_schedule_and_confirmed_status_changes_create_readable_history():
    app = AppTest.from_file(str(APP)).run(timeout=INITIAL_RENDER_TIMEOUT)
    assert not app.exception
    assert control(app.button, "Save schedule").disabled
    control(app.button, "Resume changes").click().run()
    control(app.date_input, "New date (UTC)").set_value(datetime.now(timezone.utc).date() + timedelta(days=5))
    control(app.text_input, "Reason for rescheduling").set_value("Customer requested next week")
    control(app.button, "Save schedule").click().run()
    assert not app.exception
    assert any("Schedule saved" in element.value for element in app.success)
    control(app.text_input, "Reason for status change").set_value("Inspection finished")
    control(app.button, "Apply status").click().run()
    assert any("Review the status change" in element.value for element in app.error)
    control(app.checkbox, "I reviewed this status change").check()
    control(app.button, "Apply status").click().run()
    assert not app.exception
    assert app.metric[0].value == "Completed"
    assert any("Reason: Inspection finished" in element.value for element in app.text)
    assert not control(app.checkbox, "I reviewed this status change").value
    assert control(app.text_input, "Reason for status change").value == ""


def test_stale_editor_cannot_overwrite_another_change_and_keeps_its_draft():
    app = AppTest.from_file(str(APP)).run(timeout=INITIAL_RENDER_TIMEOUT)
    control(app.button, "Resume changes").click().run()
    data = app.session_state["_workflow_example"]
    session = app.session_state["_workflow_session"]
    item_id = app.session_state["_workflow_item"]
    before = app.session_state["_workflow_snapshot"]
    newer_date = (datetime.now(timezone.utc) + timedelta(days=8)).isoformat()
    result = data["service"].reschedule(session, "Manager", item_id,
                                        expected_revision=before["revision"], starts_at=newer_date,
                                        reason="Change from another window")
    control(app.text_input, "Reason for rescheduling").set_value("Keep my unfinished explanation")
    control(app.button, "Save schedule").click().run()
    assert not app.exception
    assert any("record changed" in element.value for element in app.error)
    assert control(app.text_input, "Reason for rescheduling").value == "Keep my unfinished explanation"
    assert data["service"].read(session, "Manager", item_id) == result.after
    assert len(data["service"].audit_events(session, "Manager")) == 1
    control(app.button, "Reload latest record").click().run()
    assert app.session_state["_workflow_snapshot"]["revision"] == result.after["revision"]


def test_account_switch_clears_drafts_and_enforces_read_only_and_freeze():
    app = AppTest.from_file(str(APP)).run(timeout=INITIAL_RENDER_TIMEOUT)
    control(app.button, "Resume changes").click().run()
    control(app.text_input, "Reason for rescheduling").set_value("Private manager draft").run()
    previous = app.session_state["_workflow_session"]
    control(app.selectbox, "Demo account").select("Viewer").run()
    assert previous._closed
    assert control(app.text_input, "Reason for rescheduling").value == ""
    assert control(app.button, "Save schedule").disabled
    assert control(app.button, "Apply status").disabled
    assert not any(element.value == "Change history" for element in app.subheader)
    control(app.selectbox, "Demo account").select("Manager").run()
    control(app.button, "Pause changes").click().run()
    control(app.selectbox, "Demo account").select("Operator").run()
    assert control(app.button, "Save schedule").disabled
    assert any("Changes paused" in element.value for element in app.warning)
    assert not app.exception
