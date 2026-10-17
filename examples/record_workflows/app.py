"""Local administration-screen recipe with synthetic identities and temporary data."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time

from role_aware_dashboard_toolkit.access import AccessDenied, Identity
from role_aware_dashboard_toolkit.access_store import FreezeConflict

from examples.record_workflows.actions import ActionConflict, ActionDenied, ActionValidation
from examples.record_workflows.service import WorkItems


def resources(state):
    if "_workflow_example" not in state:
        directory = TemporaryDirectory(prefix="record-workflow-ui-")
        service = WorkItems(Path(directory.name) / "example.sqlite3", identity_key=secrets.token_bytes(32))
        identities = {role: Identity("synthetic-workflow-ui", role.lower(), time.time() + 86400)
                      for role in ("Manager", "Operator", "Viewer")}
        for role, identity in identities.items():
            service.provision(identity, [role])
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        items = [service.create_item(label=label, starts_at=(now + timedelta(days=offset)).isoformat())
                 for offset, label in enumerate(("Site inspection", "Equipment check"), 1)]
        state["_workflow_example"] = {"directory": directory, "service": service,
                                      "identities": identities, "items": items}
    return state["_workflow_example"]


def clear_editor(state):
    for key in list(state):
        if key.startswith("wf_edit_"):
            del state[key]
    state.pop("_workflow_snapshot", None)
    # A new widget identity also discards the browser's cached form values.
    # Deleting only the server key can restore an old checked confirmation.
    state["_workflow_editor_epoch"] = state.get("_workflow_editor_epoch", 0) + 1


def main():
    import streamlit as st

    st.set_page_config(page_title="Record workflows", page_icon="📋", layout="centered")
    st.title("Record workflows")
    st.caption("LOCAL DEMO · Synthetic accounts · Temporary records · All times UTC")
    st.write("Edit a schedule, record a status change, and review its history.")
    data = resources(st.session_state)
    service = data["service"]
    role = st.sidebar.selectbox("Demo account", ("Manager", "Operator", "Viewer"))
    st.sidebar.caption("This selector simulates separate accounts. Shared applications supply verified sign-in.")
    if st.session_state.get("_workflow_actor") != role:
        old = st.session_state.pop("_workflow_session", None)
        if old is not None:
            old.close()
        clear_editor(st.session_state)
        st.session_state.pop("_workflow_notice", None)
        st.session_state["_workflow_actor"] = role
        identity = data["identities"][role]
        st.session_state["_workflow_session"] = service.open_session(lambda: identity)
    session = st.session_state["_workflow_session"]
    labels = {item["id"]: item["label"] for item in data["items"]}
    item_id = st.selectbox("Work item", tuple(labels), format_func=labels.get)
    if st.session_state.get("_workflow_item") != item_id:
        clear_editor(st.session_state)
        st.session_state["_workflow_item"] = item_id
    if st.session_state.pop("_workflow_reload", False):
        clear_editor(st.session_state)
    try:
        live = service.read(session, role, item_id)
        freeze = service.freeze_state(session, role)
    except AccessDenied:
        clear_editor(st.session_state)
        st.error("This account no longer has access. Its editor has been cleared.")
        st.stop()
    if role == "Manager":
        if st.sidebar.button("Resume changes" if freeze.frozen else "Pause changes"):
            try:
                service.change_freeze(session, role, not freeze.frozen, freeze.revision)
                st.rerun()
            except (AccessDenied, FreezeConflict):
                st.error("Access or pause state changed. Reload before trying again.")
    writable = role in ("Manager", "Operator") and not freeze.frozen
    if freeze.frozen:
        st.warning("Changes paused. A Manager can resume changes.")
    elif role == "Viewer":
        st.info("Read-only account. Select a work item to view its current state.")
    else:
        st.caption("Editing enabled. The server checks permission again when you save.")
    if "_workflow_snapshot" not in st.session_state:
        st.session_state["_workflow_snapshot"] = live
    snapshot = st.session_state["_workflow_snapshot"]
    editor_epoch = st.session_state.get("_workflow_editor_epoch", 0)
    st.subheader(labels[item_id])
    left, right = st.columns(2)
    left.metric("Status", live["status"].title())
    right.metric("Scheduled time (UTC)", datetime.fromisoformat(live["starts_at"]).strftime("%b %d, %H:%M"))
    if live["revision"] != snapshot["revision"]:
        st.warning("This item changed while you were editing. Your draft is kept; reload to use the latest record.")
    if st.button("Reload latest record"):
        st.session_state["_workflow_reload"] = True
        st.rerun()
    notice = st.session_state.pop("_workflow_notice", None)
    if notice:
        st.success(notice)

    def show_failure(error):
        if isinstance(error, (AccessDenied, ActionDenied)):
            st.error("Your current account cannot make this change. No change was saved.")
        elif isinstance(error, ActionConflict):
            st.error("This record changed. Your draft is kept; reload before trying again.")
        else:
            st.error(str(error))

    starts = datetime.fromisoformat(snapshot["starts_at"])
    st.subheader("Reschedule")
    with st.form("workflow_schedule"):
        can_reschedule = writable and snapshot["status"] == "scheduled"
        date = st.date_input("New date (UTC)", value=starts.date(), key=f"wf_edit_date_{editor_epoch}", disabled=not can_reschedule)
        clock = st.time_input("New time (UTC)", value=starts.time(), key=f"wf_edit_time_{editor_epoch}", disabled=not can_reschedule)
        reason = st.text_input("Reason for rescheduling", max_chars=500, key=f"wf_edit_schedule_reason_{editor_epoch}", disabled=not can_reschedule)
        submitted = st.form_submit_button("Save schedule", disabled=not can_reschedule)
    if submitted:
        try:
            if not reason.strip():
                raise ActionValidation("Explain why the schedule is changing.")
            result = service.reschedule(session, role, item_id, expected_revision=snapshot["revision"],
                                        starts_at=datetime.combine(date, clock, timezone.utc).isoformat(), reason=reason)
            st.session_state["_workflow_notice"] = "Schedule saved with change history." if result.changed else "The schedule is unchanged."
            st.session_state["_workflow_reload"] = True
            st.rerun()
        except (ActionValidation, ActionConflict, ActionDenied, AccessDenied) as error:
            show_failure(error)

    st.subheader("Change status")
    with st.form("workflow_status"):
        choices = ("completed", "cancelled") if snapshot["status"] == "scheduled" else ("scheduled",)
        status = st.selectbox("New status", choices, format_func=lambda value: "Reopen as scheduled" if value == "scheduled" else value.title(), key=f"wf_edit_status_{editor_epoch}", disabled=not writable)
        status_reason = st.text_input("Reason for status change", max_chars=500, key=f"wf_edit_status_reason_{editor_epoch}", disabled=not writable)
        confirmed = st.checkbox("I reviewed this status change", key=f"wf_edit_confirm_{editor_epoch}", disabled=not writable)
        changed_status = st.form_submit_button("Apply status", disabled=not writable)
    if changed_status:
        try:
            if not confirmed or not status_reason.strip():
                raise ActionValidation("Review the status change and enter a reason.")
            service.change_status(session, role, item_id, expected_revision=snapshot["revision"], status=status, reason=status_reason)
            st.session_state["_workflow_notice"] = "Status saved with change history."
            st.session_state["_workflow_reload"] = True
            st.rerun()
        except (ActionValidation, ActionConflict, ActionDenied, AccessDenied) as error:
            show_failure(error)
    if role == "Manager":
        st.subheader("Change history")
        try:
            events = [event for event in service.audit_events(session, role) if event["item_id"] == item_id]
            if not events:
                st.caption("No changes recorded for this work item.")
            for event in reversed(events):
                with st.container(border=True):
                    st.text("Schedule changed" if event["action"] == "rescheduled" else "Status changed")
                    for field in ("starts_at", "status"):
                        if event["before"][field] != event["after"][field]:
                            st.text(f"{'Time (UTC)' if field == 'starts_at' else 'Status'}: {event['before'][field]} → {event['after'][field]}")
                    st.text(f"Reason: {event['reason'] or 'No reason supplied'}")
        except AccessDenied:
            st.error("Change history is unavailable to this account.")
    st.caption("The reference service uses SQLite transactions. This local screen creates a temporary database per browser session; copy the recipe and supply your own identity, storage and business rules for a shared app.")


if __name__ == "__main__":
    main()
