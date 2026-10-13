"""Run from the repository root: python -m streamlit run examples/operator_review/app.py."""
from __future__ import annotations

import streamlit as st

import role_aware_dashboard_toolkit as radt
from examples.operator_review.report import MAX_PACKET_BYTES, render_run_report
from examples.operator_review.workflow import (
    APP_TITLE,
    SIMULATION_NOTICE,
    ReviewSession,
    build_evidence_packet,
    build_roles,
    capture_candidate,
    control_values,
    record_review,
    simulate_metrics,
    start_baseline,
)

RESOURCE_KEY = "_operator_review_session"


def session_resources() -> ReviewSession:
    if RESOURCE_KEY not in st.session_state:
        st.session_state[RESOURCE_KEY] = ReviewSession()
    return st.session_state[RESOURCE_KEY]


def build_dashboard_config(session: ReviewSession) -> radt.DashboardConfig:
    return radt.DashboardConfig(
        auth_mode="demo",
        title=APP_TITLE, subtitle="Capture a baseline, compare a candidate, and hand off a human decision.",
        icon="◈", registry=session.registry, custom_roles=build_roles(), audit=session.audit,
        profile_store=session.profiles, run_store=session.runs, team_store=session.team,
        layout="columns", columns_per_row=2,
        sections=radt.DashboardSections(
            runbook=False, audit_writer=False, audit_log=False,
            observability=False, plugin_details=False,
        ),
    )


def _allowed(ctx: radt.SecurityContext, *permissions: str) -> bool:
    return all(radt.can_write(ctx, permission) for permission in permissions)


def render_comparison(run: dict) -> None:
    comparison = radt.compare_checkpoints(run["checkpoints"][0], run["checkpoints"][-1], include_telemetry=True)
    telemetry = comparison["telemetry_comparison"]
    st.table([
        {"Metric": name, "Baseline": item["from"], "Candidate": item["to"],
         "Change": item["delta"], "Unit": item["to_unit"], "Status": item["status"]}
        for name, item in telemetry["metrics"].items()
    ])
    st.caption(f"Recorded samples (UTC): {telemetry['left_sample_ts']} → {telemetry['right_sample_ts']}")
    with st.expander("Changed settings"):
        st.table([
            {"Setting": key, "Baseline": str(item["from"]), "Candidate": str(item["to"])}
            for key, item in comparison["control_diff"].items()
        ])


def render_workflow(session: ReviewSession, ctx: radt.SecurityContext) -> None:
    if not radt.has_perm(ctx, "can_view_metrics"):
        return
    st.info(SIMULATION_NOTICE)
    st.caption("Session-local exercise. The sidebar role selector and typed reviewer name are demonstrations, not authenticated identity.")
    preview = simulate_metrics(control_values(session, st.session_state))
    for column, (label, value, unit) in zip(st.columns(3), [
        ("Simulated quality", preview["quality_score"], "/ 100"),
        ("Simulated latency", preview["latency_ms"], "ms"),
        ("Simulated cost / 100 requests", preview["cost_per_100_requests"], "USD"),
    ], strict=True):
        column.metric(label, f"{value:g} {unit}")

    st.subheader("1. Save a baseline")
    st.write("Choose the starting settings above, then save a profile and the first recorded snapshot of this simulation.")
    run = session.current_run()
    if st.button("Save baseline and start run", key="review_start", disabled=(
        bool(run and run["status"] == "active")
        or not _allowed(ctx, "can_view_metrics", "can_manage_runs", "can_save_profiles")
    )):
        try:
            start_baseline(session, st.session_state, ctx)
        except (PermissionError, ValueError) as exc:
            st.warning(str(exc))
        else:
            for key in ("review_actor", "review_reason", "review_decision"):
                st.session_state.pop(key, None)
            st.rerun()
    run = session.current_run()
    if not run:
        st.caption("Use Admin or Operator to start; Viewer can inspect but cannot record changes.")
        return
    st.caption(f"Saved profile: {run['source_profile_id']} | Run: {run['run_id']}")

    st.subheader("2. Capture and compare a candidate")
    st.write("Change a setting above, then capture a candidate. The comparison uses recorded snapshots, even if live settings change later.")
    if st.button("Capture candidate for review", key="review_capture", disabled=(
        run["status"] != "active" or len(run["checkpoints"]) != 1
        or not _allowed(ctx, "can_view_metrics", "can_manage_runs", "can_edit_controls", "can_assign_reviews")
    )):
        try:
            capture_candidate(session, st.session_state, ctx)
        except (PermissionError, ValueError) as exc:
            st.warning(str(exc))
        else:
            st.rerun()
    run = session.current_run()
    if len(run["checkpoints"]) < 2:
        return
    render_comparison(run)

    if not radt.has_perm(ctx, "can_view_team_ops"):
        st.caption("The current role can inspect the comparison but cannot view review records.")
        return

    st.subheader("3. Record a human decision")
    st.write("Switch to Approver to review the captured candidate. Approval records a decision; it does not deploy settings or execute actions.")
    can_review = run["status"] == "active" and _allowed(
        ctx, "can_view_metrics", "can_view_team_ops", "can_signoff_runs", "can_approve_changes",
    )
    actor = st.text_input("Demo reviewer name", key="review_actor", disabled=not can_review)
    decision = st.selectbox("Decision", ["approved", "changes_requested", "rejected"], key="review_decision", disabled=not can_review)
    reason = st.text_area("Reason and handoff notes", key="review_reason", disabled=not can_review)
    if st.button("Save decision and finish run", key="review_signoff", disabled=not can_review):
        try:
            record_review(session, ctx, decision=decision, reason=reason, actor=actor)
        except (PermissionError, ValueError) as exc:
            st.warning(str(exc))
        else:
            st.rerun()
    run = session.current_run()
    if run["status"] == "completed":
        st.success(f"Review recorded: {run['outcome']}. Start another baseline to try a new candidate.")
    else:
        st.caption("Awaiting an explicit review. Controls Writable must be on to save a decision.")

    st.subheader("4. Export evidence for the next reviewer")
    if not all(radt.has_perm(ctx, permission) for permission in ("can_view_team_ops", "can_export_packets")):
        st.caption("The current role can view the comparison but cannot export review evidence.")
        return
    packet = build_evidence_packet(session, ctx)
    st.caption("The export contains recorded checkpoints and review notes. An unfinished review remains unapproved.")
    st.download_button("Download run packet (JSON)", radt.export_packet_json(packet),
                       "operator-review.json", "application/json", key="review_download_json")
    st.download_button("Download readable report (HTML)", render_run_report(packet),
                       "operator-review.html", "text/html", key="review_download_html")


def render_packet_reader(ctx: radt.SecurityContext) -> None:
    if not all(radt.has_perm(ctx, permission) for permission in (
        "can_view_metrics", "can_view_team_ops", "can_export_packets",
    )):
        return
    with st.expander("Read a saved run packet"):
        st.caption("Read-only: importing evidence never restores controls, grants permissions, or saves records.")
        uploaded = st.file_uploader("Run packet JSON (up to 2 MiB)", type=["json"], key="review_upload")
        if uploaded is None:
            return
        try:
            raw = uploaded.getvalue()
            if len(raw) > MAX_PACKET_BYTES:
                raise ValueError("Choose a run packet no larger than 2 MiB.")
            packet = radt.load_packet_json(raw.decode("utf-8"))
            report = render_run_report(packet)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            st.error(f"Cannot read this run packet: {exc}")
            return
        run = packet["payload"]
        st.write({"Run": run["run_id"], "Status": run["status"], "Outcome": run.get("outcome", "")})
        st.download_button("Download imported report", report, "imported-review.html", "text/html", key="review_imported_html")


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="◈", layout="wide")
    session = session_resources()
    ctx = radt.render(build_dashboard_config(session))
    render_workflow(session, ctx)
    render_packet_reader(ctx)


if __name__ == "__main__":
    main()
