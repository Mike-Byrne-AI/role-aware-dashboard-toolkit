from __future__ import annotations

from typing import Any

from .diagnostics import diagnostic_text

from ._ui_state import queue_replay, stage_replay
from ._record_projection import project_record
from .checkpoints import checkpoint_summary
from .compare import compare_checkpoints, compare_runs
from .ledger import build_run_ledger, ledger_summary
from .packets import build_checkpoint_packet, build_run_packet
from .replay import build_replay_packet_from_checkpoint
from .runs import append_checkpoint, build_run, end_run, run_summary
from .runbook_panels_parts.caseboard import _render_caseboard_panel
from .runbook_panels_parts.decisions import _render_decision_panel
from .runbook_panels_parts.governance import _render_governance_panel
from .runbook_panels_parts.operator_memory import _render_operator_memory_panel, _render_operator_memory_sidebar
from .runbook_panels_parts.shared import (
    _current_approval_state,
    _latest_telemetry,
    _parse_tags,
    _record_actor,
    _record_session,
    _render_table,
    _selected_profile_id,
)
from .runbook_panels_parts.team_ops import _render_team_ops_panel, _render_team_ops_sidebar
from .security import can_mutate, can_write, has_perm
from .sections import section_visible
from .store_diagnostics import StorePathSecurityError
from .validators import validate_record


_RUN_READ_HELP = "Help: python -m role_aware_dashboard_toolkit guide runs"
_RUN_SIDEBAR_DRAFT_KEYS = (
    "_radt_team_comment_body", "_radt_review_assignee", "_radt_review_assignee_role",
    "_radt_review_title", "_radt_handoff_to", "_radt_handoff_role",
    "_radt_operator_note_body", "_radt_operator_note_type", "_radt_incident_severity",
    "_radt_incident_title", "_radt_incident_summary", "_radt_incident_cause",
)


def _read_run_store(store: Any, operation: Any, *args: Any, validate_run: bool = False) -> tuple[Any, bool]:
    """Separate a missing record from a failed read without consuming diagnostics.

    File stores retain their read-error history across successful operations.
    Only errors added by this read indicate that its result is incomplete.
    """
    errors_before = len(getattr(store, "read_errors", ()) or ())
    try:
        result = operation(*args)
        if validate_run:
            if result is not None and (
                not isinstance(result, dict) or not validate_record("run", result)["ok"]
            ):
                return None, True
        elif not isinstance(result, list) or any(not isinstance(item, str) for item in result):
            return None, True
    except (OSError, ValueError, StorePathSecurityError):
        # Store exceptions and diagnostic records can contain paths or secrets.
        # UI messages below never copy those payloads.
        return None, True
    return result, len(getattr(store, "read_errors", ()) or ()) > errors_before


def _warn_run_history_read(st: Any) -> None:
    st.warning(
        "Run history could not be read completely. Unreadable records were skipped; "
        "available runs may still be displayed. Check the run store and retry. "
        + _RUN_READ_HELP
    )



def render_runbook_sidebar(st: Any, config: Any, ctx: Any) -> None:
    store = getattr(config, "run_store", None)
    if not section_visible(config, "runbook") or store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    st.divider()
    st.subheader(getattr(config, "runbook_title", "Runbook"))
    active_run_id = str(st.session_state.get("_radt_active_run_id", "") or "")
    active_run, read_failed = (
        _read_run_store(store, store.load, active_run_id, validate_run=True) if active_run_id else (None, False)
    )
    if not read_failed and active_run is None and active_run_id:
        st.session_state["_radt_active_run_id"] = ""
        active_run_id = ""

    can_manage = can_mutate(ctx, "can_manage_runs", default=False)

    st.text_input("Run notes", key="_radt_run_notes")
    st.text_input("Run tags", key="_radt_run_tags", help="Comma-separated tags for the current or next run.")
    st.text_input("Checkpoint label", key="_radt_checkpoint_label")
    st.text_input("Checkpoint reason", key="_radt_checkpoint_reason")
    st.text_input("Run outcome", key="_radt_run_outcome")

    if read_failed:
        # Keep draft widgets alive, but do not abandon or mutate a run when
        # storage could not establish that the record is actually missing.
        # Child sidebars cannot render without the run. Detach their draft
        # values from Streamlit's omitted-widget cleanup; never retain buttons.
        for key in _RUN_SIDEBAR_DRAFT_KEYS:
            if key in st.session_state:
                st.session_state[key] = st.session_state[key]
        st.warning(
            "The active run could not be read. Its selection is preserved; "
            "run actions are unavailable until the record can be read. "
            "Check the run store and retry. " + _RUN_READ_HELP
        )
        return

    if active_run is None:
        st.caption("No active run.")
        if st.button("Start run", key="_radt_run_start", disabled=not can_manage) and can_mutate(ctx, "can_manage_runs"):
            started = build_run(
                config.registry.persistable_snapshot(st.session_state),
                actor=_record_actor(ctx, st.session_state),
                role=ctx.role,
                source_profile_id=_selected_profile_id(st.session_state),
                active_profile_id=_selected_profile_id(st.session_state),
                notes=str(st.session_state.get("_radt_run_notes", "")),
                tags=_parse_tags(st.session_state.get("_radt_run_tags", "")),
                app_name=config.title,
                app_version=getattr(config, "version", ""),
                session_id=_record_session(ctx, st.session_state),
                source="ui",
            )
            store.save(started)
            st.session_state["_radt_active_run_id"] = started["run_id"]
            config.audit.log("run_start", detail=started["run_id"], role=ctx.role, source="ui")
            st.toast(f"Started run: {started['run_id']}")
            st.rerun()
        return

    summary = run_summary(active_run)
    st.caption(f"Active run: {summary['run_id']}")
    st.caption(f"Status: {summary['status']} | Checkpoints: {summary['checkpoint_count']}")

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Checkpoint", key="_radt_run_checkpoint", disabled=not can_manage) and can_mutate(ctx, "can_manage_runs"):
            updated = append_checkpoint(
                active_run,
                config.registry.persistable_snapshot(st.session_state),
                label=str(st.session_state.get("_radt_checkpoint_label", "") or "") or f"Checkpoint {summary['checkpoint_count'] + 1}",
                reason=str(st.session_state.get("_radt_checkpoint_reason", "") or ""),
                approval_state=_current_approval_state(ctx, can_approve=can_mutate(ctx, "can_approve_changes")),
                actor=_record_actor(ctx, st.session_state),
                role=ctx.role,
                source="ui",
                audit_events=(
                    config.audit.recent(25)
                    if has_perm(ctx, "can_view_audit", default=False)
                    else []
                ),
                telemetry=(
                    _latest_telemetry(st.session_state)
                    if has_perm(ctx, "can_view_metrics", default=False)
                    else {}
                ),
            )
            updated["active_profile_id"] = _selected_profile_id(st.session_state)
            store.save(updated)
            checkpoint_id = str(updated.get("last_checkpoint_id", ""))
            config.audit.log("checkpoint_create", detail=checkpoint_id, role=ctx.role, source="ui")
            st.toast(f"Saved checkpoint: {checkpoint_id}")
            st.rerun()
    with c2:
        if st.button("End run", key="_radt_run_end", disabled=not can_manage) and can_mutate(ctx, "can_manage_runs"):
            finished = end_run(
                active_run,
                outcome=str(st.session_state.get("_radt_run_outcome", "")),
                notes=str(st.session_state.get("_radt_run_notes", "")),
                status="completed",
            )
            finished["active_profile_id"] = _selected_profile_id(st.session_state)
            store.save(finished)
            st.session_state["_radt_active_run_id"] = ""
            config.audit.log("run_end", detail=finished["run_id"], role=ctx.role, source="ui")
            st.toast(f"Ended run: {finished['run_id']}")
            st.rerun()

    if section_visible(config, "team_ops"):
        _render_team_ops_sidebar(st, config, ctx, active_run)
    if section_visible(config, "operator_memory"):
        _render_operator_memory_sidebar(st, config, ctx, active_run)



def render_runbook_panel(st: Any, config: Any, ctx: Any) -> None:
    store = getattr(config, "run_store", None)
    if not section_visible(config, "runbook") or store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    run_ids, read_failed = _read_run_store(store, store.list_ids)
    if not run_ids:
        st.divider()
        with st.expander(getattr(config, "runbook_title", "Runbook"), expanded=False):
            if read_failed:
                _warn_run_history_read(st)
            else:
                st.caption("No runs recorded yet.")
        return

    runs = []
    for run_id in run_ids:
        run, load_failed = _read_run_store(store, store.load, run_id, validate_run=True)
        read_failed = read_failed or load_failed
        if not load_failed:
            runs.append(run)
    runs = [run for run in runs if isinstance(run, dict)]
    if not runs:
        # A listed record can disappear or become unreadable before loading.
        st.divider()
        with st.expander(getattr(config, "runbook_title", "Runbook"), expanded=False):
            if read_failed:
                _warn_run_history_read(st)
            else:
                st.caption("No runs are currently available to display.")
        return
    runs.sort(key=lambda run: (str(run.get("started_at", "")), str(run.get("run_id", ""))), reverse=True)
    summaries = [run_summary(run) for run in runs]

    st.divider()
    with st.expander(getattr(config, "runbook_title", "Runbook"), expanded=False):
        if read_failed:
            _warn_run_history_read(st)
        st.subheader("Recent Runs")
        _render_table(st, summaries)

        selected_default = str(st.session_state.get("_radt_selected_run_id", summaries[0]["run_id"]))
        selected_options = [summary["run_id"] for summary in summaries]
        if selected_default not in selected_options:
            selected_default = selected_options[0]
        selected_run_id = st.selectbox("Run detail", options=selected_options, index=selected_options.index(selected_default), key="_radt_selected_run_id")
        selected_run = next((run for run in runs if run.get("run_id") == selected_run_id), runs[0])
        can_view_metrics = has_perm(ctx, "can_view_metrics", default=False)
        # Keep original evidence for authorized mutations. All browser-bound
        # derived views start from a detached projection so comparisons cannot
        # lose a historical sensitivity flag before the output is checked.
        selected_run_view = project_record(
            selected_run, config.registry, include_control_metadata_values=can_view_metrics,
        )

        st.subheader("Selected Run")
        st.json(run_summary(selected_run))

        can_export_packets = has_perm(ctx, "can_export_packets", default=False)
        can_view_audit = has_perm(ctx, "can_view_audit", default=False)
        can_export_run_evidence = can_export_packets and can_view_metrics and can_view_audit
        if can_export_run_evidence:
            with st.expander("Protocol Preview", expanded=False):
                run_packet = build_run_packet(selected_run_view, source_version=getattr(config, "version", ""))
                run_ledger = build_run_ledger(selected_run_view)
                st.json({"run_packet": run_packet, "ledger_summary": ledger_summary(run_ledger)})

        checkpoints = list(selected_run.get("checkpoints") or [])
        selected_checkpoint = checkpoints[-1] if checkpoints else {}
        if checkpoints:
            st.subheader("Checkpoint Timeline")
            checkpoint_rows = [checkpoint_summary(checkpoint) for checkpoint in checkpoints]
            if not can_view_metrics:
                for row in checkpoint_rows:
                    row.pop("telemetry_keys", None)
            _render_table(st, checkpoint_rows)

            selected_checkpoint_id = st.selectbox(
                "Checkpoint detail",
                options=[row["checkpoint_id"] for row in checkpoint_rows],
                key="_radt_selected_checkpoint_id",
            )
            selected_checkpoint = next(
                (checkpoint for checkpoint in checkpoints if checkpoint.get("checkpoint_id") == selected_checkpoint_id),
                checkpoints[-1],
            )
            checkpoint_view = next(
                checkpoint for checkpoint in selected_run_view["checkpoints"]
                if checkpoint.get("checkpoint_id") == selected_checkpoint.get("checkpoint_id")
            )
            checkpoint_view = dict(checkpoint_view)
            if not can_view_metrics:
                checkpoint_view.pop("controls", None)
                checkpoint_view.pop("telemetry_slice", None)
            if not can_view_audit:
                checkpoint_view.pop("audit_slice", None)
            st.json(checkpoint_view)

            if can_export_run_evidence:
                with st.expander("Checkpoint Packet", expanded=False):
                    st.json(build_checkpoint_packet(checkpoint_view, run_id=selected_run.get("run_id", ""), source_version=getattr(config, "version", "")))

            can_replay = has_perm(ctx, "can_replay_runs", default=False)
            can_apply_replay = can_write(ctx, "can_replay_runs")
            replay_packet = (
                build_replay_packet_from_checkpoint(selected_checkpoint)
                if can_export_packets or can_replay
                else None
            )
            if replay_packet is not None:
                replay_packet["control_meta"] = [
                    *(selected_run.get("control_meta") or []),
                    *(selected_checkpoint.get("control_meta") or []),
                ]
            if can_export_packets and can_view_metrics:
                st.subheader("Replay Preview")
                st.json(build_replay_packet_from_checkpoint(checkpoint_view))
            if can_replay and st.button(
                "Replay checkpoint into live controls",
                key="_radt_checkpoint_replay_btn",
                disabled=not can_apply_replay,
            ) and can_write(ctx, "can_replay_runs"):
                if stage_replay(config, st.session_state, ctx, replay_packet) is not None:
                    # The control widgets already exist. Apply before widgets on
                    # the next render, rechecking the current role and freeze.
                    queue_replay(st.session_state, replay_packet, selected_checkpoint_id)
                    st.rerun()
                else:
                    st.caption("Replay denied: permission is required for every affected control. " + diagnostic_text("RADT-PERMISSION"))

            if can_view_metrics and len(checkpoints) >= 2:
                st.subheader("Checkpoint Compare")
                ids = [row["checkpoint_id"] for row in checkpoint_rows]
                left_id = st.selectbox("Left checkpoint", options=ids, index=max(0, len(ids) - 2), key="_radt_compare_checkpoint_left")
                right_id = st.selectbox("Right checkpoint", options=ids, index=len(ids) - 1, key="_radt_compare_checkpoint_right")
                left = next(cp for cp in checkpoints if cp.get("checkpoint_id") == left_id)
                right = next(cp for cp in checkpoints if cp.get("checkpoint_id") == right_id)
                safe_pair = project_record({"control_meta": selected_run.get("control_meta", []), "left": left, "right": right}, config.registry)
                comparison = compare_checkpoints(safe_pair["left"], safe_pair["right"], include_telemetry=True)
                st.json({key: value for key, value in comparison.items() if key != "telemetry_comparison"})
                _render_telemetry_comparison(st, comparison["telemetry_comparison"])

        if has_perm(ctx, "can_view_metrics", default=False) and len(runs) >= 2:
            st.subheader("Run Compare")
            options = [summary["run_id"] for summary in summaries]
            left_run_id = st.selectbox("Left run", options=options, index=0, key="_radt_compare_run_left")
            right_run_id = st.selectbox("Right run", options=options, index=min(1, len(options) - 1), key="_radt_compare_run_right")
            left_run = next(run for run in runs if run.get("run_id") == left_run_id)
            right_run = next(run for run in runs if run.get("run_id") == right_run_id)
            safe_pair = project_record([left_run, right_run], config.registry)
            comparison = compare_runs(*safe_pair, include_telemetry=True)
            st.json({key: value for key, value in comparison.items() if key != "telemetry_comparison"})
            st.caption("Run measurements come from each run's final checkpoint.")
            _render_telemetry_comparison(st, comparison["telemetry_comparison"])

        if section_visible(config, "team_ops"):
            _render_team_ops_panel(st, config, ctx, selected_run)
        if section_visible(config, "decisions"):
            _render_decision_panel(st, config, ctx, selected_run, selected_checkpoint)
        if section_visible(config, "operator_memory"):
            _render_operator_memory_panel(st, config, ctx, selected_run, selected_checkpoint)
        if section_visible(config, "caseboard"):
            _render_caseboard_panel(st, config, ctx, runs, selected_run)
        if section_visible(config, "governance"):
            _render_governance_panel(st, config, ctx, runs)





def _render_telemetry_comparison(st: Any, comparison: dict[str, Any]) -> None:
    st.subheader("Observed Outcomes")
    st.caption(
        f"Left sample: {comparison['left_sample_ts'] or 'timestamp not recorded'} | "
        f"Right sample: {comparison['right_sample_ts'] or 'timestamp not recorded'}"
    )
    st.caption(
        "Change is right minus left. These observations do not establish that "
        "a control change caused an outcome. Sample times may precede checkpoint times."
    )
    rows = [
        {
            "Metric": name, "Left": row["from"], "Right": row["to"],
            "Left unit": row["from_unit"] or "unspecified",
            "Right unit": row["to_unit"] or "unspecified",
            "Change": row["delta"],
            "Status": row["status"].replace("_", " "),
        }
        for name, row in comparison["metrics"].items()
    ]
    if rows:
        _render_table(st, rows)
    else:
        st.caption("No recorded measurements in either selected checkpoint.")


__all__ = ["render_runbook_panel", "render_runbook_sidebar"]
