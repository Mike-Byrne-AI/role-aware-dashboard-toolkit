from __future__ import annotations

from typing import Any

from .checkpoints import checkpoint_summary
from .compare import compare_checkpoints, compare_runs
from .ledger import build_run_ledger, ledger_summary
from .packets import build_checkpoint_packet, build_run_packet
from .replay import apply_replay_packet, build_replay_packet_from_checkpoint
from .runs import append_checkpoint, build_run, end_run, run_summary
from .runbook_panels_parts.caseboard import _render_caseboard_panel
from .runbook_panels_parts.decisions import _render_decision_panel
from .runbook_panels_parts.governance import _render_governance_panel
from .runbook_panels_parts.operator_memory import _render_operator_memory_panel, _render_operator_memory_sidebar
from .runbook_panels_parts.shared import (
    _current_approval_state,
    _latest_telemetry,
    _parse_tags,
    _render_table,
    _selected_profile_id,
)
from .runbook_panels_parts.team_ops import _render_team_ops_panel, _render_team_ops_sidebar
from .security import has_perm



def render_runbook_sidebar(st: Any, config: Any, ctx: Any) -> None:
    store = getattr(config, "run_store", None)
    if store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    st.divider()
    st.subheader(getattr(config, "runbook_title", "Runbook"))
    active_run_id = str(st.session_state.get("_radt_active_run_id", "") or "")
    active_run = store.load(active_run_id) if active_run_id else None
    if active_run is None and active_run_id:
        st.session_state["_radt_active_run_id"] = ""
        active_run_id = ""

    can_manage = has_perm(ctx, "can_manage_runs", default=False)
    can_approve = has_perm(ctx, "can_approve_changes", default=False)

    st.text_input("Run notes", key="_radt_run_notes")
    st.text_input("Run tags", key="_radt_run_tags", help="Comma-separated tags for the current or next run.")
    st.text_input("Checkpoint label", key="_radt_checkpoint_label")
    st.text_input("Checkpoint reason", key="_radt_checkpoint_reason")
    st.text_input("Run outcome", key="_radt_run_outcome")

    if active_run is None:
        st.caption("No active run.")
        if st.button("Start run", key="_radt_run_start", disabled=not can_manage) and can_manage:
            started = build_run(
                config.registry.persistable_snapshot(st.session_state),
                actor=str(st.session_state.get("_radt_user_id", "")),
                role=ctx.role,
                source_profile_id=_selected_profile_id(st.session_state),
                active_profile_id=_selected_profile_id(st.session_state),
                notes=str(st.session_state.get("_radt_run_notes", "")),
                tags=_parse_tags(st.session_state.get("_radt_run_tags", "")),
                app_name=config.title,
                app_version=getattr(config, "version", ""),
                session_id=str(st.session_state.get("_radt_session_id", "")),
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
        if st.button("Checkpoint", key="_radt_run_checkpoint", disabled=not can_manage) and can_manage:
            updated = append_checkpoint(
                active_run,
                config.registry.persistable_snapshot(st.session_state),
                label=str(st.session_state.get("_radt_checkpoint_label", "") or "") or f"Checkpoint {summary['checkpoint_count'] + 1}",
                reason=str(st.session_state.get("_radt_checkpoint_reason", "") or ""),
                approval_state=_current_approval_state(ctx, can_approve=can_approve),
                actor=str(st.session_state.get("_radt_user_id", "")),
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
            store.save(updated)
            checkpoint_id = str(updated.get("last_checkpoint_id", ""))
            config.audit.log("checkpoint_create", detail=checkpoint_id, role=ctx.role, source="ui")
            st.toast(f"Saved checkpoint: {checkpoint_id}")
            st.rerun()
    with c2:
        if st.button("End run", key="_radt_run_end", disabled=not can_manage) and can_manage:
            finished = end_run(
                active_run,
                outcome=str(st.session_state.get("_radt_run_outcome", "")),
                notes=str(st.session_state.get("_radt_run_notes", "")),
                status="completed",
            )
            store.save(finished)
            st.session_state["_radt_active_run_id"] = ""
            config.audit.log("run_end", detail=finished["run_id"], role=ctx.role, source="ui")
            st.toast(f"Ended run: {finished['run_id']}")
            st.rerun()

    _render_team_ops_sidebar(st, config, ctx, active_run)
    _render_operator_memory_sidebar(st, config, ctx, active_run)



def render_runbook_panel(st: Any, config: Any, ctx: Any) -> None:
    store = getattr(config, "run_store", None)
    if store is None or not has_perm(ctx, "can_view_team_ops", default=False):
        return

    run_ids = store.list_ids()
    if not run_ids:
        st.divider()
        with st.expander(getattr(config, "runbook_title", "Runbook"), expanded=False):
            st.caption("No runs recorded yet.")
        return

    runs = [store.load(run_id) for run_id in run_ids]
    runs = [run for run in runs if isinstance(run, dict)]
    runs.sort(key=lambda run: (str(run.get("started_at", "")), str(run.get("run_id", ""))), reverse=True)
    summaries = [run_summary(run) for run in runs]

    st.divider()
    with st.expander(getattr(config, "runbook_title", "Runbook"), expanded=False):
        st.subheader("Recent Runs")
        _render_table(st, summaries)

        selected_default = str(st.session_state.get("_radt_selected_run_id", summaries[0]["run_id"]))
        selected_options = [summary["run_id"] for summary in summaries]
        if selected_default not in selected_options:
            selected_default = selected_options[0]
        selected_run_id = st.selectbox("Run detail", options=selected_options, index=selected_options.index(selected_default), key="_radt_selected_run_id")
        selected_run = next((run for run in runs if run.get("run_id") == selected_run_id), runs[0])

        st.subheader("Selected Run")
        st.json(run_summary(selected_run))

        can_export_packets = has_perm(ctx, "can_export_packets", default=False)
        can_view_metrics = has_perm(ctx, "can_view_metrics", default=False)
        can_view_audit = has_perm(ctx, "can_view_audit", default=False)
        can_export_run_evidence = can_export_packets and can_view_metrics and can_view_audit
        if can_export_run_evidence:
            with st.expander("Protocol Preview", expanded=False):
                run_packet = build_run_packet(selected_run, source_version=getattr(config, "version", ""))
                run_ledger = build_run_ledger(selected_run)
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
            checkpoint_view = dict(selected_checkpoint)
            if not can_view_metrics:
                checkpoint_view.pop("controls", None)
                checkpoint_view.pop("telemetry_slice", None)
            if not can_view_audit:
                checkpoint_view.pop("audit_slice", None)
            st.json(checkpoint_view)

            if can_export_run_evidence:
                with st.expander("Checkpoint Packet", expanded=False):
                    st.json(build_checkpoint_packet(selected_checkpoint, run_id=selected_run.get("run_id", ""), source_version=getattr(config, "version", "")))

            can_replay = has_perm(ctx, "can_replay_runs", default=False)
            can_apply_replay = can_replay and bool(
                getattr(ctx, "controls_writable", True)
            )
            replay_packet = (
                build_replay_packet_from_checkpoint(selected_checkpoint)
                if can_export_packets or can_replay
                else None
            )
            if can_export_packets and can_view_metrics:
                st.subheader("Replay Preview")
                st.json(replay_packet)
            if can_replay and st.button(
                "Replay checkpoint into live controls",
                key="_radt_checkpoint_replay_btn",
                disabled=not can_apply_replay,
            ) and can_apply_replay:
                staged_state = dict(st.session_state)
                applied = apply_replay_packet(replay_packet, config.registry, staged_state)
                required_keys = set(applied["touched_keys"])
                required_keys.update(
                    ctrl.key
                    for ctrl in config.registry.all()
                    if ctrl.key in staged_state
                    and (
                        ctrl.key not in st.session_state
                        or staged_state[ctrl.key] != st.session_state[ctrl.key]
                    )
                )
                if all(
                    has_perm(ctx, config.registry.get(key).permission, default=False)
                    for key in required_keys
                ):
                    for key in required_keys:
                        st.session_state[key] = staged_state[key]
                    config.audit.log("checkpoint_replay", detail=selected_checkpoint_id, role=ctx.role, source="ui")
                    st.toast(f"Replayed checkpoint: {selected_checkpoint_id} ({applied['applied']} values)")
                    st.rerun()
                else:
                    st.caption("Replay denied: permission is required for every affected control.")

            if can_view_metrics and len(checkpoints) >= 2:
                st.subheader("Checkpoint Compare")
                ids = [row["checkpoint_id"] for row in checkpoint_rows]
                left_id = st.selectbox("Left checkpoint", options=ids, index=max(0, len(ids) - 2), key="_radt_compare_checkpoint_left")
                right_id = st.selectbox("Right checkpoint", options=ids, index=len(ids) - 1, key="_radt_compare_checkpoint_right")
                left = next(cp for cp in checkpoints if cp.get("checkpoint_id") == left_id)
                right = next(cp for cp in checkpoints if cp.get("checkpoint_id") == right_id)
                st.json(compare_checkpoints(left, right))

        if has_perm(ctx, "can_view_metrics", default=False) and len(runs) >= 2:
            st.subheader("Run Compare")
            options = [summary["run_id"] for summary in summaries]
            left_run_id = st.selectbox("Left run", options=options, index=0, key="_radt_compare_run_left")
            right_run_id = st.selectbox("Right run", options=options, index=min(1, len(options) - 1), key="_radt_compare_run_right")
            left_run = next(run for run in runs if run.get("run_id") == left_run_id)
            right_run = next(run for run in runs if run.get("run_id") == right_run_id)
            st.json(compare_runs(left_run, right_run))

        _render_team_ops_panel(st, config, ctx, selected_run)
        _render_decision_panel(st, config, ctx, selected_run, selected_checkpoint)
        _render_operator_memory_panel(st, config, ctx, selected_run, selected_checkpoint)
        _render_caseboard_panel(st, config, ctx, runs, selected_run)
        _render_governance_panel(st, config, ctx, runs)





__all__ = ["render_runbook_panel", "render_runbook_sidebar"]
