"""Session-local teaching workflow; all measurements are deterministic simulations."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit.approvals import build_approval_record
from role_aware_dashboard_toolkit.team_ops import (
    build_handoff_summary,
    build_review_assignment,
    build_signoff_record,
)
from role_aware_dashboard_toolkit.team_store import InMemoryTeamStore

APP_TITLE = "Operator Review Lab"
SIMULATION_NOTICE = "Deterministic teaching formulas; no model calls or measured performance."
METRIC_UNITS = {
    "quality_score": "points / 100",
    "latency_ms": "ms",
    "cost_per_100_requests": "simulated USD / 100 requests",
}


def build_controls() -> radt.ControlRegistry:
    registry = radt.ControlRegistry()
    registry.register(
        "Model tier", kind="select", key="model_tier", group="Response settings",
        options=["Economy", "Balanced", "Thorough"], default="Balanced",
    )
    registry.register(
        "Response limit", kind="number", key="response_limit", group="Response settings",
        default=512, min_value=128, max_value=2048, step=128,
        help="Synthetic response token limit, used only by the teaching formula.",
    )
    registry.register(
        "Temperature", kind="slider", key="temperature", group="Response settings",
        default=0.3, min_value=0.0, max_value=1.0, step=0.1,
    )
    registry.register(
        "Use reference material", kind="toggle", key="use_reference", group="Response settings",
        default=True,
    )
    return registry


def build_roles() -> dict[str, radt.RoleDef]:
    """Scope the exercise roles; the role selector is not authentication."""
    operator = radt.get_role("Operator")
    viewer = radt.get_role("Viewer")
    return {
        "Operator": radt.RoleDef(
            "Operator", {**operator.perms, "can_save_profiles": True, "can_assign_reviews": True},
            "Capture synthetic baselines and candidates; an Approver records the review.",
        ),
        "Viewer": radt.RoleDef(
            "Viewer", {**viewer.perms, "can_view_team_ops": False},
            "Inspect settings and simulated comparisons without access to reviewer notes or decisions.",
        ),
    }


@dataclass
class ReviewSession:
    registry: radt.ControlRegistry = field(default_factory=build_controls)
    profiles: radt.InMemoryProfileStore = field(default_factory=radt.InMemoryProfileStore)
    runs: radt.InMemoryRunStore = field(default_factory=radt.InMemoryRunStore)
    team: InMemoryTeamStore = field(default_factory=InMemoryTeamStore)
    audit: radt.AuditLog = field(default_factory=radt.AuditLog)
    current_run_id: str = ""

    def current_run(self) -> dict[str, Any] | None:
        return self.runs.load(self.current_run_id) if self.current_run_id else None


def _require(ctx: radt.SecurityContext, *permissions: str, write: bool = True) -> None:
    check = radt.can_write if write else radt.has_perm
    if not all(check(ctx, permission) for permission in permissions):
        raise PermissionError("The current role and writable switch do not permit this action.")


def control_values(session: ReviewSession, state: Any) -> dict[str, Any]:
    staged = dict(state)
    session.registry.ensure_defaults(staged)
    session.registry.sanitize_session_state(staged)
    return session.registry.persistable_snapshot(staged)


def simulate_metrics(values: dict[str, Any]) -> dict[str, float]:
    """Invented formulas illustrate a tradeoff; these numbers are not benchmarks."""
    quality, latency, cost = {
        "Economy": (62, 220, 0.06),
        "Balanced": (75, 450, 0.15),
        "Thorough": (86, 800, 0.40),
    }[values["model_tier"]]
    limit = float(values["response_limit"])
    temperature = float(values["temperature"])
    reference = bool(values["use_reference"])
    return {
        "quality_score": round(min(100, quality + min(limit / 128, 8)
                                   + 6 * reference - 12 * abs(temperature - 0.3)), 1),
        "latency_ms": round(latency + 0.8 * limit + 120 * reference, 1),
        "cost_per_100_requests": round(cost * limit / 512 + 0.02 * reference, 3),
    }


def _sample(values: dict[str, Any]) -> dict[str, Any]:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "metrics": simulate_metrics(values),
        "units": dict(METRIC_UNITS),
        "labels": {"measurement_kind": "simulated", "scenario": "support_reply"},
        "source": "operator_review_teaching_formula",
    }


def start_baseline(session: ReviewSession, state: Any, ctx: radt.SecurityContext) -> dict[str, Any]:
    _require(ctx, "can_view_metrics", "can_manage_runs", "can_save_profiles")
    current = session.current_run()
    if current and current["status"] == "active":
        raise ValueError("Review the current candidate before starting another baseline.")
    values = control_values(session, state)
    run = radt.build_run(values, role=ctx.role, app_name=APP_TITLE, notes=SIMULATION_NOTICE)
    profile_id = f"baseline_{run['run_id']}"
    profile = radt.build_profile(profile_id, session.registry, values, role=ctx.role, app_name=APP_TITLE)
    run["source_profile_id"] = profile_id
    run["active_profile_id"] = profile_id
    run = radt.append_checkpoint(run, values, label="Baseline", reason="Synthetic starting point",
                                 role=ctx.role, telemetry=_sample(values))
    session.profiles.save(profile)
    session.runs.save(run)
    session.current_run_id = run["run_id"]
    session.audit.log("review_baseline", detail=run["run_id"], role=ctx.role)
    return run


def capture_candidate(session: ReviewSession, state: Any, ctx: radt.SecurityContext) -> dict[str, Any]:
    _require(ctx, "can_view_metrics", "can_manage_runs", "can_edit_controls", "can_assign_reviews")
    run = session.current_run()
    if not run or run["status"] != "active" or len(run["checkpoints"]) != 1:
        raise ValueError("Start a baseline, then capture one candidate for review.")
    values = control_values(session, state)
    if values == run["initial_controls"]:
        raise ValueError("Change at least one setting before capturing the candidate.")
    run = radt.append_checkpoint(run, values, label="Candidate", reason="Explicit review requested",
                                 role=ctx.role, telemetry=_sample(values))
    run["active_profile_id"] = ""
    assignment = build_review_assignment(
        run["run_id"], checkpoint_id=run["last_checkpoint_id"], title="Review synthetic candidate",
        instructions="Compare the recorded tradeoff and record a reasoned decision.",
        assignee_role="Approver", assigned_role=ctx.role,
    )
    session.runs.save(run)
    session.team.save_assignment(assignment)
    session.audit.log("review_candidate", detail=run["last_checkpoint_id"], role=ctx.role)
    return run


def record_review(
    session: ReviewSession, ctx: radt.SecurityContext, *, decision: str, reason: str, actor: str,
) -> dict[str, Any]:
    _require(ctx, "can_view_metrics", "can_view_team_ops", "can_signoff_runs", "can_approve_changes")
    run = session.current_run()
    if not run or run["status"] != "active" or len(run["checkpoints"]) != 2:
        raise ValueError("Capture a candidate before recording its review.")
    if decision not in {"approved", "changes_requested", "rejected"}:
        raise ValueError("Choose approved, changes_requested or rejected.")
    if not reason.strip() or not actor.strip():
        raise ValueError("Enter a reviewer name and a reason for the decision.")
    checkpoint = run["checkpoints"][-1]
    assignments = session.team.list_assignments(run["run_id"], checkpoint["checkpoint_id"])
    assignment = assignments[-1]
    signoff = build_signoff_record(
        run["run_id"], decision, checkpoint_id=checkpoint["checkpoint_id"],
        assignment_id=assignment["assignment_id"], actor=actor.strip(), role=ctx.role, reason=reason.strip(),
    )
    # A completed review run does not imply approval: preserve the explicit decision.
    approval = decision if decision in {"approved", "rejected"} else "proposed"
    checkpoint["approval_state"] = approval
    checkpoint["approval"] = build_approval_record(approval, actor=actor.strip(), role=ctx.role, reason=reason.strip())
    run = radt.end_run(run, outcome=decision, notes=f"Human review: {reason.strip()}")
    assignment["status"] = "completed"
    session.team.save_assignment(assignment)
    session.team.save_signoff(signoff)
    handoff = build_handoff_summary(
        run, actor=actor.strip(), role=ctx.role, handoff_role="Operator", notes=reason.strip(),
        assignments=[assignment], signoffs=[signoff],
    )
    session.team.save_handoff(handoff)
    session.runs.save(run)
    session.audit.log("review_signoff", detail=f"{checkpoint['checkpoint_id']}: {decision}", role=ctx.role)
    return run


def build_evidence_packet(session: ReviewSession, ctx: radt.SecurityContext) -> dict[str, Any]:
    _require(ctx, "can_view_metrics", "can_view_team_ops", "can_export_packets", write=False)
    run = session.current_run()
    if not run:
        raise ValueError("Start an experiment before exporting evidence.")
    handoffs = session.team.list_handoffs(run["run_id"])
    return radt.build_packet(
        "run", run, source_app=APP_TITLE, source_version=radt.__version__,
        meta={"run_id": run["run_id"], "operator_review": {
            "simulation": SIMULATION_NOTICE,
            "assignments": session.team.list_assignments(run["run_id"]),
            "signoffs": session.team.list_signoffs(run["run_id"]),
            "handoff": handoffs[-1] if handoffs else {},
        }},
    )
