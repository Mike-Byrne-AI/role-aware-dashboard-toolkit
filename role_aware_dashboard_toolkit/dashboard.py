from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .audit import AuditLog
from .controls import ControlRegistry
from .dashboard_context import prepare_render_state
from .dashboard_panels import render_audit_panel, render_groups
from .observability import ObservabilityConfig, ObservabilityPanel
from .run_store import BaseRunStore
from .team_store import BaseTeamStore
from .decision_store import BaseDecisionStore
from .case_store import BaseCaseStore
from .governance_store import BaseGovernanceStore
from .operator_memory_store import BaseOperatorMemoryStore
from .plugins import PluginRegistry
from .profile_store import BaseProfileStore
from .security import RoleDef, SecurityContext, has_perm
from .runbook_panels import render_runbook_panel
from .sidebar import render_sidebar
from .version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION

st: Any | None = None


class DashboardConfig:
    """Top-level configuration for a Role-Aware Dashboard Toolkit dashboard."""

    def __init__(
        self,
        title: str = "Dashboard",
        subtitle: str = "",
        icon: str = "Control Panel",
        registry: ControlRegistry | None = None,
        audit: AuditLog | None = None,
        custom_roles: dict[str, RoleDef] | None = None,
        profile_dir: str = "profiles",
        profile_store: BaseProfileStore | None = None,
        on_change: Callable | None = None,
        layout: str = "stacked",
        columns_per_row: int = 2,
        auth_hook: Callable[[], str] | None = None,
        sanitize_session_state: bool = True,
        observability: ObservabilityConfig | None = None,
        plugins: PluginRegistry | None = None,
        run_store: BaseRunStore | None = None,
        runbook_title: str = "Runbook",
        team_store: BaseTeamStore | None = None,
        team_ops_title: str = "Team Ops",
        decision_store: BaseDecisionStore | None = None,
        decision_title: str = "Decision Layer",
        operator_memory_store: BaseOperatorMemoryStore | None = None,
        timeline_title: str = "Incident Timeline",
        case_store: BaseCaseStore | None = None,
        caseboard_title: str = "Caseboard",
        governance_store: BaseGovernanceStore | None = None,
        governance_title: str = "Governance",
        version: str = ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION,
        audit_dir: str = "audit_logs",
    ):
        self.title = title
        self.subtitle = subtitle
        self.icon = icon
        self.registry = registry if registry is not None else ControlRegistry()
        self.audit = audit if audit is not None else AuditLog()
        self.custom_roles = custom_roles if custom_roles is not None else {}
        self.profile_dir = profile_dir
        self.audit_dir = str(audit_dir or "audit_logs")
        self.profile_store = profile_store
        self.on_change = on_change
        self.layout = layout
        self.columns_per_row = max(1, columns_per_row)
        self.auth_hook = auth_hook
        self.sanitize_session_state = bool(sanitize_session_state)
        self.observability = observability
        self.plugins = plugins if plugins is not None else PluginRegistry()
        self.run_store = run_store
        self.runbook_title = str(runbook_title or "Runbook")
        self.team_store = team_store
        self.team_ops_title = str(team_ops_title or "Team Ops")
        self.decision_store = decision_store
        self.decision_title = str(decision_title or "Decision Layer")
        self.operator_memory_store = operator_memory_store
        self.timeline_title = str(timeline_title or "Incident Timeline")
        self.case_store = case_store
        self.caseboard_title = str(caseboard_title or "Caseboard")
        self.governance_store = governance_store
        self.governance_title = str(governance_title or "Governance")
        self.version = version


def _require_streamlit() -> Any:
    global st
    if st is not None:
        return st
    try:
        import streamlit as streamlit_runtime
    except ModuleNotFoundError as exc:
        if exc.name != "streamlit":
            raise
        raise ModuleNotFoundError(
            "Streamlit is required for Role-Aware Dashboard Toolkit dashboard rendering. "
            'Install with: pip install "role-aware-dashboard-toolkit[workbench]"',
            name="streamlit",
        ) from None
    st = streamlit_runtime
    return st


def render(config: DashboardConfig) -> SecurityContext:
    streamlit_runtime = _require_streamlit()
    plugin_setup_errors = config.plugins.initialize({"st": streamlit_runtime, "config": config, "ctx": None})
    state = prepare_render_state(config, streamlit_runtime.session_state)
    sidebar = render_sidebar(streamlit_runtime, config)
    ctx = sidebar.ctx

    # ``render_sidebar`` uses this locked context when the configured auth hook
    # fails.  Do not continue into host or plugin data surfaces after that
    # failure; the sidebar has already displayed the generic auth error.
    if ctx.role == "Unauthenticated" and not ctx.perms and not ctx.controls_writable:
        return ctx

    streamlit_runtime.title(f"{config.icon} {config.title}".strip())
    if config.subtitle:
        streamlit_runtime.caption(config.subtitle)

    if has_perm(ctx, "can_view_metrics", default=False):
        corrected = int(streamlit_runtime.session_state.pop("_radt_last_sanitize_count", 0) or 0)
        if corrected > 0:
            streamlit_runtime.info(f"Role-Aware Dashboard Toolkit corrected {corrected} out-of-range or stale control value(s) before render.")

        render_groups(streamlit_runtime, state.groups, ctx, config)

        if config.observability and config.observability.enabled:
            panel = ObservabilityPanel(config.observability, state.audit, streamlit_runtime.session_state)
            panel.render(streamlit_runtime)

    render_runbook_panel(streamlit_runtime, config, ctx)

    for error in config.plugins.discovery_errors():
        streamlit_runtime.warning(f"Plugin discovery error: {error}")

    for error in plugin_setup_errors:
        streamlit_runtime.warning(f"Plugin setup error: {error}")

    plugin_errors = config.plugins.render_panels(
        {"st": streamlit_runtime, "config": config, "ctx": ctx},
        initialize_plugins=False,
    )
    for error in plugin_errors:
        streamlit_runtime.warning(f"Plugin panel error: {error}")

    if has_perm(ctx, "can_view_audit"):
        render_audit_panel(streamlit_runtime, state.audit, ctx)

    return ctx


__all__ = ["DashboardConfig", "render"]
