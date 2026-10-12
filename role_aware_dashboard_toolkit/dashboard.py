from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import copy
from typing import Any

from ._ui_state import protect_native_controls, retain_control_state, restore_unauthorized_control_state
from .appearance import validate_dashboard_appearance, validate_dashboard_colors
from .audit import AuditLog
from .controls import ControlRegistry
from .dashboard_context import prepare_render_state
from .diagnostics import attach_diagnostic, diagnostic_text
from .dashboard_panels import _validate_control_widgets, render_audit_panel, render_groups
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
from .sections import DashboardSections, section_visible
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
        sections: DashboardSections | None = None,
        card_background_color: str | None = None,
        group_background_colors: Mapping[str, str] | None = None,
        auth_mode: str | None = None,
        access: Any | None = None,
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
        self.auth_mode = auth_mode if auth_mode is not None else ("authenticated" if access is not None else "host" if auth_hook else "demo")
        if self.auth_mode not in {"authenticated", "demo", "host"}:
            raise ValueError("auth_mode must be authenticated, demo, or host")
        if access is not None and self.auth_mode != "authenticated":
            raise ValueError("access requires authenticated mode")
        if self.auth_mode == "authenticated" and auth_hook is not None:
            raise ValueError("Choose access or the legacy auth_hook, not both")
        if self.auth_mode == "host" and auth_hook is None:
            raise ValueError("host mode requires auth_hook")
        self.access = access
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
        if sections is not None and not isinstance(sections, DashboardSections):
            raise attach_diagnostic(TypeError("sections must be DashboardSections or None"), "RADT-SECTIONS")
        self.sections = sections if sections is not None else DashboardSections()
        self.card_background_color, self.group_background_colors = validate_dashboard_colors(
            card_background_color, group_background_colors
        )


def _require_streamlit() -> Any:
    global st
    if st is not None:
        return st
    try:
        import streamlit as streamlit_runtime
    except ModuleNotFoundError as exc:
        if exc.name != "streamlit":
            raise
        raise attach_diagnostic(ModuleNotFoundError(
            "Streamlit is required for Role-Aware Dashboard Toolkit dashboard rendering. "
            'From your reviewed toolkit source checkout, run: python -m pip install ".[workbench]". '
            "From another directory, use the absolute source path or local wheel filename "
            "with [workbench] appended. No package-index release is assumed.",
            name="streamlit",
        ), "RADT-STREAMLIT") from None
    st = streamlit_runtime
    return st


def prepare_access(config: DashboardConfig) -> SecurityContext:
    """Authenticate before a host loads protected data or creates session resources.

    Use this at the beginning of an authenticated Streamlit application, before
    widgets. Raises AccessDenied for a missing/invalid identity, role grant, or
    access store. A principal change clears session state and reruns the script.
    Catch AccessDenied to show the provider sign-in flow. ``render`` rechecks
    access later; this helper does not authorize arbitrary host operations.
    """
    from .access import AccessDenied
    from ._access_ui import prepare_authenticated_access

    if config.auth_mode != "authenticated":
        raise ValueError("prepare_access requires authenticated mode")
    ctx = prepare_authenticated_access(_require_streamlit(), copy(config))
    if ctx is None:
        raise AccessDenied()
    return ctx


def render(config: DashboardConfig) -> SecurityContext:
    streamlit_runtime = _require_streamlit()
    if section_visible(config, "controls"):
        _validate_control_widgets(config.registry)
    if config.auth_mode == "authenticated":
        # Binding an actor must never mutate a config shared between sessions.
        config = copy(config)
    # Authenticate before toolkit/plugin data surfaces. Hosts call prepare_access
    # before their own reads. Streamlit callbacks must also guard each mutation.
    prepared_access = None
    if config.auth_mode == "authenticated":
        from ._access_ui import prepare_authenticated_access
        prepared_access = prepare_authenticated_access(streamlit_runtime, config)
        if prepared_access is None:
            return SecurityContext(role="Unauthenticated", controls_writable=False)
    retain_control_state(config.registry, streamlit_runtime.session_state)
    if prepared_access is not None:
        restore_unauthorized_control_state(config.registry, streamlit_runtime.session_state, prepared_access)
    plugin_setup_errors = config.plugins.initialize({"st": streamlit_runtime, "config": config, "ctx": prepared_access})
    if section_visible(config, "controls"):
        # Setup can register controls; validate those before native widgets too.
        _validate_control_widgets(config.registry)
    # Setup can register additional controls on every Streamlit script run.
    # Retain those values too before sidebar actions can trigger an early rerun.
    retain_control_state(config.registry, streamlit_runtime.session_state)
    if prepared_access is not None:
        restore_unauthorized_control_state(config.registry, streamlit_runtime.session_state, prepared_access)
    # Plugins may register groups during setup; validate overrides before widgets.
    try:
        validate_dashboard_appearance(config, st=streamlit_runtime)
    except (TypeError, ValueError, RuntimeError) as exc:
        if not plugin_setup_errors:
            raise
        # Authentication has not run yet: report the dependency failure without
        # revealing plugin names or exception details from trusted host code.
        exc.args = (
            f"{exc} Plugin setup also failed for {len(plugin_setup_errors)} plugin(s); "
            "check plugin setup configuration and retry. " + diagnostic_text("RADT-PLUGIN"),
        )
        raise
    # Detect structured secrets before sanitation can turn them into ordinary
    # text. The view is session-local; shared host definitions stay untouched.
    protected_registry = protect_native_controls(config.registry, streamlit_runtime.session_state)
    if protected_registry is not config.registry:
        config = copy(config)
        config.registry = protected_registry
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

        if section_visible(config, "controls"):
            render_groups(streamlit_runtime, state.groups, ctx, config)

        if section_visible(config, "observability") and config.observability and config.observability.enabled:
            panel = ObservabilityPanel(
                config.observability, state.audit, streamlit_runtime.session_state,
                can_read_audit=lambda: has_perm(ctx, "can_view_audit"),
                registry=config.registry,
            )
            panel.render(streamlit_runtime)

    if section_visible(config, "runbook"):
        render_runbook_panel(streamlit_runtime, config, ctx)

    for error in config.plugins.discovery_errors():
        streamlit_runtime.warning(f"Plugin discovery error: {error}")

    for error in plugin_setup_errors:
        streamlit_runtime.warning(f"Plugin setup error: {error}")

    plugin_errors = (
        config.plugins.render_panels(
            {"st": streamlit_runtime, "config": config, "ctx": ctx},
            initialize_plugins=False,
        )
        if section_visible(config, "plugin_panels") else []
    )
    for error in plugin_errors:
        streamlit_runtime.warning(f"Plugin panel error: {error}")

    if section_visible(config, "audit_log") and has_perm(ctx, "can_view_audit"):
        render_audit_panel(streamlit_runtime, state.audit, ctx, registry=config.registry)

    return ctx


__all__ = ["DashboardConfig", "render"]
