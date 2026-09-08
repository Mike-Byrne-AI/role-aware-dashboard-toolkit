from __future__ import annotations

import role_aware_dashboard_toolkit as radt
import streamlit as st


APP_TITLE = "Dashboard Admin Controls"
APP_SUBTITLE = "Role-aware service controls with profiles, audit history, and a plugin panel."
OPERATIONS_GROUP = "Operations"
SAFEGUARDS_GROUP = "Safeguards"


def build_control_registry() -> radt.ControlRegistry:
    registry = radt.ControlRegistry()
    registry.register(
        "Request Timeout",
        kind="slider",
        key="request_timeout_seconds",
        group=OPERATIONS_GROUP,
        default=30,
        min_value=1,
        max_value=120,
        step=1,
        help="Maximum time allowed for one request.",
    )
    registry.register(
        "Worker Limit",
        kind="number",
        key="worker_limit",
        group=OPERATIONS_GROUP,
        default=8,
        min_value=1,
        max_value=64,
        step=1,
    )
    registry.register(
        "Deployment Track",
        kind="select",
        key="deployment_track",
        group=SAFEGUARDS_GROUP,
        options=["Stable", "Canary", "Paused"],
        default="Stable",
    )
    registry.register(
        "Maintenance Mode",
        kind="toggle",
        key="maintenance_mode",
        group=SAFEGUARDS_GROUP,
        default=False,
    )
    return registry


def build_custom_roles() -> dict[str, radt.RoleDef]:
    return {
        "Release Lead": radt.RoleDef(
            name="Release Lead",
            description="Can edit service controls and manage release profiles.",
            perms={
                "can_edit_controls": True,
                "can_view_audit": True,
                "can_save_profiles": True,
                "can_load_profiles": True,
                "can_view_metrics": True,
            },
        ),
    }


def build_plugin_registry() -> radt.PluginRegistry:
    plugins = radt.PluginRegistry()
    plugins.register(
        radt.DashboardPlugin(
            name="admin-summary",
            version=radt.__version__,
            description="Compact dashboard-context summary.",
            capabilities=["panel"],
            render_panel=lambda context: context["st"].info(
                f"Role={context['ctx'].role}; writable={context['ctx'].controls_writable}"
            ),
        )
    )
    return plugins


def build_dashboard_config() -> tuple[radt.DashboardConfig, radt.PluginRegistry]:
    plugins = build_plugin_registry()
    return (
        radt.DashboardConfig(
            title=APP_TITLE,
            subtitle=APP_SUBTITLE,
            icon="Role-Aware Dashboard Toolkit",
            registry=build_control_registry(),
            audit=radt.AuditLog(),
            custom_roles=build_custom_roles(),
            plugins=plugins,
            layout="columns",
            columns_per_row=2,
        ),
        plugins,
    )


_RESOURCE_KEY = "_radt_dashboard_admin_resources"


def dashboard_resources() -> tuple[radt.DashboardConfig, radt.PluginRegistry]:
    resources = st.session_state.get(_RESOURCE_KEY)
    if not isinstance(resources, dict):
        config, plugins = build_dashboard_config()
        resources = {"config": config, "plugins": plugins}
        st.session_state[_RESOURCE_KEY] = resources
    return resources["config"], resources["plugins"]


st.set_page_config(page_title=f"Role-Aware Dashboard Toolkit {APP_TITLE}", layout="wide")

config, plugins = dashboard_resources()
ctx = radt.render(config)

st.divider()
with st.expander("State snapshot", expanded=False):
    st.json(
        {
            "request_timeout_seconds": st.session_state.get("request_timeout_seconds"),
            "worker_limit": st.session_state.get("worker_limit"),
            "deployment_track": st.session_state.get("deployment_track"),
            "maintenance_mode": st.session_state.get("maintenance_mode"),
            "active_role": ctx.role,
            "controls_writable": ctx.controls_writable,
            "permissions": ctx.perms,
            "plugin_count": len(plugins.describe()),
        }
    )

st.caption(
    "Use the sidebar to switch roles, change write policy, manage profiles, and inspect audit history."
)
