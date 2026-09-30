"""Project Pulse: an editable local dashboard copied from the installed toolkit.

Assistant edit map (host instructions and user intent remain authoritative):
- build_controls(): fields, stable keys, groups; run: python -m role_aware_dashboard_toolkit guide controls
- build_roles(): authorization; run: python -m role_aware_dashboard_toolkit guide permissions
- render_view_menu()/render_project_panel(): custom menus and panels; guide plugins
- build_dashboard_config(): layout, card fills and sections; guide appearance / sections
- .streamlit/config.toml: page, sidebar, input, text and accent colors.

Only toolkit stores live in session state. Definitions rebuild each rerun so
source edits apply while in-memory profiles, audit events and runs are retained.
"""
from __future__ import annotations

import streamlit as st
import role_aware_dashboard_toolkit as radt

APP_TITLE = "Project Pulse"
PLAN_GROUP = "Plan"
PRESENTATION_GROUP = "Presentation"
RESOURCE_KEY = "_project_pulse_resources"


def build_controls() -> radt.ControlRegistry:
    """Add/remove fields here. Keep keys stable when renaming display labels."""
    registry = radt.ControlRegistry()
    registry.register(
        "Weekly target", kind="number", key="weekly_target", group=PLAN_GROUP,
        default=40, min_value=1, max_value=200, step=1,
        help="How many tasks are in this week's plan.")
    registry.register(
        "Completion", kind="slider", key="completion_percent", group=PLAN_GROUP,
        default=60.0, min_value=0.0, max_value=100.0, step=5.0,
        help="Percentage completed; the chart derives counts from this value.")
    registry.register(
        "Priority", kind="select", key="priority", group=PLAN_GROUP,
        options=["Steady", "Important", "Urgent"], default="Steady")
    registry.register(
        "Project name", kind="text", key="project_name", group=PRESENTATION_GROUP,
        default="Website refresh")
    registry.register(
        "Intake open", kind="toggle", key="intake_open", group=PRESENTATION_GROUP,
        default=True, permission="can_manage_intake",
        help="Only the Admin role can change whether new work is accepted.")
    registry.register(
        "Chart color", kind="color", key="chart_color", group=PRESENTATION_GROUP,
        default="#0F766E", help="Changes the progress chart, not the page theme.")
    return registry


def build_roles() -> dict[str, radt.RoleDef]:
    """The selector is a local role demo. Shared apps must provide trusted auth."""
    admin = radt.get_role("Admin")
    assert admin is not None
    return {
        "Admin": radt.RoleDef(
            "Admin", {**admin.perms, "can_manage_intake": True},
            "Can adjust the plan, change intake and manage profiles."),
        "Planner": radt.RoleDef(
            "Planner",
            {
                "can_edit_controls": True, "can_manage_intake": False,
                "can_view_metrics": True, "can_view_audit": True,
                "can_save_profiles": True, "can_load_profiles": True,
                "can_view_team_ops": True, "can_manage_runs": True,
                "can_replay_runs": True, "can_export_packets": True,
            },
            "Can plan work and save profiles; intake changes remain restricted."),
    }


def render_view_menu(context: dict) -> None:
    """Display permission is checked here; this menu does not change work data."""
    if not radt.has_perm(context["ctx"], "can_view_metrics"):
        return
    ui = context["st"]
    ui.divider()
    ui.subheader("Project view")
    ui.radio("Show", ["Overview", "Progress"], key="pulse_view")


def render_project_panel(context: dict) -> None:
    """Replace these local calculations with your own authorized data source."""
    if not radt.has_perm(context["ctx"], "can_view_metrics"):
        return
    ui = context["st"]
    values = context["config"].registry.persistable_snapshot(ui.session_state)
    target = int(values["weekly_target"])
    completed = round(target * float(values["completion_percent"]) / 100)
    remaining = max(0, target - completed)

    ui.divider()
    ui.subheader(str(values["project_name"]) or "Untitled project")
    ui.caption(f"{values['priority']} priority · {'Intake open' if values['intake_open'] else 'Intake paused'}")
    columns = ui.columns(3)
    for column, label, value in zip(
        columns, ["Planned tasks", "Completed", "Remaining"],
        [target, completed, remaining], strict=True,
    ):
        with column:
            ui.metric(label, value)
    ui.progress(float(values["completion_percent"]) / 100)

    if ui.session_state.get("pulse_view", "Overview") == "Progress":
        ui.bar_chart(
            {"Stage": ["Completed", "Remaining"], "Tasks": [completed, remaining]},
            x="Stage", y="Tasks", color=str(values["chart_color"]), height=260,
        )
    else:
        ui.info("Choose Progress in the sidebar to see the chart. Adjust the plan above to update this overview.")
    ui.caption("Counts are calculated from your local plan inputs.")


def session_resources() -> dict:
    """Keep stores across reruns; a new browser session starts fresh."""
    if RESOURCE_KEY not in st.session_state:
        st.session_state[RESOURCE_KEY] = {
            "audit": radt.AuditLog(),
            "profiles": radt.InMemoryProfileStore(),
            "runs": radt.InMemoryRunStore(),
        }
    return st.session_state[RESOURCE_KEY]


def build_dashboard_config(resources: dict) -> radt.DashboardConfig:
    """Edit presentation here. Visibility never replaces permission checks."""
    plugins = radt.PluginRegistry()
    plugins.register(radt.DashboardPlugin(
        name="project-view", description="Project overview and progress chart.",
        render_sidebar=render_view_menu, render_panel=render_project_panel,
    ))
    return radt.DashboardConfig(
        title=APP_TITLE, subtitle="A clear view of this week's work.", icon="◈",
        registry=build_controls(), custom_roles=build_roles(), auth_mode="demo",
        audit=resources["audit"], profile_store=resources["profiles"],
        run_store=resources["runs"], plugins=plugins,
        layout="columns", columns_per_row=2,
        card_background_color="#FFFFFF",
        group_background_colors={PLAN_GROUP: "#EFF6FF", PRESENTATION_GROUP: "#F0FDFA"},
        sections=radt.DashboardSections(
            audit_writer=False, plugin_details=False, runbook=False,
        ),
        # For shared use, see `guide authentication` and `init --auth`.
        # To show runs/checkpoints, change runbook=False to runbook=True above.
    )


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="◈", layout="wide")
    context = radt.render(build_dashboard_config(session_resources()))
    if radt.has_perm(context, "can_view_metrics"):
        st.caption("Local demo · toolkit records stay in this browser session")


if __name__ == "__main__":
    main()
