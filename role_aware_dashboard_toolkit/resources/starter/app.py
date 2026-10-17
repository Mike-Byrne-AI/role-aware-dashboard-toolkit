"""Project Pulse: an editable local dashboard copied from the installed toolkit.

Assistant edit map (host instructions and user intent remain authoritative):
- build_controls(): fields, stable keys, groups; run: python -m role_aware_dashboard_toolkit guide controls
- build_roles(): authorization; run: python -m role_aware_dashboard_toolkit guide permissions
- render_view_menu()/render_project_panel(): custom menus and panels; guide plugins
- build_dashboard_config(): layout, card fills and sections; guide appearance / sections
- .streamlit/config.toml: page, sidebar, input, text and accent colors.

Definitions rebuild each rerun. Session-owned stores and stable control keys
keep the plan, profiles and audit history when switching views.
"""
from __future__ import annotations

import streamlit as st
import role_aware_dashboard_toolkit as radt

APP_TITLE = "Project Pulse"
PLAN_GROUP = "Plan"
PRESENTATION_GROUP = "Presentation"
RESOURCE_KEY = "_project_pulse_resources"
VIEWS = ("Overview", "Plan", "Progress", "Activity")


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
        default="#2F614B", help="Changes the progress chart, not the page theme.")
    return registry


def build_roles() -> dict[str, radt.RoleDef]:
    """The selector is a local role demo. Shared apps must provide trusted auth."""
    admin = radt.get_role("Admin")
    if admin is None:
        raise RuntimeError("The toolkit's built-in Admin role is missing.")
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
    ui.radio("Show", VIEWS, key="pulse_view")
    ctx = context["ctx"]
    if not ctx.controls_writable:
        ui.warning("Changes paused")
        ui.caption("An Admin can turn Controls Writable on to resume editing. Views remain available.")
    elif radt.can_write(ctx, "can_manage_intake"):
        ui.caption("Administrative access")
        ui.caption("Edit the plan, manage intake, and pause changes for this demo session.")
    elif radt.can_write(ctx, "can_edit_controls"):
        ui.caption("Planning access")
        ui.caption("Edit the plan and use profiles. Intake remains administrator-controlled.")
    else:
        ui.caption("Read-only access")
        ui.caption("Explore the plan, progress and activity. Editing requires a permitted role.")


def render_project_panel(context: dict) -> None:
    """Replace these local calculations with your own authorized data source."""
    if not radt.has_perm(context["ctx"], "can_view_metrics"):
        return
    ui = context["st"]
    view = ui.session_state.get("pulse_view", "Overview")
    if view == "Activity":
        ui.caption("Activity records changes made in this demo session. Open Audit Log below to inspect them.")
        return
    if view == "Plan":
        ui.caption("Plan values are kept when you change views. Use Profiles in the sidebar to save a named baseline.")
        return
    values = context["config"].registry.persistable_snapshot(ui.session_state)
    target = int(values["weekly_target"])
    completed = round(target * float(values["completion_percent"]) / 100)
    remaining = max(0, target - completed)

    ui.subheader("Project overview" if view == "Overview" else "Project progress")
    # User-authored names are plain text, not Markdown links or remote images.
    ui.text(str(values["project_name"]) or "Untitled project")
    ui.caption(f"{values['priority']} priority · {'Intake open' if values['intake_open'] else 'Intake paused'}")
    columns = ui.columns(4)
    metrics = (
        ("Planned tasks", target, "The weekly target entered in Plan."),
        ("Completed", completed, "Weekly target multiplied by Completion, rounded to a whole task."),
        ("Remaining", remaining, "Planned tasks minus completed tasks."),
        ("Completion rate", f"{float(values['completion_percent']):g}%", "The completion percentage entered in Plan."),
    )
    for column, (label, value, help_text) in zip(columns, metrics, strict=True):
        with column:
            ui.metric(label, value, help=help_text, border=True)
    ui.progress(float(values["completion_percent"]) / 100,
                text=f"{completed} of {target} planned tasks complete")

    if view == "Progress":
        ui.bar_chart(
            {"Stage": ["Completed", "Remaining"], "Tasks": [completed, remaining]},
            x="Stage", y="Tasks", color=str(values["chart_color"]), height=260,
        )
    else:
        with ui.container(border=True):
            ui.subheader("Next steps")
            ui.write("Use **Plan** to adjust inputs, **Progress** to inspect the chart, and **Activity** to review changes.")
            ui.caption("Save a profile before trying a different plan; loading it restores its permitted control values.")
    ui.caption("Calculated from local demo inputs; these figures are not connected to a live project.")


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
    view = st.session_state.get("pulse_view", "Overview")
    return radt.DashboardConfig(
        title=APP_TITLE, subtitle="Plan the work. Track progress. Review changes.", icon="",
        registry=build_controls(), custom_roles=build_roles(), auth_mode="demo",
        audit=resources["audit"], profile_store=resources["profiles"],
        run_store=resources["runs"], plugins=plugins,
        layout="columns", columns_per_row=2,
        card_background_color="#FFFFFF",
        group_background_colors={PLAN_GROUP: "#EEF3E9", PRESENTATION_GROUP: "#FFFFFF"},
        sections=radt.DashboardSections(
            controls=view == "Plan", audit_log=view == "Activity",
            audit_writer=False, plugin_details=False, runbook=False,
        ),
        # For shared use, see `guide authentication` and `init --auth`.
        # To show runs/checkpoints, change runbook=False to runbook=True above.
    )


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="◈", layout="wide")
    context = radt.render(build_dashboard_config(session_resources()))
    if radt.has_perm(context, "can_view_metrics"):
        st.caption("Local role demo · Choose a role in the sidebar. This does not authenticate users.")


if __name__ == "__main__":
    main()
