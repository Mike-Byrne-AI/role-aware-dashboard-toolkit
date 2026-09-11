"""Studio Dispatch: local synthetic studio planning built with Role-Aware Dashboard Toolkit."""
from __future__ import annotations

import streamlit as st
import role_aware_dashboard_toolkit as radt

APP_TITLE = "Studio Dispatch"
STAFFING_GROUP = "Staffing"
DELIVERY_GROUP = "Delivery"
RESOURCE_KEY = "_studio_dispatch_resources"


def build_controls() -> radt.ControlRegistry:
    """Customize fields here; stable keys preserve existing profile identity."""
    registry = radt.ControlRegistry()
    registry.register(
        "Weekly available hours", kind="number", key="weekly_hours",
        group=STAFFING_GROUP, default=120, min_value=0, max_value=400, step=1,
        help="Synthetic team capacity for this week, in hours.",
    )
    registry.register(
        "Accept new work", kind="toggle", key="accept_new_work",
        group=STAFFING_GROUP, default=True,
        help="Whether the studio is accepting new briefs this week.",
    )
    registry.register(
        "Completion / load (%)", kind="slider", key="completion_percent",
        group=DELIVERY_GROUP, default=40, min_value=0, max_value=100, step=5,
        help="Share of weekly capacity already completed; remaining hours are derived.",
    )
    registry.register(
        "Priority", kind="select", key="priority", group=DELIVERY_GROUP,
        options=["Routine", "Important", "Urgent"], default="Important",
    )
    registry.register(
        "Client / project name", kind="text", key="project_name",
        group=DELIVERY_GROUP, default="Northstar / Brand refresh",
        help="Use synthetic client and project names only.",
    )
    registry.register(
        "Chart color", kind="color", key="chart_color", group=DELIVERY_GROUP,
        default="#5EEAD4", help="Sets the workload chart color.",
    )
    return registry


def build_roles() -> dict[str, radt.RoleDef]:
    """This selector is a local demo; shared deployment needs a trusted auth_hook."""
    return {
        "Viewer": radt.RoleDef(
            "Viewer", {"can_view_metrics": True},
            "Read-only: can view the workload and notes, but cannot change settings or profiles.",
        ),
    }


def render_view_menu(context: dict) -> None:
    if not radt.has_perm(context["ctx"], "can_view_metrics"):
        return
    ui = context["st"]
    ui.divider()
    ui.subheader("Studio view")
    ui.radio("Show", ["Workload", "Notes"], key="studio_view")


def render_project_panel(context: dict) -> None:
    if not radt.has_perm(context["ctx"], "can_view_metrics"):
        return
    ui = context["st"]
    values = context["config"].registry.persistable_snapshot(ui.session_state)
    capacity = int(values["weekly_hours"])
    completed = round(capacity * int(values["completion_percent"]) / 100, 1)
    remaining = round(capacity - completed, 1)
    ui.divider()
    ui.subheader(str(values["project_name"]) or "Untitled studio project")
    ui.caption(
        f"{values['priority']} priority | "
        f"{'Accepting new work' if values['accept_new_work'] else 'New work paused'}"
    )
    columns = ui.columns(3)
    for column, label, value in zip(
        columns, ["Weekly capacity", "Completed", "Remaining"],
        [capacity, completed, remaining], strict=True,
    ):
        with column:
            ui.metric(label, f"{value:g} h")
    ui.progress(int(values["completion_percent"]) / 100)
    if ui.session_state.get("studio_view", "Workload") == "Workload":
        ui.bar_chart(
            {"Stage": ["Completed", "Remaining"], "Hours": [completed, remaining]},
            x="Stage", y="Hours", color=str(values["chart_color"]), height=280,
        )
        ui.caption("Completed hours = weekly capacity × completion / 100. Remaining hours are the balance.")
    else:
        ui.subheader("Studio notes")
        ui.info("Synthetic planning exercise: no client records or external services are connected.")
        ui.markdown(
            "- **Monday:** align on the Northstar brand direction.\n"
            "- **Wednesday:** internal review of two concept routes.\n"
            "- **Friday:** prepare the demonstration handoff."
        )
        ui.caption("Freeze settings with Controls Writable in the sidebar. Saved profiles last for this browser session.")


def session_resources() -> dict:
    """Keep profile/audit/run stores through reruns; records are session-local."""
    if RESOURCE_KEY not in st.session_state:
        st.session_state[RESOURCE_KEY] = {
            "audit": radt.AuditLog(),
            "profiles": radt.InMemoryProfileStore(),
            "runs": radt.InMemoryRunStore(),
        }
    return st.session_state[RESOURCE_KEY]


def build_dashboard_config(resources: dict) -> radt.DashboardConfig:
    plugins = radt.PluginRegistry()
    plugins.register(radt.DashboardPlugin(
        name="studio-view", description="Synthetic studio workload and notes.",
        render_sidebar=render_view_menu, render_panel=render_project_panel,
    ))
    return radt.DashboardConfig(
        title=APP_TITLE, subtitle="A clear view of this week's creative work.", icon="◈",
        registry=build_controls(), custom_roles=build_roles(),
        audit=resources["audit"], profile_store=resources["profiles"],
        run_store=resources["runs"], plugins=plugins,
        layout="columns", columns_per_row=2,
        card_background_color="#134E4A",
        group_background_colors={STAFFING_GROUP: "#134E4A", DELIVERY_GROUP: "#115E59"},
        sections=radt.DashboardSections(
            audit_writer=False, audit_log=False, runbook=False,
            observability=False, plugin_details=False,
        ),
    )


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="◈", layout="wide")
    context = radt.render(build_dashboard_config(session_resources()))
    if radt.has_perm(context, "can_view_metrics"):
        st.caption("Synthetic studio demo | Profiles stay in this browser session")


if __name__ == "__main__":
    main()
