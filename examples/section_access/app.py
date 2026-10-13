"""Authenticated A/B/C dashboard. Run demo.py for the explicit local simulation."""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st
import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit.access import AccessDenied, AccessPolicy, SQLiteAccessStore
from role_aware_dashboard_toolkit.access_cli import read_identity_key
from role_aware_dashboard_toolkit.dashboard import prepare_access
from role_aware_dashboard_toolkit.streamlit_auth import (
    StreamlitIdentityResolver, render_sign_in, sign_out_and_stop,
)

from examples.section_access.policy import (
    ROLE_SECTIONS, build_roles, read_section, run_admin_action, visible_sections,
)

APP_TITLE = "A / B / C Access Lab"


def build_access_policy() -> AccessPolicy:
    """Production identity comes only from verified OIDC and external grants."""
    directory = Path(os.environ["RADT_ACCESS_DIRECTORY"]).expanduser().absolute()
    # Compare resolved paths: /tmp/app/secrets is inside an app at /private/tmp/app.
    if directory.resolve().is_relative_to(Path(__file__).resolve().parent):
        raise ValueError("Access storage must be outside the application source tree.")
    identity_key = read_identity_key(directory)
    return AccessPolicy(
        StreamlitIdentityResolver(
            trusted_issuer=os.environ["RADT_OIDC_ISSUER"],
            expected_audience=os.environ["RADT_OIDC_AUDIENCE"],
            max_session_age=3600,
        ),
        SQLiteAccessStore(directory / "access.sqlite3", allowed_roles=tuple(ROLE_SECTIONS)),
        identity_key,
    )


def load_synthetic_section(section: str) -> dict[str, str]:
    """Replace with a private backend loader only behind read_section()."""
    return {
        "A": {
            "title": "Operations", "metric": "Open work items", "value": "24",
            "note": "A-101: Prepare the weekly plan. A-102: Review the delivery queue.",
        },
        "B": {
            "title": "Planning", "metric": "Scheduled projects", "value": "8",
            "note": "B-201: Northstar launch. B-202: Cedar refresh.",
        },
        "C": {
            "title": "Review", "metric": "Reviews awaiting sign-off", "value": "5",
            "note": "C-301: Release readiness. C-302: Quality checkpoint.",
        },
    }[section]


def _record_admin_run() -> int:
    count = st.session_state.get("section_access_admin_runs", 0) + 1
    st.session_state["section_access_admin_runs"] = count
    return count


def main(access: AccessPolicy | None = None, *, simulation: bool = False) -> None:
    """An injected policy is a trusted host/test integration, never URL input."""
    st.set_page_config(page_title=APP_TITLE, page_icon="🔐", layout="wide")
    if simulation:
        st.warning("LOCAL SIMULATION — anyone can switch accounts. Synthetic data only; no real sign-in.")
    try:
        if access is None:
            access = build_access_policy()
    except Exception:
        # Configuration errors can contain credentials or private host paths.
        st.error("Access configuration is unavailable. Follow the example README to configure sign-in.")
        st.stop()
        return

    config = radt.DashboardConfig(
        title=APP_TITLE, subtitle="Three sections. Four assigned access roles.", icon="",
        auth_mode="authenticated", access=access, custom_roles=build_roles(),
        sections=radt.DashboardSections(
            controls=False, profiles=False, runbook=False, audit_writer=False,
            audit_log=False, observability=False, plugin_details=False,
            plugin_sidebar=False, plugin_panels=False, team_ops=False,
            decisions=False, operator_memory=False, caseboard=False, governance=False,
        ),
    )
    try:
        prepare_access(config)
    except AccessDenied:
        if simulation:
            st.info("This simulated account has no access. Choose an assigned account in the sidebar.")
            # Return before all protected work, allowing demo.py to build its
            # public recovery selector after denial has cleared session state.
            return
        render_sign_in(st, provider=os.environ.get("RADT_OIDC_PROVIDER"))

    if not simulation:
        st.sidebar.button(
            "Sign out", key="section_access_sign_out",
            on_click=lambda: sign_out_and_stop(st),
        )

    ctx = radt.render(config)
    allowed = visible_sections(ctx)
    if not allowed:
        st.error("Access denied. No sections are assigned to this account.")
        st.stop()
        return

    st.caption(f"Active access role: {ctx.role} · Available sections: {', '.join(allowed)}")
    # An old tab or a forged navigation value must never select a denied read.
    if st.session_state.get("section_access_section") not in allowed:
        st.session_state["section_access_section"] = allowed[0]
    section = st.radio("Section", allowed, horizontal=True, key="section_access_section")
    try:
        data = read_section(ctx, section, load_synthetic_section)
    except AccessDenied:
        st.error("Access changed. Refresh or sign in again.")
        st.stop()
        return

    with st.container(border=True):
        st.subheader(f"Section {section}")
        st.caption(data["title"])
        st.metric(data["metric"], data["value"])
        st.write(data["note"])
    st.caption("All records are invented. Restricted section data is checked before loading.")

    if radt.has_perm(ctx, "can_run_admin_action"):
        st.divider()
        st.subheader("Administrator")
        st.write("Run a harmless admin action: increment a counter in this session.")
        if st.button(
            "Run admin action", key="section_access_admin_action",
            disabled=not radt.can_write(ctx, "can_run_admin_action"),
        ):
            try:
                count = run_admin_action(ctx, _record_admin_run)
            except AccessDenied:
                st.error("Admin action denied. Your assignment or the shared freeze may have changed.")
            else:
                st.success(f"Admin action completed. Session count: {count}.")
        st.caption("Unfreeze changes in the sidebar to enable this action. Section reads remain available while frozen.")


if __name__ == "__main__":
    main()
