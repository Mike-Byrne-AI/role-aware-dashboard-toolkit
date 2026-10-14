"""Authenticated starter: configure host secrets and provision roles before use.

Run ``python -m role_aware_dashboard_toolkit guide authentication`` for setup.
The planning values are synthetic and session-local. Authorization and freeze
are shared through the external SQLite store. No first visitor is an Admin.
"""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st
import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit.access import AccessDenied, AccessPolicy, SQLiteAccessStore
from role_aware_dashboard_toolkit.access_cli import read_identity_key
from role_aware_dashboard_toolkit.dashboard import prepare_access
from role_aware_dashboard_toolkit.streamlit_auth import (
    StreamlitIdentityResolver, clear_authenticated_state, render_sign_in, sign_out_and_stop,
)

APP_TITLE = "Shared Project Pulse"
RESOURCE_KEY = "_authenticated_pulse_resources"


def _inside(directory: Path, tree: Path) -> bool:
    """Return whether ``directory`` is ``tree`` or below it, by directory identity.

    Text comparison misses /tmp/app on macOS (a link to /private/tmp/app), a
    case-changed /deploy/APP on a case-insensitive disk and the
    /System/Volumes/Data/... firmlink; device and inode numbers do not.
    """
    tree_info = tree.stat()
    for candidate in (directory, *directory.parents):
        try:
            info = candidate.stat()
        except OSError:
            continue  # a directory that does not exist yet
        if (info.st_dev, info.st_ino) == (tree_info.st_dev, tree_info.st_ino):
            return True
    return False


def build_access_policy() -> AccessPolicy:
    """Only trusted process configuration selects the store and OIDC client."""
    directory = Path(os.environ["RADT_ACCESS_DIRECTORY"]).expanduser().absolute()
    # Compare directory identities, not path text (see _inside).
    if _inside(directory.resolve(), Path(__file__).resolve().parent):
        raise ValueError("Access storage must be outside the application source tree.")
    identity_key = read_identity_key(directory)
    return AccessPolicy(
        identity_resolver=StreamlitIdentityResolver(
            trusted_issuer=os.environ["RADT_OIDC_ISSUER"],
            expected_audience=os.environ["RADT_OIDC_AUDIENCE"],
            max_session_age=3600,
        ),
        store=SQLiteAccessStore(directory / "access.sqlite3"),
        identity_key=identity_key,
    )


def build_controls() -> radt.ControlRegistry:
    registry = radt.ControlRegistry()
    registry.register(
        "Weekly target", kind="number", key="weekly_target", group="Plan",
        default=40, min_value=1, max_value=200, step=1,
    )
    registry.register(
        "Completion", kind="slider", key="completion_percent", group="Plan",
        default=60.0, min_value=0.0, max_value=100.0, step=5.0,
    )
    return registry


def session_resources(initial_audit: radt.AuditLog) -> dict:
    # Called only after prepare_access clears state on an account change.
    if RESOURCE_KEY not in st.session_state:
        st.session_state[RESOURCE_KEY] = {
            # Retain the session-start event recorded by the access gate.
            "audit": initial_audit,
            "profiles": radt.InMemoryProfileStore(),
        }
    return st.session_state[RESOURCE_KEY]


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="◈", layout="wide")
    try:
        access = build_access_policy()
    except Exception:
        clear_authenticated_state(st)
        st.error("Access configuration is unavailable. Contact the dashboard administrator.")
        st.stop()
        return
    config = radt.DashboardConfig(
        title=APP_TITLE, subtitle="A shared dashboard with assigned roles.",
        auth_mode="authenticated", access=access,
        sections=radt.DashboardSections(
            audit_writer=False, runbook=False, plugin_details=False,
            team_ops=False, decisions=False, operator_memory=False,
            caseboard=False, governance=False,
        ),
    )
    try:
        prepare_access(config)
    except AccessDenied:
        render_sign_in(st, provider=os.environ.get("RADT_OIDC_PROVIDER"))

    st.button(
        "Sign out", key="_authenticated_pulse_sign_out",
        on_click=lambda: sign_out_and_stop(st),
    )

    # Load private host data or account-specific stores only below this gate.
    # Data reads still need their applicable permission check at the read site.
    resources = session_resources(config.audit)
    config.registry = build_controls()
    config.audit = resources["audit"]
    config.profile_store = resources["profiles"]
    context = radt.render(config)
    if radt.has_perm(context, "can_view_metrics"):
        values = config.registry.persistable_snapshot(st.session_state)
        target = int(values["weekly_target"])
        complete = round(target * float(values["completion_percent"]) / 100)
        st.metric("Completed tasks", f"{complete} / {target}")
        st.caption("Synthetic planning values · profiles and audit stay in this session")


if __name__ == "__main__":
    main()
