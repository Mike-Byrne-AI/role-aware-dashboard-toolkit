"""Explicit local simulation: browser-selectable identities are NOT authentication.

Launch on 127.0.0.1 only. Never deploy this entry point or connect private data.
The production app.py has no account selector and does not import this module.
"""

from __future__ import annotations

import secrets
import time

import streamlit as st
from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, InMemoryAccessStore, principal_id

from examples.section_access.app import main
from examples.section_access.policy import ROLE_SECTIONS

ACCOUNTS = {
    "Admin": "Admin — A, B and C",
    "AOnly": "A only",
    "AB": "A and B",
    "COnly": "C only",
    "Unassigned": "Unassigned — access denied",
}


def synthetic_identity(account: str) -> Identity:
    return Identity("synthetic-section-access", account, time.time() + 3600)


@st.cache_resource
def demo_store() -> tuple[InMemoryAccessStore, bytes]:
    """One synthetic shared freeze per process; no files or real account grants."""
    store = InMemoryAccessStore(allowed_roles=tuple(ROLE_SECTIONS))
    key = secrets.token_bytes(32)
    for role in ROLE_SECTIONS:
        store.replace_grants(principal_id(synthetic_identity(role), key), (role,))
    return store, key


def selected_identity() -> Identity:
    # Deliberately untrusted for this local simulation only. The query value
    # survives the toolkit clearing session state when the account changes.
    account = st.query_params.get("demo_account", "Admin")
    return synthetic_identity(account if account in ACCOUNTS else "Unassigned")


def demo() -> None:
    # Reserve sidebar placement only. Build the widget after the access gate:
    # denial clears all session state, including previously rendered widgets.
    selector = st.sidebar.container()
    store, key = demo_store()
    main(AccessPolicy(selected_identity, store, key), simulation=True)
    requested = st.query_params.get("demo_account", "Admin")
    account = requested if requested in ACCOUNTS else "Unassigned"

    def change_account() -> None:
        st.query_params["demo_account"] = st.session_state["section_access_demo_account"]

    selector.selectbox(
        "Simulated account", list(ACCOUNTS), index=list(ACCOUNTS).index(account),
        format_func=ACCOUNTS.get, key="section_access_demo_account", on_change=change_account,
    )
    selector.caption("Local simulation. Switching accounts clears session data.")


if __name__ == "__main__":
    demo()
