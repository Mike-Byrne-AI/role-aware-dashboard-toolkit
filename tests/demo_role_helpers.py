"""Start demo-mode AppTest sessions in an explicit role.

A demo session starts in its least-privileged role (Viewer for the built-in
roles). Tests that drive Admin workflows in demo mode choose Admin first, the
way a person picks a role in the sidebar.
"""
from __future__ import annotations

from typing import Any


def start_as_admin(app: Any) -> Any:
    """Preset the demo role selector to Admin before the first run."""
    app.session_state["_radt_role"] = "Admin"
    return app
