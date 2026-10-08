"""Host-owned roles and action boundaries for the synthetic A/B/C dashboard.

Role definitions and loaders are trusted server code. Never accept either from
query parameters, uploaded profiles, or other browser input.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from role_aware_dashboard_toolkit import RoleDef, SecurityContext, can_write, has_perm
from role_aware_dashboard_toolkit.access import AccessDenied

SECTIONS = ("A", "B", "C")
ROLE_SECTIONS = {
    "Admin": ("A", "B", "C"),
    "AOnly": ("A",),
    "AB": ("A", "B"),
    "COnly": ("C",),
}
T = TypeVar("T")


def build_roles() -> dict[str, RoleDef]:
    """Admin gets custom permissions explicitly; no wildcard grants exist."""
    return {
        name: RoleDef(
            name,
            {
                **{f"can_view_section_{section.lower()}": section in sections for section in SECTIONS},
                "can_manage_freeze": name == "Admin",
                "can_run_admin_action": name == "Admin",
            },
            f"Read sections {', '.join(sections)}."
            + (" Manage freeze and run the admin action." if name == "Admin" else " Read-only."),
        )
        for name, sections in ROLE_SECTIONS.items()
    }


def visible_sections(ctx: SecurityContext) -> tuple[str, ...]:
    """Navigation is filtered, but each actual read is checked again below."""
    if not ctx.authenticated:
        return ()
    return tuple(section for section in SECTIONS if has_perm(ctx, f"can_view_section_{section.lower()}"))


def read_section(ctx: SecurityContext, section: str, loader: Callable[[str], T]) -> T:
    """Authorize before fetching data, including on a direct/stale invocation."""
    if (
        not ctx.authenticated
        or section not in SECTIONS
        or not has_perm(ctx, f"can_view_section_{section.lower()}")
    ):
        raise AccessDenied()
    return loader(section)


def run_admin_action(ctx: SecurityContext, action: Callable[[], T]) -> T:
    """Check live role grants and shared freeze at the actual mutation site.

    A check plus an external write is not one atomic transaction. A real host
    must supply transaction/cancellation semantics for its own backend.
    """
    if not ctx.authenticated or not can_write(ctx, "can_run_admin_action"):
        raise AccessDenied()
    return action()
