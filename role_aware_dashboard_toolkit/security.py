# role_aware_dashboard_toolkit/security.py
# RBAC security context for dashboard controls.
#
# Provides role-based permission gating: controls disable/hide based on the
# active role's permission set. The "controls_writable" master switch lets
# admins freeze the entire dashboard without changing roles.

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecurityContext:
    """Immutable-ish snapshot of who the current user is and what they can do."""

    role: str = ""
    perms: dict[str, bool] = field(default_factory=dict)
    controls_writable: bool = True



def make_security_context(
    role: str,
    perms: dict[str, bool] | None = None,
    *,
    controls_writable: bool = True,
) -> SecurityContext:
    return SecurityContext(
        role=str(role or ""),
        perms=dict(perms or {}),
        controls_writable=bool(controls_writable),
    )



def has_perm(ctx: SecurityContext | None, key: str, *, default: bool = False) -> bool:
    """Check whether the context grants a specific permission."""
    if ctx is None:
        return bool(default)
    if ctx.perms is None:
        return bool(default)
    if not isinstance(ctx.perms, Mapping):
        raise TypeError("SecurityContext.perms must be a mapping")
    return bool(ctx.perms.get(key, default))



def can_write(ctx: SecurityContext | None, perm_key: str, *, default: bool = False) -> bool:
    """Require both the master writable switch and the specific permission."""
    if ctx is None:
        return bool(default)
    if not bool(getattr(ctx, "controls_writable", True)):
        return False
    return has_perm(ctx, perm_key, default=default)


@dataclass
class RoleDef:
    """A named role with a fixed set of permissions."""

    name: str
    perms: dict[str, bool] = field(default_factory=dict)
    description: str = ""


BUILTIN_ROLES: dict[str, RoleDef] = {
    "Admin": RoleDef(
        name="Admin",
        description="Full access to controls, profiles, runs, decisions, governance, packet export, and audit.",
        perms={
            "can_edit_controls": True,
            "can_view_audit": True,
            "can_manage_audit": True,
            "can_save_profiles": True,
            "can_load_profiles": True,
            "can_view_metrics": True,
            "can_manage_runs": True,
            "can_approve_changes": True,
            "can_replay_runs": True,
            "can_comment_runs": True,
            "can_assign_reviews": True,
            "can_signoff_runs": True,
            "can_view_team_ops": True,
            "can_manage_team_ops": True,
            "can_view_decisions": True,
            "can_manage_decisions": True,
            "can_view_governance": True,
            "can_manage_governance": True,
            "can_export_packets": True,
        },
    ),
    "Operator": RoleDef(
        name="Operator",
        description="Can adjust controls, run experiments, contribute review context, and preview governance state.",
        perms={
            "can_edit_controls": True,
            "can_view_audit": True,
            "can_manage_audit": False,
            "can_save_profiles": False,
            "can_load_profiles": True,
            "can_view_metrics": True,
            "can_manage_runs": True,
            "can_approve_changes": False,
            "can_replay_runs": True,
            "can_comment_runs": True,
            "can_assign_reviews": False,
            "can_signoff_runs": False,
            "can_view_team_ops": True,
            "can_manage_team_ops": False,
            "can_view_decisions": True,
            "can_manage_decisions": True,
            "can_view_governance": True,
            "can_manage_governance": False,
            "can_export_packets": True,
        },
    ),
    "Approver": RoleDef(
        name="Approver",
        description="Can review runs, manage decision state, and save governance outcomes without changing live controls.",
        perms={
            "can_edit_controls": False,
            "can_view_audit": True,
            "can_manage_audit": False,
            "can_save_profiles": False,
            "can_load_profiles": False,
            "can_view_metrics": True,
            "can_manage_runs": True,
            "can_approve_changes": True,
            "can_replay_runs": False,
            "can_comment_runs": True,
            "can_assign_reviews": True,
            "can_signoff_runs": True,
            "can_view_team_ops": True,
            "can_manage_team_ops": True,
            "can_view_decisions": True,
            "can_manage_decisions": True,
            "can_view_governance": True,
            "can_manage_governance": True,
            "can_export_packets": True,
        },
    ),
    "Auditor": RoleDef(
        name="Auditor",
        description="Can inspect audit trails, decisions, governance, and packet output without mutating controls.",
        perms={
            "can_edit_controls": False,
            "can_view_audit": True,
            "can_manage_audit": False,
            "can_save_profiles": False,
            "can_load_profiles": False,
            "can_view_metrics": True,
            "can_manage_runs": False,
            "can_approve_changes": False,
            "can_replay_runs": False,
            "can_comment_runs": False,
            "can_assign_reviews": False,
            "can_signoff_runs": False,
            "can_view_team_ops": True,
            "can_manage_team_ops": False,
            "can_view_decisions": True,
            "can_manage_decisions": False,
            "can_view_governance": True,
            "can_manage_governance": False,
            "can_export_packets": True,
        },
    ),
    "Viewer": RoleDef(
        name="Viewer",
        description="Read-only. Can inspect dashboards, run context, and saved governance outcomes.",
        perms={
            "can_edit_controls": False,
            "can_view_audit": True,
            "can_manage_audit": False,
            "can_save_profiles": False,
            "can_load_profiles": False,
            "can_view_metrics": True,
            "can_manage_runs": False,
            "can_approve_changes": False,
            "can_replay_runs": False,
            "can_comment_runs": False,
            "can_assign_reviews": False,
            "can_signoff_runs": False,
            "can_view_team_ops": True,
            "can_manage_team_ops": False,
            "can_view_decisions": True,
            "can_manage_decisions": False,
            "can_view_governance": True,
            "can_manage_governance": False,
            "can_export_packets": False,
        },
    ),
}


def get_role_names(custom_roles: dict[str, RoleDef] | None = None) -> list[str]:
    """Return ordered list of role names (builtins + custom)."""
    roles = dict(BUILTIN_ROLES)
    if custom_roles:
        roles.update(custom_roles)
    return list(roles.keys())



def get_role(name: str, custom_roles: dict[str, RoleDef] | None = None) -> RoleDef | None:
    roles = dict(BUILTIN_ROLES)
    if custom_roles:
        roles.update(custom_roles)
    return roles.get(name)



def apply_security_fields(
    target: Any,
    role: str,
    perms: dict[str, bool] | None = None,
    *,
    controls_writable: bool = True,
) -> SecurityContext:
    """Stamp a generic object with a Role-Aware Dashboard Toolkit security context.

    This is useful when the UI, a backend adapter, or a custom runtime object
    needs a synchronized view of the current role and permissions.
    """
    ctx = make_security_context(role, perms, controls_writable=controls_writable)
    target._sec_role = ctx.role
    target._sec_perms = dict(ctx.perms)
    target._sec_controls_writable = bool(ctx.controls_writable)
    target._sec_ctx = ctx
    return ctx



def read_security_context(target: Any) -> SecurityContext | None:
    """Read a stamped security context back from an object."""
    ctx = getattr(target, "_sec_ctx", None)
    if isinstance(ctx, SecurityContext):
        return ctx
    role = getattr(target, "_sec_role", None)
    perms = getattr(target, "_sec_perms", None)
    writable = getattr(target, "_sec_controls_writable", None)
    if role is None and perms is None and writable is None:
        return None
    return make_security_context(
        str(role or ""),
        dict(perms or {}),
        controls_writable=bool(True if writable is None else writable),
    )
