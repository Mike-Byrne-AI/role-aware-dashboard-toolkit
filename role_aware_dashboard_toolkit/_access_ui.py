"""Authenticated dashboard lifecycle and administrator-controlled shared freeze."""
from __future__ import annotations

from typing import Any
from uuid import uuid4

from .access import AccessDenied, AccessPolicy, FreezeConflict, FreezeState
from .access_audit import bind_audit_identity
from .security import SecurityContext, get_role, has_perm

_PRINCIPAL = "_radt_authenticated_principal"
_SESSION = "_radt_authenticated_session"
_ROLE = "_radt_role"
_FREEZE_REVISION = "_radt_freeze_revision"
_FREEZE_WIDGET = "_radt_shared_frozen"


def _read_freeze(policy: AccessPolicy) -> FreezeState:
    state = policy.store.read_freeze()
    if (not isinstance(state, FreezeState) or type(state.frozen) is not bool
            or type(state.revision) is not int or state.revision < 0):
        raise AccessDenied()
    return state


def _deny(st: Any) -> None:
    # Authentication failure must not leave another account's data or queued
    # writes in session state. Provider cookies/claims are not stored here.
    for key in list(st.session_state):
        # Login/logout button triggers must survive until render_sign_in reads
        # them on this rerun. These booleans cannot grant roles or data access.
        if key not in {"_radt_sign_in", "_radt_sign_out"}:
            del st.session_state[key]
    st.error("Access denied. Sign in with an assigned account; otherwise ask the operator to configure access.")


def prepare_authenticated_access(st: Any, config: Any) -> SecurityContext | None:
    policy = config.access
    if not isinstance(policy, AccessPolicy):
        _deny(st)
        return None
    try:
        principal = policy.identify()
        roles = policy.assigned_roles(principal)
        if not roles or any(get_role(role, config.custom_roles) is None for role in roles):
            raise AccessDenied()
        freeze = _read_freeze(policy)
    except Exception:
        # Adapter failures are denied without exposing private exception data.
        _deny(st)
        return None

    if st.session_state.get(_PRINCIPAL) != principal:
        # A rerun is essential: host code may hold references to resources
        # constructed before render. Do not execute that frame for a new user.
        for key in list(st.session_state):
            del st.session_state[key]
        st.session_state[_PRINCIPAL] = principal
        st.session_state[_SESSION] = uuid4().hex
        st.session_state[_ROLE] = roles[0]
        st.rerun()

    role = st.session_state.get(_ROLE)
    if role not in roles:
        # A revoked role never remains effective, even if a browser submits an
        # old selected value. Its deferred actions are discarded as well.
        role = roles[0]
        st.session_state[_ROLE] = role
        st.session_state.pop("_radt_pending_replay", None)
    role_def = get_role(role, config.custom_roles)
    session_id = st.session_state[_SESSION]
    ctx = SecurityContext(
        role=role, perms=dict(role_def.perms), controls_writable=not freeze.frozen,
        authenticated=True, user_id=principal, session_id=session_id,
        _authorize=lambda permission, write: policy.authorize(
            principal, role, permission, custom_roles=config.custom_roles, write=write,
        ),
    )
    # Native records and audit events share a verified, pseudonymous actor.
    # Always overwrite descriptive session fields; they never grant access.
    st.session_state["_radt_user_id"] = principal
    st.session_state["_radt_session_id"] = session_id
    config.audit = bind_audit_identity(config.audit, principal, session_id)
    if st.session_state.get("_radt_auth_audited_session") != session_id:
        config.audit.log("access_session_started", role=ctx.role)
        st.session_state["_radt_auth_audited_session"] = session_id
    return ctx


def render_authenticated_sidebar(st: Any, config: Any) -> SecurityContext | None:
    ctx = prepare_authenticated_access(st, config)
    if ctx is None:
        return None
    policy = config.access
    try:
        roles = policy.assigned_roles(ctx.user_id)
        freeze = _read_freeze(policy)
    except Exception:
        _deny(st)
        return None
    st.caption("Authenticated access")
    if len(roles) == 1:
        st.caption(f"Assigned role: {ctx.role}")
    else:
        selected = st.selectbox("Assigned role", options=list(roles), key=_ROLE)
        if selected not in roles:
            _deny(st)
            return None
        if selected != ctx.role:
            st.session_state.pop("_radt_pending_replay", None)
            st.rerun()
    previous_role = st.session_state.get("_radt_previous_role")
    if previous_role and previous_role != ctx.role:
        config.audit.log_role_switch(previous_role, ctx.role)
    st.session_state["_radt_previous_role"] = ctx.role

    def set_shared_freeze() -> None:
        # Recheck identity, assigned role, management permission and revision at
        # click time. The toggle is not itself the authority to change state.
        try:
            desired = st.session_state.get(_FREEZE_WIDGET)
            if type(desired) is not bool:
                raise AccessDenied()
            changed = policy.change_freeze(
                ctx.user_id, ctx.role, desired,
                expected_revision=st.session_state[_FREEZE_REVISION],
                custom_roles=config.custom_roles,
            )
            config.audit.log("shared_freeze_changed", new_value=changed.frozen, role=ctx.role)
        except (AccessDenied, FreezeConflict, KeyError):
            st.session_state["_radt_freeze_denied"] = True

    # Refresh the display from authoritative server state, not a previous tab's
    # cached toggle. Callback above runs before the next render.
    st.session_state[_FREEZE_WIDGET] = freeze.frozen
    st.session_state[_FREEZE_REVISION] = freeze.revision
    st.toggle("Freeze changes for everyone", key=_FREEZE_WIDGET,
              disabled=not has_perm(ctx, "can_manage_freeze"), on_change=set_shared_freeze,
              help="Shared server lock. Only assigned freeze administrators can change it.")
    if st.session_state.pop("_radt_freeze_denied", False):
        st.warning("Freeze change denied or superseded. The current server state is shown.")
    st.caption("Changes are frozen." if freeze.frozen else "Changes are enabled.")
    return ctx
