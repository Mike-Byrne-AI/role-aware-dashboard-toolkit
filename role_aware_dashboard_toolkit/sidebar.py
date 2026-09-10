from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._ui_state import apply_pending_replay
from .profile_store import FileProfileStore
from .audit import _get_writer_shutdown_error, _get_writer_startup_error
from .path_redaction import redact_text_local_paths
from .plugins import PluginErrorRecord
from .profiles import delete_profile, list_profiles, load_profile, load_profile_data, save_profile
from .runbook_panels import render_runbook_sidebar
from .security import (
    SecurityContext,
    can_write,
    get_role,
    get_role_names,
    has_perm,
    make_security_context,
)
from .store_diagnostics import StorePathSecurityError, safe_store_write_path


@dataclass
class SidebarResult:
    ctx: SecurityContext
    plugin_errors: list[PluginErrorRecord]


_AUTH_FAILURE_ROLE = "Unauthenticated"


def _resolve_authenticated_role(
    auth_hook: Any,
    all_roles: list[str],
) -> tuple[str | None, str | None]:
    if auth_hook is None:
        return None, None
    try:
        role = auth_hook()
    except Exception as exc:
        return (
            None,
            f"Authentication failed ({type(exc).__name__}): auth hook raised an exception.",
        )
    if not isinstance(role, str):
        return (
            None,
            "Authentication failed (InvalidRoleType): auth hook must return a role name string.",
        )
    if not role.strip():
        return (
            None,
            "Authentication failed (EmptyRole): auth hook returned an empty role.",
        )
    if role not in all_roles:
        return (
            None,
            "Authentication failed (UnknownRole): auth hook returned an unrecognized role.",
        )
    return role, None



def render_sidebar(st: Any, config: Any) -> SidebarResult:
    audit = config.audit
    all_roles = get_role_names(config.custom_roles)
    plugin_errors: list[PluginErrorRecord] = []

    with st.sidebar:
        st.header(f"{config.icon} {config.title}".strip())

        current_role = st.session_state.get("_radt_role", all_roles[0] if all_roles else "Admin")
        if current_role not in all_roles and all_roles:
            current_role = all_roles[0]
            st.session_state["_radt_role"] = current_role

        forced_role, auth_error = _resolve_authenticated_role(config.auth_hook, all_roles)
        if auth_error:
            st.session_state["_radt_role"] = _AUTH_FAILURE_ROLE
            st.session_state["_radt_previous_role"] = _AUTH_FAILURE_ROLE
            st.session_state["_radt_writable"] = False
            st.session_state["_radt_previous_writable"] = False
            st.session_state.pop("_radt_pending_replay", None)
            st.error(auth_error)
            return SidebarResult(
                ctx=make_security_context(
                    _AUTH_FAILURE_ROLE,
                    {},
                    controls_writable=False,
                ),
                plugin_errors=[],
            )
        if forced_role is not None:
            st.session_state["_radt_role"] = forced_role
            new_role = forced_role
            st.caption(f"Role locked by auth: {new_role}")
        else:
            new_role = st.selectbox(
                "Role",
                options=all_roles,
                index=all_roles.index(current_role) if current_role in all_roles else 0,
                key="_radt_role",
            )

        previous_role = str(st.session_state.get("_radt_previous_role", current_role))
        if new_role != previous_role:
            audit.log_role_switch(previous_role, new_role)
        st.session_state["_radt_previous_role"] = new_role

        current_writable = bool(st.session_state.get("_radt_writable", True))
        writable = st.toggle(
            "Controls Writable",
            value=current_writable,
            key="_radt_writable",
            help="OFF freezes all controls at their current values.",
        )
        previous_writable = bool(st.session_state.get("_radt_previous_writable", current_writable))
        if writable != previous_writable:
            audit.log_freeze(writable, role=new_role)
        st.session_state["_radt_previous_writable"] = writable

        role_def = get_role(new_role, config.custom_roles)
        perms = dict(role_def.perms) if role_def else {}
        ctx = make_security_context(new_role, perms, controls_writable=writable)

        apply_pending_replay(st, config, ctx)
        _render_profiles(st, config, ctx, all_roles)
        render_runbook_sidebar(st, config, ctx)
        _render_audit_writer_controls(st, config, ctx)

        plugin_errors.extend(
            config.plugins.render_sidebar(
                {"st": st, "config": config, "ctx": ctx},
                initialize_plugins=False,
            )
        )
        if config.plugins.describe():
            with st.expander("Plugins", expanded=False):
                st.json(config.plugins.describe())
        for error in plugin_errors:
            st.warning(f"Plugin sidebar error: {error}")

    return SidebarResult(ctx=ctx, plugin_errors=plugin_errors)



class _ProfileStorageFailure(Exception):
    """Sanitized failure raised only around a profile store operation."""


def _profile_store_call(operation: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return operation(*args, **kwargs)
    except (OSError, StorePathSecurityError) as exc:
        raise _ProfileStorageFailure(type(exc).__name__) from None


def _render_profiles(st: Any, config: Any, ctx: SecurityContext, all_roles: list[str]) -> None:
    profile_store = getattr(config, "profile_store", None)
    try:
        if profile_store is None:
            profile_store = _profile_store_call(FileProfileStore, config.profile_dir)
        _render_profile_controls(st, config, ctx, profile_store)
    except _ProfileStorageFailure as exc:
        # Custom and file stores may raise before returning diagnostics. Do not
        # expose exception text: paths and credentials can appear in it.
        st.error(f"Profile storage failed ({exc}). The requested operation did not complete; live controls were preserved.")
    if getattr(profile_store, "read_errors", None):
        st.warning("Profile storage has unreadable records. Existing records were preserved; check storage access and repair invalid profile data.")


def _render_profile_controls(st: Any, config: Any, ctx: SecurityContext, profile_store: Any) -> None:
    reg = config.registry
    audit = config.audit
    st.divider()
    st.subheader("Profiles")
    profiles = _profile_store_call(list_profiles, config.profile_dir, store=profile_store)
    profile_options = ["(none)", *profiles]
    current_choice = st.session_state.get("_radt_profile_choice", "(none)")
    if current_choice not in profile_options:
        st.session_state["_radt_profile_choice"] = "(none)"

    selected_profile = st.selectbox("Load profile", options=profile_options, key="_radt_profile_choice")
    st.text_input("Profile name", value="my_profile", key="_radt_profile_name")

    if selected_profile and selected_profile != "(none)":
        loaded = _profile_store_call(load_profile_data, selected_profile, profile_dir=config.profile_dir, store=profile_store)
        if loaded:
            parent = str(loaded.get("parent_profile_id") or "").strip()
            if parent:
                st.caption(f"Parent profile: {parent}")
            diff_count = len(loaded.get("diff_from_parent") or {})
            if diff_count > 0:
                st.caption(f"Diff entries: {diff_count}")
            source = str(loaded.get("source") or "")
            if source:
                st.caption(f"Source: {redact_text_local_paths(source, repo_root=str(config.profile_dir))}")

    can_save_profiles = has_perm(ctx, "can_save_profiles")
    can_load_profiles = can_write(ctx, "can_load_profiles")
    c_save, c_load = st.columns(2)
    with c_save:
        save_requested = st.button(
            "Save",
            key="_radt_profile_save",
            disabled=not can_save_profiles,
        )
        if save_requested and can_save_profiles:
            name = str(st.session_state.get("_radt_profile_name", "")).strip()
            if name:
                parent_profile_id = selected_profile if selected_profile != "(none)" else ""
                parent_data = _profile_store_call(load_profile_data, parent_profile_id, profile_dir=config.profile_dir, store=profile_store) if parent_profile_id else None
                _profile_store_call(
                    save_profile,
                    name,
                    reg,
                    st.session_state,
                    role=ctx.role,
                    profile_dir=config.profile_dir,
                    store=profile_store,
                    parent_profile_id=parent_profile_id,
                    parent_values=(parent_data or {}).get("values"),
                    app_name=config.title,
                    app_version=getattr(config, "version", ""),
                    session_id=str(st.session_state.get("_radt_session_id", "")),
                    source="ui",
                )
                audit.log_profile_save(name, role=ctx.role)
                st.toast(f"Saved profile: {name}")
            else:
                st.warning("Enter a profile name.")

    with c_load:
        load_requested = st.button(
            "Load",
            key="_radt_profile_load",
            disabled=not can_load_profiles,
        )
        if load_requested and can_load_profiles:
            choice = st.session_state.get("_radt_profile_choice", "(none)")
            if choice and choice != "(none)":
                staged_state = dict(st.session_state)
                result = _profile_store_call(load_profile, choice, reg, staged_state, profile_dir=config.profile_dir, store=profile_store)
                if result:
                    # A bulk restore must not bypass a control's permission,
                    # including changes made by whole-registry sanitization.
                    restored_keys = set(result.get("values", {}))
                    denied = any(
                        not can_write(ctx, ctrl.permission)
                        for ctrl in reg.all()
                        if (not ctrl.sensitive and ctrl.key in restored_keys)
                        or ctrl.key not in st.session_state
                        or staged_state[ctrl.key] != st.session_state[ctrl.key]
                    )
                    if denied:
                        st.warning("Profile requires permission to edit all restored controls.")
                        return
                    for ctrl in reg.all():
                        st.session_state[ctrl.key] = staged_state[ctrl.key]
                    st.session_state["_radt_active_profile_id"] = str(result.get("profile_id") or choice)
                    audit.log_profile_load(choice, role=ctx.role)
                    loaded_keys = set(result.get("values", {}).keys())
                    registry_keys = set(reg.keys())
                    extra = loaded_keys - registry_keys
                    missing = registry_keys - loaded_keys
                    if extra:
                        st.warning(f"Profile contains {len(extra)} unknown controls: {', '.join(sorted(extra)[:5])}")
                    if missing:
                        st.info(f"Profile is missing {len(missing)} controls; existing values were retained.")
                    corrected = int(result.get("corrected_values", 0) or 0)
                    if corrected > 0:
                        st.info(f"Corrected {corrected} profile value(s) to match the current registry.")
                    # Saved role is provenance only; loading values never changes
                    # the current role, its permissions, or an auth-locked identity.
                    st.toast(f"Loaded profile: {choice}")
                else:
                    st.warning(f"Profile '{choice}' not found.")

    delete_requested = st.button(
        "Delete",
        key="_radt_profile_delete",
        disabled=not can_save_profiles,
    )
    if delete_requested and can_save_profiles:
        choice = st.session_state.get("_radt_profile_choice", "(none)")
        if choice and choice != "(none)":
            if _profile_store_call(delete_profile, choice, profile_dir=config.profile_dir, store=profile_store):
                audit.log("profile_delete", detail=choice, role=ctx.role)
                st.toast(f"Deleted profile: {choice}")
                st.rerun()
            else:
                st.warning(f"Could not delete '{choice}'.")



def _render_audit_writer_controls(st: Any, config: Any, ctx: SecurityContext) -> None:
    audit = config.audit
    audit_root = Path(getattr(config, "audit_dir", "audit_logs"))
    default_audit_path = (audit_root / "audit.jsonl").as_posix()
    can_manage_writer = has_perm(ctx, "can_manage_audit")

    st.divider()
    st.subheader("Audit Logging")
    writer_on = st.toggle(
        "Write audit to JSONL",
        value=bool(st.session_state.get("_radt_audit_writer", False)),
        key="_radt_audit_writer",
        help="Writes audit events to disk in a background thread.",
        disabled=not can_manage_writer,
    )
    audit_path = st.text_input(
        "Audit file path",
        value=str(st.session_state.get("_radt_audit_path", default_audit_path)),
        key="_radt_audit_path",
        disabled=not can_manage_writer,
    )
    lifecycle_error: dict[str, str] = {}
    startup_error: dict[str, str] = {}
    try:
        if can_manage_writer:
            if writer_on and audit_path.strip():
                try:
                    safe_path = safe_store_write_path(Path(audit_path.strip()), root_dir=audit_root)
                except (OSError, ValueError, StorePathSecurityError):
                    st.error(
                        "Audit file path must stay within configured audit directory."
                    )
                    audit.stop_writer()
                else:
                    try:
                        audit.start_writer(str(safe_path))
                    except Exception as exc:
                        startup_error = _get_writer_startup_error(exc)
                        if not startup_error:
                            raise
            else:
                audit.stop_writer()
    except TimeoutError as exc:
        lifecycle_error = _get_writer_shutdown_error(exc)
        if not lifecycle_error:
            raise

    writer_status = {} if startup_error else audit.writer_status()
    dropped_events = int(writer_status.get("dropped_events", 0) or 0)
    if dropped_events > 0:
        st.caption(f"Dropped events (queue full): {dropped_events}")

    writer_error_count = int(writer_status.get("writer_error_count", 0) or 0)
    if startup_error or lifecycle_error or writer_error_count > 0:
        last_error = startup_error or lifecycle_error or writer_status.get("last_writer_error")
        error_record = last_error if isinstance(last_error, dict) else {}
        error_type = str(error_record.get("error_type") or error_record.get("exception_type") or "Error")
        message = redact_text_local_paths(
            str(error_record.get("message") or "unknown writer failure"),
            repo_root=str(audit_root),
        )
        st.error(f"Audit writer error ({error_type}): {message}")


__all__ = ["SidebarResult", "render_sidebar"]
