from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._profile_preview import InvalidProfilePreviewValues, build_profile_restore_preview
from ._ui_state import apply_pending_replay, remember_authorized_control_values
from .profile_store import FileProfileStore
from .diagnostics import build_diagnostic, diagnostic_text
from .audit import _get_writer_shutdown_error, _get_writer_startup_error
from .path_redaction import redact_text_local_paths
from .plugins import PluginErrorRecord
from .profiles import (
    _InvalidProfileError, _load_ui_profile, _require_profile_shape, delete_profile, list_profiles,
    load_profile_data, save_profile,
)
from .runbook_panels import render_runbook_sidebar
from .sections import section_visible
from .security import (
    SecurityContext,
    can_write,
    can_mutate,
    get_role,
    get_role_names,
    make_security_context,
)
from .store_diagnostics import StorePathSecurityError, safe_store_write_path


@dataclass
class SidebarResult:
    ctx: SecurityContext
    plugin_errors: list[PluginErrorRecord]


_AUTH_FAILURE_ROLE = "Unauthenticated"
_PROFILE_REPLACE_PENDING = "_radt_profile_replace_pending"


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

    # Preserve writer configuration when an earlier action reruns the sidebar.
    for key in ("_radt_audit_writer", "_radt_audit_path"):
        if key in st.session_state:
            st.session_state[key] = st.session_state[key]

    if getattr(config, "auth_mode", "demo") == "authenticated":
        from ._access_ui import render_authenticated_sidebar
        with st.sidebar:
            st.header(f"{config.icon} {config.title}".strip())
            ctx = render_authenticated_sidebar(st, config)
            if ctx is None:
                return SidebarResult(
                    make_security_context(_AUTH_FAILURE_ROLE, {}, controls_writable=False), [],
                )
            return _render_authorized_sidebar(st, config, ctx, all_roles)

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
            st.error(auth_error + " " + diagnostic_text("RADT-AUTH"))
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
            st.caption("Demo access: roles are self-selected; no user identity is verified.")
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

        return _render_authorized_sidebar(st, config, ctx, all_roles)


def _render_authorized_sidebar(st: Any, config: Any, ctx: SecurityContext, all_roles: list[str]) -> SidebarResult:
    apply_pending_replay(st, config, ctx)
    if section_visible(config, "profiles"):
        _render_profiles(st, config, ctx, all_roles)
    render_runbook_sidebar(st, config, ctx)
    _render_audit_writer_controls(st, config, ctx)
    plugin_errors = []
    if section_visible(config, "plugin_sidebar"):
        plugin_errors.extend(config.plugins.render_sidebar(
            {"st": st, "config": config, "ctx": ctx}, initialize_plugins=False,
        ))
    if section_visible(config, "plugin_details") and config.plugins.describe():
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
    except (OSError, StorePathSecurityError, _InvalidProfileError) as exc:
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
        st.error(f"Profile storage failed ({exc}). " + diagnostic_text("RADT-PROFILE-IO"))
    if getattr(profile_store, "read_errors", None):
        # Read errors may outlive the read that recorded them. A successful
        # save/load/delete in this render must not be described as a failure.
        st.warning(
            "Profile storage has unreadable records. Unreadable records were skipped; "
            "other profile operations may still succeed. Help: "
            + build_diagnostic("RADT-PROFILE-IO")["guide_command"]
        )


def _render_profile_controls(st: Any, config: Any, ctx: SecurityContext, profile_store: Any) -> None:
    st.divider()
    st.subheader("Profiles")
    profiles = _profile_store_call(list_profiles, config.profile_dir, store=profile_store)
    selected_profile = st.session_state.get("_radt_profile_choice", "(none)")
    if selected_profile not in profiles:
        selected_profile = "(none)"
        st.session_state["_radt_profile_choice"] = selected_profile
    selected_profile_valid = True
    if selected_profile != "(none)":
        selected_data = _profile_store_call(
            load_profile_data, selected_profile, profile_dir=config.profile_dir, store=profile_store,
        )
        if selected_data is not None:
            try:
                _require_profile_shape(selected_data)
            except _InvalidProfileError:
                selected_profile_valid = False

    # Keep inputs visually above the buttons, but create their widgets after a
    # successful write has refreshed membership. An early rerun would interrupt
    # host/plugin widgets later in the script and can discard their state.
    inputs = st.container()
    try:
        if _render_profile_actions(st, config, ctx, profile_store, selected_profile,
                                   selected_profile_valid=selected_profile_valid,
                                   known_profiles=profiles):
            profiles = _profile_store_call(list_profiles, config.profile_dir, store=profile_store)
    finally:
        # A failed store operation or denied load must still render these keyed
        # inputs, so Streamlit does not remove the operator's selection/name.
        with inputs:
            profile_options = ["(none)", *profiles]
            current_choice = st.session_state.get("_radt_profile_choice", "(none)")
            st.session_state["_radt_profile_choice"] = (
                current_choice if current_choice in profile_options else "(none)"
            )
            selected_profile = st.selectbox(
                "Load profile", options=profile_options, key="_radt_profile_choice"
            )
            st.text_input(
                "Profile name", value="my_profile", key="_radt_profile_name",
                disabled=not can_mutate(ctx, "can_save_profiles"),
                help="Name for saving the current settings. Replacing an existing profile requires confirmation.",
            )

    with inputs:
        if selected_profile and selected_profile != "(none)":
            loaded = _profile_store_call(load_profile_data, selected_profile, profile_dir=config.profile_dir, store=profile_store)
            if loaded:
                try:
                    _require_profile_shape(loaded)
                except _InvalidProfileError:
                    st.warning("Profile preview is unavailable: saved values are invalid.")
                    return
                parent = str(loaded.get("parent_profile_id") or "").strip()
                if parent:
                    st.caption(f"Parent profile: {parent}")
                diff_count = len(loaded.get("diff_from_parent") or {})
                if diff_count > 0:
                    st.caption(f"Diff entries: {diff_count}")
                source = str(loaded.get("source") or "")
                if source:
                    st.caption(f"Source: {redact_text_local_paths(source, repo_root=str(config.profile_dir))}")
                _render_profile_preview(st, config, ctx, loaded)


def _render_profile_preview(
    st: Any, config: Any, ctx: SecurityContext, profile: dict[str, Any],
) -> None:
    try:
        preview = build_profile_restore_preview(profile, config.registry, st.session_state, ctx)
    except InvalidProfilePreviewValues:
        st.warning("Profile preview is unavailable: saved values are invalid.")
        return
    with st.expander("Preview profile changes", expanded=False):
        if preview.blocked_reasons:
            st.warning("Load is blocked; no values will change. " + " ".join(preview.blocked_reasons))
        if preview.values_visible:
            st.caption("Effective values show the proposed result after correction. Load rechecks permissions.")
            if preview.rows:
                st.dataframe(preview.rows, use_container_width=True, hide_index=True)
            else:
                st.caption("No registered controls to restore.")
        else:
            st.caption("Values require permission to view controls and load profiles.")
        if preview.corrected_count:
            st.caption(f"{preview.corrected_count} value(s) would be corrected to match the current controls.")
        if preview.unknown_count:
            st.caption(f"{preview.unknown_count} unknown field(s) omitted; their values are hidden.")
        if preview.sensitive_omitted_count:
            st.caption(f"{preview.sensitive_omitted_count} sensitive saved field(s) omitted; saved values will not be restored.")


def _save_ui_profile(st: Any, config: Any, ctx: SecurityContext, store: Any,
                     name: str, selected_profile: str) -> bool:
    parent_id = selected_profile if selected_profile != "(none)" else ""
    parent = _profile_store_call(
        load_profile_data, parent_id, profile_dir=config.profile_dir, store=store,
    ) if parent_id else None
    if parent is not None:
        _profile_store_call(_require_profile_shape, parent)
    if not can_mutate(ctx, "can_save_profiles"):
        st.warning("Save denied. Your permission or the shared freeze changed.")
        return False
    _profile_store_call(
        save_profile, name, config.registry, st.session_state, role=ctx.role,
        profile_dir=config.profile_dir, store=store, parent_profile_id=parent_id,
        parent_values=(parent or {}).get("values"), app_name=config.title,
        app_version=getattr(config, "version", ""),
        session_id=str(st.session_state.get("_radt_session_id", "")), source="ui",
    )
    config.audit.log_profile_save(name, role=ctx.role)
    st.toast(f"Saved profile: {name}")
    return True


def _read_profile_save_target(config: Any, store: Any, name: str,
                              known_profiles: list[str]) -> dict | None:
    errors_before = len(getattr(store, "read_errors", ()))
    saved = _profile_store_call(
        load_profile_data, name, profile_dir=config.profile_dir, store=store,
    )
    if saved is None and (
        name in known_profiles or len(getattr(store, "read_errors", ())) > errors_before
    ):
        # An unreadable/disappearing record is not permission to overwrite it.
        raise _ProfileStorageFailure("UnreadableProfile")
    if saved is not None:
        _profile_store_call(_require_profile_shape, saved)
    return saved


def _render_profile_save(st: Any, config: Any, ctx: SecurityContext, store: Any,
                         selected_profile: str, selected_profile_valid: bool,
                         known_profiles: list[str], *, save_column: Any) -> bool:
    allowed = can_mutate(ctx, "can_save_profiles") and selected_profile_valid
    name = str(st.session_state.get("_radt_profile_name", "")).strip()
    intent = {
        "name": name, "parent": selected_profile, "role": ctx.role,
        "values": config.registry.persistable_snapshot(st.session_state),
    }
    pending = st.session_state.get(_PROFILE_REPLACE_PENDING)
    if pending is not None and (not allowed or pending.get("intent") != intent):
        st.session_state.pop(_PROFILE_REPLACE_PENDING, None)
        pending = None
        st.info("Replacement canceled because the settings, selection, or access changed. Choose Save to review it again.")
    # A confirmation must come from an earlier render, not the Save submission.
    was_pending = pending is not None
    with save_column:
        requested = st.button("Save", key="_radt_profile_save", disabled=not allowed)
    if requested and allowed and can_mutate(ctx, "can_save_profiles"):
        was_pending = False
        if not name:
            st.warning("Enter a profile name.")
        else:
            saved = _read_profile_save_target(config, store, name, known_profiles)
            if saved is None:
                return _save_ui_profile(st, config, ctx, store, name, selected_profile)
            pending = {"intent": deepcopy(intent), "saved": deepcopy(saved)}
            st.session_state[_PROFILE_REPLACE_PENDING] = pending
    if pending is None:
        return False
    confirmation = st.empty()
    with confirmation.container():
        st.warning(f'A saved profile named "{name}" already exists. Replace it with the current settings, or cancel to keep the saved version.')
        replace_requested = st.button("Replace saved profile", key="_radt_profile_replace_confirm")
        cancel_requested = st.button("Cancel replacement", key="_radt_profile_replace_cancel")
    if cancel_requested:
        st.session_state.pop(_PROFILE_REPLACE_PENDING, None)
        confirmation.empty()
        st.info("Replacement canceled. The saved profile was kept.")
        return False
    if replace_requested and was_pending:
        # Consume consent once, including on denial or an uncertain store write.
        st.session_state.pop(_PROFILE_REPLACE_PENDING, None)
        try:
            if not can_mutate(ctx, "can_save_profiles"):
                st.warning("Replacement denied. Your permission or the shared freeze changed.")
                return False
            saved = _read_profile_save_target(config, store, name, known_profiles)
            if saved != pending["saved"]:
                st.warning("The saved profile changed. Nothing was replaced; choose Save to review it again.")
                return False
            return _save_ui_profile(st, config, ctx, store, name, selected_profile)
        finally:
            confirmation.empty()
    return False


def _render_profile_actions(
    st: Any, config: Any, ctx: SecurityContext, profile_store: Any, selected_profile: str,
    *, selected_profile_valid: bool = True, known_profiles: list[str] | None = None,
) -> bool:
    """Process profile actions once; report a successful membership-changing write."""
    reg = config.registry
    audit = config.audit
    profiles_changed = False
    can_save_profiles = can_mutate(ctx, "can_save_profiles")
    can_load_profiles = can_write(ctx, "can_load_profiles")
    c_save, c_load = st.columns(2)
    profiles_changed = _render_profile_save(
        st, config, ctx, profile_store, selected_profile, selected_profile_valid,
        known_profiles or [], save_column=c_save,
    )

    with c_load:
        load_requested = st.button(
            "Load",
            key="_radt_profile_load",
            disabled=not can_load_profiles or not selected_profile_valid,
        )
    if load_requested and can_write(ctx, "can_load_profiles"):
        choice = st.session_state.get("_radt_profile_choice", "(none)")
        if choice and choice != "(none)":
            staged_state = dict(st.session_state)
            result = _profile_store_call(_load_ui_profile, choice, reg, staged_state, profile_dir=config.profile_dir, store=profile_store)
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
                    st.warning("Profile requires permission to edit all restored controls. " + diagnostic_text("RADT-PERMISSION"))
                    return profiles_changed
                for ctrl in reg.all():
                    st.session_state[ctrl.key] = staged_state[ctrl.key]
                if getattr(ctx, "authenticated", False):
                    remember_authorized_control_values(
                        st.session_state, {ctrl.key: staged_state[ctrl.key] for ctrl in reg.all()},
                    )
                st.session_state["_radt_active_profile_id"] = str(result.get("profile_id") or choice)
                audit.log_profile_load(choice, role=ctx.role)
                loaded_keys = set(result.get("values", {}).keys())
                registry_keys = set(reg.keys())
                extra = loaded_keys - registry_keys
                missing = {ctrl.key for ctrl in reg.all() if not ctrl.sensitive} - loaded_keys
                if extra:
                    st.warning(f"Profile contains {len(extra)} unknown controls: {', '.join(sorted(extra)[:5])}")
                if missing:
                    st.caption(
                        "This preset updates only the settings it includes. "
                        "Other settings and your permissions stay unchanged."
                    )
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
    if delete_requested and can_mutate(ctx, "can_save_profiles"):
        choice = st.session_state.get("_radt_profile_choice", "(none)")
        if choice and choice != "(none)":
            if _profile_store_call(delete_profile, choice, profile_dir=config.profile_dir, store=profile_store):
                audit.log("profile_delete", detail=choice, role=ctx.role)
                st.toast(f"Deleted profile: {choice}")
                profiles_changed = True
            else:
                st.warning(f"Could not delete '{choice}'.")
    return profiles_changed



def _render_audit_writer_controls(st: Any, config: Any, ctx: SecurityContext) -> None:
    audit = config.audit
    audit_root = Path(getattr(config, "audit_dir", "audit_logs"))
    default_audit_path = (audit_root / "audit.jsonl").as_posix()
    can_manage_writer = can_mutate(ctx, "can_manage_audit")

    writer_on = bool(st.session_state.get("_radt_audit_writer", False))
    audit_path = str(st.session_state.get("_radt_audit_path", default_audit_path))
    if section_visible(config, "audit_writer"):
        st.divider()
        st.subheader("Audit Logging")
        writer_on = st.toggle(
            "Write audit to JSONL",
            key="_radt_audit_writer",
            help="Writes audit events to disk in a background thread.",
            disabled=not can_manage_writer,
        )
        audit_path = st.text_input(
            "Audit file path",
            key="_radt_audit_path",
            disabled=not can_manage_writer,
            **({"value": audit_path} if "_radt_audit_path" not in st.session_state else {}),
        )
    lifecycle_error: dict[str, str] = {}
    startup_error: dict[str, str] = {}
    try:
        if can_mutate(ctx, "can_manage_audit"):
            if writer_on and audit_path.strip():
                try:
                    safe_path = safe_store_write_path(Path(audit_path.strip()), root_dir=audit_root)
                except (OSError, ValueError, StorePathSecurityError):
                    st.error(
                        "Audit file path must stay within configured audit directory. "
                        + diagnostic_text("RADT-AUDIT-IO")
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
        if len(error_type) > 80 or not error_type.isidentifier():
            error_type = "Error"
        # Writer exception messages may contain paths or credentials. The fixed
        # diagnostic describes uncertain persistence without echoing that data.
        st.error(f"Audit writer error ({error_type}): " + diagnostic_text("RADT-AUDIT-IO"))


__all__ = ["SidebarResult", "render_sidebar"]
