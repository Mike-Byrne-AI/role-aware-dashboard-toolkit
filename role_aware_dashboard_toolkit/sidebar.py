from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._profile_preview import InvalidProfilePreviewValues, build_profile_restore_preview
from ._ui_state import apply_pending_replay, remember_authorized_control_values
from .profile_store import FileProfileStore
from .diagnostics import build_diagnostic, diagnostic_text
from .audit import _get_writer_shutdown_error, _get_writer_startup_error, _ui_attribution
from .path_redaction import redact_text_local_paths
from .plugins import PluginErrorRecord
from .profiles import (
    _InvalidProfileError, _load_ui_profile, _public_profile_values, _require_profile_shape, delete_profile, list_profiles,
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
    has_perm,
    make_security_context,
)
from .store_diagnostics import StorePathSecurityError, safe_store_write_path, store_read_error_total


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



def _least_privileged_role(all_roles: list[str], custom_roles: Any) -> str:
    """The demo session's starting role: the fewest granted permissions.

    Ties keep declaration order (built-ins first). Built-in roles start as
    Viewer; a host's custom role with fewer grants starts instead.
    """
    if not all_roles:
        return "Viewer"

    def granted(name: str) -> int:
        role = get_role(name, custom_roles)
        perms = role.perms if role is not None and isinstance(role.perms, dict) else {}
        return sum(1 for value in perms.values() if value is True)

    return min(all_roles, key=granted)


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

        default_role = _least_privileged_role(all_roles, config.custom_roles)
        current_role = st.session_state.get("_radt_role", default_role)
        if current_role not in all_roles and all_roles:
            current_role = default_role
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

        role_def = get_role(new_role, config.custom_roles)
        perms = dict(role_def.perms) if role_def else {}
        can_manage_freeze = has_perm(make_security_context(new_role, perms), "can_manage_freeze")
        requested_writable = bool(st.session_state.get("_radt_writable", True))
        previous_writable = bool(st.session_state.get("_radt_previous_writable", requested_writable))
        if requested_writable != previous_writable and not can_manage_freeze:
            # A disabled toggle cannot send a change; refuse a forged one.
            st.session_state["_radt_writable"] = previous_writable
        writable = st.toggle(
            "Controls Writable",
            key="_radt_writable",
            help="OFF freezes all controls at their current values."
            + ("" if can_manage_freeze else " Changing it requires permission to manage the freeze."),
            disabled=not can_manage_freeze,
            **({"value": True} if "_radt_writable" not in st.session_state else {}),
        )
        if writable != previous_writable:
            audit.log_freeze(writable, role=new_role)
        st.session_state["_radt_previous_writable"] = writable

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


class _ProfileAccessDenied(Exception):
    """Stop a profile render when its live metadata permission is lost."""


def _profile_metadata_allowed(ctx: SecurityContext) -> bool:
    # Preserve the legacy demo menu. In authenticated mode, profile managers
    # need names/metadata for parent selection, replacement and deletion even
    # when they cannot load values. Neither grant means no profile-store reads.
    if ctx.role == "Unauthenticated":
        return False
    if not ctx.authenticated:
        return True
    return has_perm(ctx, "can_load_profiles") or has_perm(ctx, "can_save_profiles")


def _require_profile_metadata(ctx: SecurityContext) -> None:
    if not _profile_metadata_allowed(ctx):
        raise _ProfileAccessDenied()


def _clear_profile_state(st: Any) -> None:
    for key in list(st.session_state):
        if str(key).startswith("_radt_profile_") or key in {
            "_radt_active_profile_id", "_radt_selected_profile_id", "_radt_last_profile_id",
        }:
            del st.session_state[key]


def _profile_store_call(operation: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return operation(*args, **kwargs)
    except (OSError, StorePathSecurityError, _InvalidProfileError) as exc:
        raise _ProfileStorageFailure(type(exc).__name__) from None


def _profile_read(ctx: SecurityContext, operation: Any, *args: Any, **kwargs: Any) -> Any:
    _require_profile_metadata(ctx)
    try:
        return _profile_store_call(operation, *args, **kwargs)
    finally:
        # A store callback can take time; never publish data returned after
        # the profile grant was removed while that read was in flight.
        _require_profile_metadata(ctx)


def _render_profiles(st: Any, config: Any, ctx: SecurityContext, all_roles: list[str]) -> None:
    if not _profile_metadata_allowed(ctx):
        _clear_profile_state(st)
        return
    profile_store = getattr(config, "profile_store", None)
    region = st.empty() if ctx.authenticated else None
    try:
        if profile_store is None:
            profile_store = _profile_read(ctx, FileProfileStore, config.profile_dir)
        if region is not None:
            with region.container():
                _render_profile_controls(st, config, ctx, profile_store)
        else:
            _render_profile_controls(st, config, ctx, profile_store)
        _require_profile_metadata(ctx)
    except _ProfileAccessDenied:
        _clear_profile_state(st)
        if region is not None:
            region.empty()
        return
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
    _require_profile_metadata(ctx)
    st.divider()
    st.subheader("Profiles")
    profiles = _profile_read(ctx, list_profiles, config.profile_dir, store=profile_store)
    selected_profile = st.session_state.get("_radt_profile_choice")
    if selected_profile not in profiles:
        selected_profile = None
        st.session_state["_radt_profile_choice"] = selected_profile
    selected_profile_valid = True
    if selected_profile is not None:
        selected_data = _profile_read(
            ctx, load_profile_data, selected_profile, profile_dir=config.profile_dir, store=profile_store,
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
            profiles = _profile_read(ctx, list_profiles, config.profile_dir, store=profile_store)
    finally:
        # A failed store operation or denied load must still render these keyed
        # inputs, so Streamlit does not remove the operator's selection/name.
        _require_profile_metadata(ctx)
        with inputs:
            # None cannot collide with a store's string identifiers. Keep an
            # actual profile named '(none)' selectable and distinguish its label.
            profile_options = [None, *profiles]
            current_choice = st.session_state.get("_radt_profile_choice")
            st.session_state["_radt_profile_choice"] = (
                current_choice if current_choice in profile_options else None
            )
            selected_profile = st.selectbox(
                "Load profile", options=profile_options, key="_radt_profile_choice",
                format_func=lambda value: (
                    "(none)" if value is None else
                    "(none) (saved profile)" if value == "(none)" else value
                ),
            )
            st.text_input(
                "Profile name", key="_radt_profile_name",
                **({"value": "my_profile"} if "_radt_profile_name" not in st.session_state else {}),
                disabled=not can_mutate(ctx, "can_save_profiles"),
                help="Name for saving the current settings. Replacing an existing profile requires confirmation.",
            )

    with inputs:
        if selected_profile is not None:
            loaded = _profile_read(ctx, load_profile_data, selected_profile, profile_dir=config.profile_dir, store=profile_store)
            if loaded:
                try:
                    _require_profile_shape(loaded)
                except _InvalidProfileError:
                    st.warning("Profile preview is unavailable: saved values are invalid.")
                    return
                _require_profile_metadata(ctx)
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
    _require_profile_metadata(ctx)
    with st.expander("Preview profile changes", expanded=False):
        if preview.blocked_reasons:
            st.warning("Load is blocked; no values will change. " + " ".join(preview.blocked_reasons))
        # Preview construction checks other live permissions while staging its
        # rows. Its earlier visibility result is not authority to publish them.
        if (preview.values_visible and has_perm(ctx, "can_view_metrics")
                and has_perm(ctx, "can_load_profiles")):
            st.caption("Effective values show the proposed result after correction. Load rechecks permissions.")
            if preview.rows:
                st.dataframe(preview.rows, width="stretch", hide_index=True)
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
                     name: str, selected_profile: str | None) -> bool:
    parent_id = selected_profile if selected_profile is not None else ""
    parent = _profile_read(
        ctx, load_profile_data, parent_id, profile_dir=config.profile_dir, store=store,
    ) if parent_id else None
    if parent is not None:
        _profile_store_call(_require_profile_shape, parent)
    # Native saves must not copy fields hidden by the selected parent's preview
    # into a new durable diff. Keep the trusted core builder's contract intact.
    parent_values = _public_profile_values(
        config.registry, (parent or {}).get("values"),
        (parent or {}).get("control_meta"), known_only=False,
    )
    if not can_mutate(ctx, "can_save_profiles"):
        st.warning("Save denied. Your permission or the shared freeze changed.")
        return False
    _profile_store_call(
        save_profile, name, config.registry, st.session_state, role=ctx.role,
        profile_dir=config.profile_dir, store=store, parent_profile_id=parent_id,
        parent_values=parent_values, app_name=config.title,
        app_version=getattr(config, "version", ""),
        session_id=str(st.session_state.get("_radt_session_id", "")), source="ui",
    )
    config.audit.log_profile_save(name, role=ctx.role)
    st.toast(f"Saved profile: {name}")
    return True


def _read_profile_save_target(config: Any, ctx: SecurityContext, store: Any, name: str,
                              known_profiles: list[str]) -> dict | None:
    errors_before = store_read_error_total(store)
    saved = _profile_read(
        ctx, load_profile_data, name, profile_dir=config.profile_dir, store=store,
    )
    if saved is None and (
        name in known_profiles or store_read_error_total(store) > errors_before
    ):
        # An unreadable/disappearing record is not permission to overwrite it.
        raise _ProfileStorageFailure("UnreadableProfile")
    if saved is not None:
        _profile_store_call(_require_profile_shape, saved)
    return saved


def _render_profile_save(st: Any, config: Any, ctx: SecurityContext, store: Any,
                         selected_profile: str | None, selected_profile_valid: bool,
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
            saved = _read_profile_save_target(config, ctx, store, name, known_profiles)
            if saved is None:
                return _save_ui_profile(st, config, ctx, store, name, selected_profile)
            pending = {"intent": deepcopy(intent), "saved": deepcopy(saved)}
            st.session_state[_PROFILE_REPLACE_PENDING] = pending
    if pending is None:
        return False
    _require_profile_metadata(ctx)
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
            saved = _read_profile_save_target(config, ctx, store, name, known_profiles)
            if saved != pending["saved"]:
                st.warning("The saved profile changed. Nothing was replaced; choose Save to review it again.")
                return False
            return _save_ui_profile(st, config, ctx, store, name, selected_profile)
        finally:
            confirmation.empty()
    return False


def _render_profile_actions(
    st: Any, config: Any, ctx: SecurityContext, profile_store: Any, selected_profile: str | None,
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
        choice = st.session_state.get("_radt_profile_choice")
        if choice is not None:
            staged_state = dict(st.session_state)
            result = _profile_read(ctx, _load_ui_profile, choice, reg, staged_state, profile_dir=config.profile_dir, store=profile_store)
            if not can_write(ctx, "can_load_profiles"):
                st.warning("Load denied. Your permission or the shared freeze changed.")
                return profiles_changed
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
        choice = st.session_state.get("_radt_profile_choice")
        if choice is not None:
            if _profile_store_call(delete_profile, choice, profile_dir=config.profile_dir, store=profile_store):
                audit.log("profile_delete", detail=choice, role=ctx.role)
                st.toast(f"Deleted profile: {choice}")
                profiles_changed = True
            else:
                st.warning(f"Could not delete '{choice}'.")
    return profiles_changed



_AUDIT_WRITER_KEY = "_radt_audit_writer"
_AUDIT_PATH_KEY = "_radt_audit_path"
# What this session's form showed after its last render. A toggle or path that
# differs from it was changed by the operator; anything else is not a request.
_AUDIT_WRITER_SEEN_KEY = "_radt_audit_writer_seen"
_AUDIT_PATH_SEEN_KEY = "_radt_audit_path_seen"


def _render_audit_writer_controls(st: Any, config: Any, ctx: SecurityContext) -> None:
    """Show the writer's live state; change it only on an explicit request.

    A render never starts or stops the writer by itself: not when the form is
    hidden, not for a role that cannot manage it, and not because this
    session's widget holds a stale value while another session (or the host)
    changed the shared writer.
    """
    audit = config.audit
    audit_root = Path(getattr(config, "audit_dir", "audit_logs"))
    default_audit_path = (audit_root / "audit.jsonl").as_posix()
    lifecycle_error: dict[str, str] = {}
    startup_error: dict[str, str] = {}
    if section_visible(config, "audit_writer"):
        state = st.session_state
        live_active = bool(audit.writer_status().get("writer_active"))
        requested = state.get(_AUDIT_WRITER_KEY)
        seen = state.get(_AUDIT_WRITER_SEEN_KEY, live_active)
        audit_path = str(state.get(_AUDIT_PATH_KEY, default_audit_path))
        seen_path = str(state.get(_AUDIT_PATH_SEEN_KEY, audit_path))
        toggled = requested is not None and bool(requested) != bool(seen)
        wants_on = bool(requested) if toggled else live_active
        path_edited = wants_on and live_active and audit_path.strip() != seen_path.strip()
        try:
            if (toggled or path_edited) and can_mutate(ctx, "can_manage_audit"):
                attribution = _ui_attribution(audit, ctx)
                if not wants_on:
                    audit.stop_writer(**attribution)
                elif not audit_path.strip():
                    st.warning("Enter an audit file path.")
                else:
                    try:
                        safe_path = safe_store_write_path(Path(audit_path.strip()), root_dir=audit_root)
                    except (OSError, ValueError, StorePathSecurityError):
                        # Refuse the change; a running writer keeps running.
                        st.error(
                            "Audit file path must stay within configured audit directory. "
                            + diagnostic_text("RADT-AUDIT-IO")
                        )
                    else:
                        try:
                            audit.start_writer(str(safe_path), **attribution)
                        except Exception as exc:
                            startup_error = _get_writer_startup_error(exc)
                            if not startup_error:
                                raise
        except TimeoutError as exc:
            lifecycle_error = _get_writer_shutdown_error(exc)
            if not lifecycle_error:
                raise

        # Every role sees the live state, not what this session last chose.
        # A failed start leaves ownership uncertain, so do not probe it.
        live_status = {} if startup_error else audit.writer_status()
        live_active = bool(live_status.get("writer_active"))
        state[_AUDIT_WRITER_KEY] = live_active
        state[_AUDIT_WRITER_SEEN_KEY] = live_active
        state[_AUDIT_PATH_SEEN_KEY] = audit_path
        can_manage_writer = can_mutate(ctx, "can_manage_audit")
        st.divider()
        st.subheader("Audit Logging")
        st.toggle(
            "Write audit to JSONL",
            key=_AUDIT_WRITER_KEY,
            help="Writes audit events to disk in a background thread. Shows the live writer state.",
            disabled=not can_manage_writer,
        )
        st.text_input(
            "Audit file path",
            key=_AUDIT_PATH_KEY,
            disabled=not can_manage_writer,
            **({"value": audit_path} if _AUDIT_PATH_KEY not in state else {}),
        )
        live_path = str(live_status.get("writer_path") or "")
        if live_active and live_path != str(Path(audit_path.strip())):
            st.caption("The writer is running on a different file than the path shown.")

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
