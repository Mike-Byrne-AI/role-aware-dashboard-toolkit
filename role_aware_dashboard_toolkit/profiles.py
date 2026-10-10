from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .controls import ControlRegistry
from .sensitive_values import is_sensitive_name
from .validators_parts.common import record_shape_errors
from .profile_store import (
    DEFAULT_PROFILE_DIR,
    PROFILE_SCHEMA_VERSION,
    BaseProfileStore,
    FileProfileStore,
)


_DEFAULT_APP_NAME = "role_aware_dashboard_toolkit"


class _InvalidProfileError(ValueError):
    """A stored profile failed the restore contract; details contain no values."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("Stored profile fields are invalid.")


def _require_profile_shape(profile: Any) -> None:
    # Older native profiles may lack today's schema/provenance metadata. Validate
    # fields that are present, without inventing or requiring historical metadata.
    legacy_nullable = {"values", "control_meta", "diff_from_parent", "extra"}
    checked = (
        {key: value for key, value in profile.items()
         if key not in legacy_nullable or value is not None}
        if isinstance(profile, dict) else profile
    )
    errors = record_shape_errors("profile", checked)
    if errors:
        raise _InvalidProfileError(errors)



def build_profile(
    profile_id: str,
    registry: ControlRegistry,
    session_state: dict[str, Any],
    *,
    role: str = "",
    extra: dict[str, Any] | None = None,
    parent_profile_id: str = "",
    parent_values: dict[str, Any] | None = None,
    app_name: str = _DEFAULT_APP_NAME,
    app_version: str = "",
    session_id: str = "",
    source: str = "ui",
) -> dict[str, Any]:
    """Build a detached serializable snapshot of state and profile metadata."""
    values = registry.persistable_snapshot(session_state)
    safe_parent_values = registry.filter_persistable_values(parent_values or {})
    diff_from_parent = profile_diff(safe_parent_values, values) if parent_profile_id else {}
    return deepcopy({
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_id": profile_id,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "role": role,
        "parent_profile_id": parent_profile_id,
        "values": values,
        "diff_from_parent": diff_from_parent,
        "control_meta": registry.export_metadata(),
        "app_name": str(app_name or _DEFAULT_APP_NAME),
        "app_version": str(app_version or ""),
        "session_id": str(session_id or ""),
        "source": str(source or "ui"),
        "extra": registry.filter_persistable_values(extra or {}),
    })


def save_profile(
    profile_id: str,
    registry: ControlRegistry,
    session_state: dict[str, Any],
    *,
    role: str = "",
    extra: dict[str, Any] | None = None,
    profile_dir: str = DEFAULT_PROFILE_DIR,
    parent_profile_id: str = "",
    parent_values: dict[str, Any] | None = None,
    store: BaseProfileStore | None = None,
    app_name: str = _DEFAULT_APP_NAME,
    app_version: str = "",
    session_id: str = "",
    source: str = "ui",
) -> str:
    """Save the current dashboard state as a named profile."""
    profile = build_profile(
        profile_id,
        registry,
        session_state,
        role=role,
        extra=extra,
        parent_profile_id=parent_profile_id,
        parent_values=parent_values,
        app_name=app_name,
        app_version=app_version,
        session_id=session_id,
        source=source,
    )
    return _resolve_store(store=store, profile_dir=profile_dir).save(profile)


def load_profile(
    profile_id: str,
    registry: ControlRegistry,
    session_state: dict[str, Any],
    *,
    profile_dir: str = DEFAULT_PROFILE_DIR,
    store: BaseProfileStore | None = None,
) -> dict[str, Any] | None:
    """Load a profile and restore its values into session state."""
    data = _resolve_store(store=store, profile_dir=profile_dir).load(profile_id)
    if data is None:
        return None
    return _restore_profile_data(data, registry, session_state)


def _restore_profile_data(
    data: dict[str, Any], registry: ControlRegistry, session_state: dict[str, Any],
) -> dict[str, Any]:
    """Stage a detached profile after the caller has selected its trust boundary."""
    _require_profile_shape(data)
    data = deepcopy(data)
    values = registry.filter_persistable_values(data.get("values", {}))
    data["values"] = values
    data["diff_from_parent"] = registry.filter_persistable_values(data.get("diff_from_parent", {}))
    data["control_meta"] = registry.export_metadata()
    data["extra"] = registry.filter_persistable_values(data.get("extra", {}))
    staged = dict(session_state)
    corrected = registry.restore(staged, values, include_sensitive=False)
    # Validation and sanitation complete before committing any live control.
    for key in registry.keys():
        session_state[key] = staged[key]
    data["corrected_values"] = int(corrected)
    return data


def _historical_sensitive_keys(metadata: Any) -> set[str]:
    return {
        item.get("key") for item in (metadata if isinstance(metadata, list) else [])
        if isinstance(item, dict) and item.get("sensitive")
        and isinstance(item.get("key"), str)
    }


def _contains_secret_fields(value: Any) -> bool:
    pending = [value]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if not isinstance(item, (dict, list, tuple)) or id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, dict):
            if any(is_sensitive_name(key) for key in item):
                return True
            pending.extend(item.values())
        else:
            pending.extend(item)
    return False


def _public_profile_values(
    registry: ControlRegistry, values: dict[str, Any] | None, metadata: Any = None,
    *, known_only: bool = True,
) -> dict[str, Any]:
    """Project browser-bound profile values before coercion erases secret keys.

    Native loading retains safe unknown fields for its existing feedback; the
    HTTP boundary exposes registered controls only. Neither projection edits
    stored evidence or changes the host-controlled core restore contract.
    """
    historical_sensitive = _historical_sensitive_keys(metadata)
    candidates = values or {}
    if not known_only:
        candidates = registry.filter_persistable_values(candidates)
    return {
        key: value for key, value in candidates.items()
        if ((control := registry.get(key)) is not None and not control.sensitive
            or not known_only and control is None)
        and key not in historical_sensitive and not _contains_secret_fields(value)
    }


def _load_ui_profile(
    profile_id: str, registry: ControlRegistry, session_state: dict[str, Any],
    *, profile_dir: str = DEFAULT_PROFILE_DIR, store: BaseProfileStore | None = None,
) -> dict[str, Any] | None:
    data = load_profile_data(profile_id, profile_dir=profile_dir, store=store)
    if data is None:
        return None
    _require_profile_shape(data)
    safe_data = {**data, "values": _public_profile_values(
        registry, data.get("values"), data.get("control_meta"), known_only=False,
    )}
    return _restore_profile_data(safe_data, registry, session_state)


def list_profiles(profile_dir: str = DEFAULT_PROFILE_DIR, *, store: BaseProfileStore | None = None) -> list[str]:
    return _resolve_store(store=store, profile_dir=profile_dir).list_ids()


def delete_profile(profile_id: str, *, profile_dir: str = DEFAULT_PROFILE_DIR, store: BaseProfileStore | None = None) -> bool:
    return _resolve_store(store=store, profile_dir=profile_dir).delete(profile_id)


def load_profile_data(profile_id: str, *, profile_dir: str = DEFAULT_PROFILE_DIR, store: BaseProfileStore | None = None) -> dict[str, Any] | None:
    return _resolve_store(store=store, profile_dir=profile_dir).load(profile_id)


def profile_diff(base_values: dict[str, Any], new_values: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Report changed values and key additions/removals in the existing shape.

    A missing side is represented by None. A null-valued key added or removed
    therefore has both values set to None; consult the source mappings for its
    direction. A key present with None on both sides is unchanged.
    """
    diff: dict[str, dict[str, Any]] = {}
    keys = set(base_values.keys()) | set(new_values.keys())
    for key in sorted(keys):
        old = base_values.get(key)
        new = new_values.get(key)
        if key not in base_values or key not in new_values or old != new:
            diff[key] = {"from": old, "to": new}
    return diff


def merge_profile_values(base_values: dict[str, Any], override_values: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base_values)
    merged.update(dict(override_values or {}))
    return merged


def _resolve_store(*, store: BaseProfileStore | None, profile_dir: str) -> BaseProfileStore:
    return store if store is not None else FileProfileStore(profile_dir)


__all__ = [
    "DEFAULT_PROFILE_DIR",
    "PROFILE_SCHEMA_VERSION",
    "build_profile",
    "delete_profile",
    "list_profiles",
    "load_profile",
    "load_profile_data",
    "merge_profile_values",
    "profile_diff",
    "save_profile",
]
