"""Detached secret-safe views for native UI and HTTP record boundaries.

Stored evidence and public record builders retain their original contracts.
Permission checks belong to the caller; a read grant never disables redaction.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .sensitive_values import REDACTED_SECRET, is_sensitive_name


_CONTROL_MAPS = frozenset({
    "controls", "initial_controls", "latest_controls", "preview_state",
    "control_diff", "diff_from_parent", "values", "restore_controls",
})


def _historical_keys(value: Any) -> set[str]:
    """Collect flags before transforms or comparisons discard their metadata."""
    pending = [value]
    seen: set[int] = set()
    keys: set[str] = set()
    while pending:
        item = pending.pop()
        if not isinstance(item, (Mapping, list, tuple)) or id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, Mapping):
            metadata = item.get("control_meta")
            if isinstance(metadata, (list, tuple)):
                keys.update(
                    field["key"] for field in metadata
                    if isinstance(field, Mapping) and field.get("sensitive")
                    and isinstance(field.get("key"), str)
                )
            pending.extend(item.values())
        else:
            pending.extend(item)
    return keys


def project_record(
    value: Any, registry: Any = None, *, include_control_metadata_values: bool = True,
) -> Any:
    """Conceal secrets in a detached browser/API-bound record or collection.

    Current and recorded sensitivity apply to control maps, audit old/new values,
    observability summaries and metadata defaults. Nested secret-named fields
    are redacted before text coercion. Explicit public controls such as a token
    count retain their values in control maps; this does not exempt nested fields.
    Unknown values do not become trusted merely because the registry is absent.
    Callers without control-value read authority also omit metadata defaults and
    choices; those fields contain values even when the control is not sensitive.
    """
    controls = registry.all() if registry is not None else ()
    sensitive = {control.key for control in controls if control.sensitive}
    public = {control.key for control in controls if not control.sensitive}
    sensitive.update(_historical_keys(value))
    active: set[int] = set()

    def hidden_control(key: Any) -> bool:
        return isinstance(key, str) and (
            key in sensitive or key not in public and is_sensitive_name(key)
        )

    def visit(
        item: Any, *, control_map: bool = False, metric_map: bool = False, depth: int = 0,
    ) -> Any:
        if not isinstance(item, (Mapping, list, tuple)):
            return deepcopy(item)
        if id(item) in active or depth >= 100:
            # Malformed cyclic/deep records must not bypass output projection.
            return REDACTED_SECRET
        active.add(id(item))
        try:
            if not isinstance(item, Mapping):
                projected = [visit(child, depth=depth + 1) for child in item]
                return tuple(projected) if isinstance(item, tuple) else projected
            # Malformed/legacy events may rename or normalize their type. The
            # keyed old/new value shape carries the confidentiality obligation.
            audit_secret = ("old" in item or "new" in item) and hidden_control(item.get("key"))
            summary_secret = "new" in item and hidden_control(item.get("control"))
            metadata_secret = "key" in item and (
                item.get("sensitive") or hidden_control(item.get("key"))
            )
            # Telemetry normalization retains both a dotted path and its leaf
            # alias. Conceal both before native summaries derive numeric values.
            private_metric_aliases = {
                str(key).rsplit(".", 1)[-1] for key in item
                if metric_map and "." in str(key) and is_sensitive_name(str(key))
            }
            result = {}
            for key, child in item.items():
                name = str(key)
                if not include_control_metadata_values and "key" in item and name in {"default", "options"}:
                    continue
                hide = (
                    control_map and name in sensitive
                    or is_sensitive_name(name) and not (control_map and name in public)
                    or (audit_secret or summary_secret) and name in {"old", "new"}
                    or metadata_secret and name in {"default", "options"}
                    or name in private_metric_aliases
                )
                result[key] = REDACTED_SECRET if hide else visit(
                    child, control_map=name in _CONTROL_MAPS,
                    metric_map=name in {"metrics", "latest"}, depth=depth + 1,
                )
            return result
        finally:
            active.remove(id(item))

    return visit(value)


def project_audit_events(events: Any, registry: Any = None) -> list[Any]:
    """Return an independently projected audit collection for a permitted read."""
    return project_record(list(events), registry)


def preserve_sensitivity_metadata(record: dict, *sources: Any) -> dict:
    """Detach a native derived record and retain source confidentiality flags.

    Carry only the minimum classification metadata, never source defaults or
    options. Public builders and persisted source records remain unchanged.
    """
    view = deepcopy(record)
    keys = _historical_keys([record, *sources])
    if keys:
        view["control_meta"] = [{"key": key, "sensitive": True} for key in sorted(keys)]
    return view
