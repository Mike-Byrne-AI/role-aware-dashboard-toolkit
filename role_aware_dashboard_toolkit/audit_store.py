from __future__ import annotations

import copy
import json
import os
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

from ._json_safety import sanitize_non_finite_numbers, strict_json_loads
from .path_redaction import (
    _FilesystemTextCache,
    _filesystem_text,
    redact_diagnostic_path,
    redact_payload_local_paths,
)
from .sensitive_values import REDACTED_SECRET, is_sensitive_name
from .store_diagnostics import (
    StoreReadDiagnosticsMixin,
    append_text_record,
    build_read_error,
    read_text_record,
)

AUDIT_EVENT_SCHEMA_VERSION = 1
_AUDIT_EVENT_FIELD_KEYS = frozenset(
    {
        "app_name",
        "app_version",
        "detail",
        "key",
        "new",
        "old",
        "role",
        "schema_version",
        "session_id",
        "source",
        "ts",
        "type",
        "user_id",
    }
)
_REDACTED_LOCAL_PATH = "<redacted-local-path>"


class BaseAuditStore:
    """Storage adapter for Role-Aware Dashboard Toolkit audit events."""

    def append(self, event: dict[str, Any]) -> None:
        raise NotImplementedError

    def append_many(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            self.append(event)

    def read_all(self) -> list[dict[str, Any]]:
        raise NotImplementedError


def redact_audit_event(
    event: Mapping[Any, Any], *, declared_public_keys: Collection[str] = (),
) -> dict[str, Any]:
    """Return a redacted copy of an audit event.

    A ``control_change`` event's old and new values are redacted when its key
    looks secret, unless the key is in ``declared_public_keys``: controls the
    host declared not secret through ``AuditLog.log_control_change(...,
    sensitive=False)``. The declaration is never read from the event itself.
    Secret-named fields nested in a value are redacted either way.
    """
    filesystem_text_cache: _FilesystemTextCache = {}
    prepared, event_type, control_key, control_key_readable = _audit_context(
        event, cache=filesystem_text_cache
    )
    sanitized = redact_payload_local_paths(
        prepared,
        repo_root="",
        _mapping_value_transform=_redact_sensitive_mapping_value,
        _reserved_top_level_keys=_AUDIT_EVENT_FIELD_KEYS,
        _filesystem_text_cache=filesystem_text_cache,
    )
    if not isinstance(sanitized, dict):
        return {}
    # A control the host declared not secret keeps its values even when its
    # key looks secret; nested secret fields were redacted above.
    declared_public = control_key_readable and control_key in declared_public_keys
    if event_type == "control_change" and not declared_public and (
        not control_key_readable or is_sensitive_name(control_key)
    ):
        sanitized["old"] = REDACTED_SECRET
        sanitized["new"] = REDACTED_SECRET
    return sanitize_non_finite_numbers(sanitized)


def _redact_sensitive_mapping_value(
    key_text: str,
    key_readable: bool,
    value: Any,
) -> Any:
    if not key_readable or is_sensitive_name(key_text):
        return REDACTED_SECRET
    return value


def _audit_field_text(
    value: Any,
    *,
    cache: _FilesystemTextCache,
) -> tuple[str, bool]:
    if isinstance(value, os.PathLike):
        rendered = _filesystem_text(value, cache=cache)
        return (
            (rendered, True)
            if rendered is not None
            else (_REDACTED_LOCAL_PATH, False)
        )
    if isinstance(value, str):
        return str.__str__(value), True
    return str(value or ""), True


def _audit_context(
    event: Mapping[Any, Any],
    *,
    cache: _FilesystemTextCache,
) -> tuple[Mapping[Any, Any], str, str, bool]:
    raw_event_type = event.get("type")
    raw_control_key = event.get("key")
    event_type, _ = _audit_field_text(raw_event_type, cache=cache)
    control_key, control_key_readable = _audit_field_text(raw_control_key, cache=cache)
    overrides: dict[str, str] = {}
    if isinstance(raw_event_type, os.PathLike):
        overrides["type"] = event_type
    if isinstance(raw_control_key, os.PathLike):
        overrides["key"] = control_key
    if not overrides:
        return event, event_type.strip().lower(), control_key, control_key_readable
    prepared = dict(event)
    prepared.update(overrides)
    return prepared, event_type.strip().lower(), control_key, control_key_readable


class FileAuditStore(StoreReadDiagnosticsMixin, BaseAuditStore):
    def __init__(self, path: str) -> None:
        self._init_read_diagnostics()
        self.path = path
        # Set by the AuditLog that owns this writer store: the control keys
        # its host declared not secret.
        self._declared_public_keys: Collection[str] = ()

    def append(self, event: dict[str, Any]) -> None:
        sanitized = redact_audit_event(event, declared_public_keys=self._declared_public_keys)
        path = Path(self.path)
        rendered = (
            json.dumps(sanitized, ensure_ascii=False, default=str, allow_nan=False) + "\n"
        )
        append_text_record(path, rendered, root_dir=path.parent)

    def read_all(self) -> list[dict[str, Any]]:
        path = Path(self.path)
        rendered = read_text_record(path, self._read_errors, root_dir=path.parent)
        if rendered is None:
            return []
        rows: list[dict[str, Any]] = []
        # JSONL records end at LF; Unicode line separators can occur in strings.
        for line_number, line in enumerate(rendered.split("\n"), start=1):
            if not line.strip():
                continue
            try:
                loaded = strict_json_loads(line)
            except (ValueError, RecursionError) as exc:
                self._read_errors.append(
                    build_read_error(path, exc, message=f"line {line_number}: {exc}")
                )
                continue
            if not isinstance(loaded, dict):
                self._read_errors.append(
                    {
                        "path": redact_diagnostic_path(path, repo_root=str(path.parent)),
                        "error_type": type(loaded).__name__,
                        "exception_type": type(loaded).__name__,
                        "message": f"line {line_number}: JSONL audit event must be an object",
                    }
                )
                continue
            rows.append(loaded)
        return rows


class InMemoryAuditStore(BaseAuditStore):
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def append(self, event: dict[str, Any]) -> None:
        sanitized = redact_audit_event(event)
        self._events.append(_json_sanitized_copy(sanitized))

    def read_all(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._events)


def _json_sanitized_copy(value: Any) -> dict[str, Any]:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        default=str,
        allow_nan=False,
    )
    return strict_json_loads(rendered)


__all__ = [
    "AUDIT_EVENT_SCHEMA_VERSION",
    "BaseAuditStore",
    "FileAuditStore",
    "InMemoryAuditStore",
    "redact_audit_event",
]
