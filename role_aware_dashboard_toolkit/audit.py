from __future__ import annotations

import atexit
import copy
import functools
import json
import logging
import queue
import threading
import weakref
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from ._json_safety import sanitize_non_finite_numbers
from .diagnostics import diagnostic_text
from .path_redaction import redact_payload_local_paths
from .audit_store import (
    AUDIT_EVENT_SCHEMA_VERSION,
    BaseAuditStore,
    FileAuditStore,
    redact_audit_event,
)
from .sensitive_values import REDACTED_SECRET

_WRITER_SHUTDOWN_ERROR_ATTR = "role_aware_dashboard_toolkit_audit_writer_shutdown_error"
_WRITER_STARTUP_ERROR_ATTR = "role_aware_dashboard_toolkit_audit_writer_startup_error"
_WRITER_SHUTDOWN_ERROR_TOKEN = object()
_WRITER_STARTUP_ERROR_TOKEN = object()
_LOGGER = logging.getLogger(__name__)
_WRITER_STOP_TIMEOUT_SECONDS = 3.0


def _safe_writer_error_message(exc: Exception) -> str:
    # Third-party exceptions can contain credentials or have unsafe __str__ methods.
    # Status and logging share fixed guidance; callers retain the exception type.
    return diagnostic_text("RADT-AUDIT-IO")


def _get_writer_error(
    exc: Exception,
    *,
    attribute: str,
    phase: str,
    token: object,
) -> dict[str, str]:
    try:
        payload = getattr(exc, attribute, None)
        if (
            not isinstance(payload, tuple)
            or len(payload) != 2
            or payload[0] is not token
        ):
            return {}
        record = payload[1]
        expected_type = type(exc).__name__
        if (
            not isinstance(record, dict)
            or record.get("error_type") != expected_type
            or record.get("exception_type") != expected_type
            or not isinstance(record.get("message"), str)
        ):
            return {}
        return {
            "error_type": expected_type,
            "exception_type": expected_type,
            "message": record["message"],
        }
    except Exception as inspect_exc:
        _LOGGER.warning(
            "Audit writer %s diagnostic could not be inspected on %s; "
            "the original exception will be re-raised (%s: %s)",
            phase,
            type(exc).__name__,
            type(inspect_exc).__name__,
            _safe_writer_error_message(inspect_exc),
        )
        return {}


def _get_writer_shutdown_error(exc: Exception) -> dict[str, str]:
    return _get_writer_error(
        exc,
        attribute=_WRITER_SHUTDOWN_ERROR_ATTR,
        phase="shutdown",
        token=_WRITER_SHUTDOWN_ERROR_TOKEN,
    )


def _get_writer_startup_error(exc: Exception) -> dict[str, str]:
    return _get_writer_error(
        exc,
        attribute=_WRITER_STARTUP_ERROR_ATTR,
        phase="startup",
        token=_WRITER_STARTUP_ERROR_TOKEN,
    )


def _attach_writer_error(
    exc: Exception,
    record: dict[str, str],
    *,
    attribute: str,
    phase: str,
    token: object,
) -> None:
    try:
        setattr(exc, attribute, (token, dict(record)))
    except Exception as attach_exc:
        _LOGGER.warning(
            "Audit writer %s diagnostic could not be attached to %s; "
            "the original exception will be re-raised (%s: %s)",
            phase,
            type(exc).__name__,
            type(attach_exc).__name__,
            _safe_writer_error_message(attach_exc),
        )


def _attach_writer_shutdown_error(exc: Exception, record: dict[str, str]) -> None:
    _attach_writer_error(
        exc,
        record,
        attribute=_WRITER_SHUTDOWN_ERROR_ATTR,
        phase="shutdown",
        token=_WRITER_SHUTDOWN_ERROR_TOKEN,
    )


def _attach_writer_startup_error(exc: Exception, record: dict[str, str]) -> None:
    _attach_writer_error(
        exc,
        record,
        attribute=_WRITER_STARTUP_ERROR_ATTR,
        phase="startup",
        token=_WRITER_STARTUP_ERROR_TOKEN,
    )


def _make_event(
    event_type: str,
    *,
    key: str = "",
    old_value: Any = None,
    new_value: Any = None,
    role: str = "",
    detail: str = "",
    source: str = "ui",
    user_id: str = "",
    session_id: str = "",
    app_name: str = "role_aware_dashboard_toolkit",
    app_version: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "key": key,
        "old": old_value,
        "new": new_value,
        "role": role,
        "detail": detail,
        "source": str(source or "ui"),
        "user_id": str(user_id or ""),
        "session_id": str(session_id or ""),
        "app_name": str(app_name or "role_aware_dashboard_toolkit"),
        "app_version": str(app_version or ""),
    }


def _is_well_formed_audit_event(event: Any) -> bool:
    if (
        not isinstance(event, dict)
        or event.get("schema_version") != AUDIT_EVENT_SCHEMA_VERSION
    ):
        return False
    return all(
        str(event.get(field) or "").strip() for field in ("ts", "type", "source")
    )


def _run_writer_loop(
    owner_ref: Any,
    queue_ref: queue.Queue,
    store: BaseAuditStore,
    stop_event: threading.Event,
) -> None:
    """Persist queued events until stopped and drained.

    The loop holds only a weak reference to its ``AuditLog``, so a log the
    host drops can be collected; its finalizer then stops this thread.
    """
    while True:
        try:
            item = queue_ref.get(timeout=0.2)
        except queue.Empty:
            if stop_event.is_set():
                break
            continue
        try:
            store.append(item)
        except Exception as exc:
            owner = owner_ref()
            if owner is not None:
                owner._record_writer_error(exc)
            del owner


def _abandon_writer(stop_event: threading.Event, exit_hook: Any) -> None:
    """Finalizer for a collected ``AuditLog``: let its thread drain and exit."""
    stop_event.set()
    atexit.unregister(exit_hook)


def _drain_writer_at_exit(
    owner_ref: Any, writer_thread: threading.Thread, stop_event: threading.Event,
) -> None:
    """Bounded drain at interpreter exit for a writer nobody stopped."""
    owner = owner_ref()
    if owner is not None and owner._writer_lock.acquire(timeout=_WRITER_STOP_TIMEOUT_SECONDS):
        try:
            if owner._writer_thread is writer_thread:
                owner._stop_writer_locked(_lifecycle_attribution("", "atexit", "", ""))
        except Exception as exc:
            _LOGGER.warning(
                "Audit writer could not be drained at exit (%s: %s)",
                type(exc).__name__,
                _safe_writer_error_message(exc),
            )
        finally:
            owner._writer_lock.release()
        # A replaced writer is not this hook's to stop: the shared stop event
        # would end the current one.
        return
    del owner
    # The log is gone or its lock is held: stop this thread without recording.
    stop_event.set()
    writer_thread.join(timeout=_WRITER_STOP_TIMEOUT_SECONDS)


def _lifecycle_attribution(
    role: Any, source: Any, user_id: Any, session_id: Any,
) -> dict[str, str]:
    return {
        "role": str(role or ""),
        "source": str(source or "host"),
        "user_id": str(user_id or ""),
        "session_id": str(session_id or ""),
    }


def _ui_attribution(audit: Any, ctx: Any) -> dict[str, str]:
    """Attribute a dashboard-initiated audit lifecycle action.

    An identity-bound audit view pins its actor for ``log``; lifecycle methods
    delegate to the shared log, so pass the same actor explicitly.
    """
    authenticated = bool(getattr(ctx, "authenticated", False))
    attribution = {"role": str(getattr(ctx, "role", "") or ""), "source": "ui"}
    for field_name in ("user_id", "session_id"):
        pinned = getattr(audit, field_name, None)
        if not isinstance(pinned, str):
            pinned = getattr(ctx, field_name, "") if authenticated else ""
        attribution[field_name] = pinned if isinstance(pinned, str) else ""
    return attribution


def audit_event_view(event: Any) -> dict[str, Any]:
    """Return a display record without laundering malformed data into the current schema."""
    if _is_well_formed_audit_event(event):
        return dict(event)

    if isinstance(event, dict):
        record = dict(event)
        original_type = str(record.get("type") or "").strip()
        record.pop("schema_version", None)
        if original_type:
            record["original_type"] = original_type
        record["type"] = "malformed"
        record["source"] = "malformed_audit_event"
        record["malformed"] = True
        return record

    return {
        "type": "malformed",
        "detail": str(event),
        "source": "malformed_audit_event",
        "malformed": True,
    }


class AuditLog:
    """Audit events with a bounded in-memory view and an optional JSONL writer.

    The JSONL file is append-only. The in-memory view keeps the newest
    ``max_events`` and can be cleared; a clear records ``audit_cleared``.
    """

    def __init__(self, max_events: int = 500) -> None:
        self._events: list[Any] = []
        self._max: int = max(10, int(max_events))
        self._lock = threading.Lock()
        self._writer_lock = threading.Lock()
        self._writer_thread: threading.Thread | None = None
        self._writer_queue: queue.Queue | None = None
        self._writer_stop = threading.Event()
        self._writer_store: BaseAuditStore | None = None
        self._writer_path: str | None = None
        self._writer_exit_hook: Any = None
        self._writer_finalizer: weakref.finalize | None = None
        # A stop that timed out: its record, for the file once the thread ends.
        self._writer_stop_record: dict[str, Any] | None = None
        # Control keys the host declared not secret (log_control_change with
        # sensitive=False). Redaction takes them as an argument, never from an
        # event's own fields.
        self._declared_public_keys: set[str] = set()
        self.dropped: int = 0
        self._writer_error_count: int = 0
        self._last_writer_error: dict[str, str] = {}

    def log(
        self,
        event_type: str,
        *,
        key: str = "",
        old_value: Any = None,
        new_value: Any = None,
        role: str = "",
        detail: str = "",
        source: str = "ui",
        user_id: str = "",
        session_id: str = "",
        app_name: str = "role_aware_dashboard_toolkit",
        app_version: str = "",
    ) -> dict[str, Any]:
        evt = _make_event(
            event_type,
            key=key,
            old_value=old_value,
            new_value=new_value,
            role=role,
            detail=detail,
            source=source,
            user_id=user_id,
            session_id=session_id,
            app_name=app_name,
            app_version=app_version,
        )
        return self._store_event(redact_audit_event(evt), writer_locked=False)

    def _store_event(self, evt: dict[str, Any], *, writer_locked: bool) -> dict[str, Any]:
        stored_event = copy.deepcopy(evt)
        with self._lock:
            self._events.append(stored_event)
            if len(self._events) > self._max:
                self._events = self._events[-self._max :]

        if writer_locked:
            self._enqueue_locked(stored_event)
        else:
            with self._writer_lock:
                self._enqueue_locked(stored_event)

        return copy.deepcopy(stored_event)

    def _enqueue_locked(self, stored_event: dict[str, Any]) -> None:
        if self._writer_queue is not None and not self._writer_stop.is_set():
            try:
                self._writer_queue.put_nowait(copy.deepcopy(stored_event))
            except queue.Full:
                self.dropped += 1

    def _log_lifecycle_locked(
        self, event_type: str, path: str | None, attribution: Mapping[str, str],
    ) -> None:
        """Record a writer transition; the caller holds the writer lock."""
        evt = _make_event(event_type, detail=str(path or ""), **attribution)
        self._store_event(redact_audit_event(evt), writer_locked=True)

    def _writer_running_locked(self) -> bool:
        writer_thread = self._writer_thread
        return bool(
            writer_thread is not None
            and self._writer_queue is not None
            and not self._writer_stop.is_set()
            and writer_thread.is_alive()
        )

    def recent(self, n: int = 20) -> list[Any]:
        limit = max(0, int(n))
        if limit == 0:
            return []
        with self._lock:
            return copy.deepcopy(self._events[-limit:])

    def all_events(self) -> list[Any]:
        with self._lock:
            return copy.deepcopy(self._events)

    def clear(
        self,
        *,
        role: str = "",
        source: str = "host",
        user_id: str = "",
        session_id: str = "",
    ) -> int:
        """Empty the in-memory view and record an ``audit_cleared`` event.

        The record (``old`` = events cleared, ``new`` = 0) stays as the view's
        first entry and also goes to a running writer. The JSONL file is never
        truncated. Returns the number of events cleared.
        """
        attribution = _lifecycle_attribution(role, source, user_id, session_id)
        with self._writer_lock:
            with self._lock:
                cleared = len(self._events)
                self._events.clear()
            evt = _make_event(
                "audit_cleared",
                old_value=cleared,
                new_value=0,
                detail="in-memory audit history cleared",
                **attribution,
            )
            self._store_event(redact_audit_event(evt), writer_locked=True)
        return cleared

    def filter_events(
        self,
        *,
        event_types: list[str] | None = None,
        key: str = "",
        role: str = "",
        text: str = "",
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        events = self.all_events()
        types = set(event_types or [])
        key_lower = key.strip().lower()
        role_lower = role.strip().lower()
        text_lower = text.strip().lower()
        filtered: list[dict[str, Any]] = []
        for event in events:
            event_record = audit_event_view(event)
            if types and event_record.get("type") not in types:
                continue
            if key_lower and key_lower not in str(event_record.get("key", "")).lower():
                continue
            if (
                role_lower
                and role_lower not in str(event_record.get("role", "")).lower()
            ):
                continue
            if text_lower and not any(
                text_lower in str(value).lower() for value in event_record.values()
            ):
                continue
            filtered.append(event_record)
        if limit is not None:
            normalized_limit = max(0, int(limit))
            filtered = filtered[-normalized_limit:] if normalized_limit else []
        return filtered

    def replay_plan(self, *, limit: int = 20) -> dict[str, Any]:
        control_events = [
            event_record
            for event in self.recent(limit)
            if (event_record := audit_event_view(event)).get("type") == "control_change"
            and event_record.get("key")
        ]
        preview: dict[str, Any] = {}
        touched: list[str] = []
        for event in control_events:
            preview[event["key"]] = event.get("new")
            touched.append(event["key"])
        return {
            "event_count": len(control_events),
            "touched_keys": sorted(set(touched)),
            "preview_state": preview,
        }

    def export_jsonl(self, events: list[Any] | None = None) -> str:
        source = events if events is not None else self.all_events()
        sanitized = [
            sanitize_non_finite_numbers(
                redact_audit_event(event, declared_public_keys=self._declared_public_keys)
                if isinstance(event, Mapping)
                else redact_payload_local_paths({"event": event}, repo_root="")["event"]
            )
            for event in source
        ]
        return "\n".join(
            json.dumps(event, default=str, allow_nan=False) for event in sanitized
        )

    def log_control_change(
        self,
        key: str,
        old_value: Any,
        new_value: Any,
        *,
        role: str = "",
        source: str = "ui",
        sensitive: bool | None = None,
    ) -> None:
        """Record a control change.

        ``sensitive=True`` replaces both values with the redaction marker. By
        default (``None``) they are redacted when the key looks secret.
        ``sensitive=False`` declares the control not secret, as
        ``ControlRegistry.register(..., sensitive=False)`` does: this log then
        keeps its values even when the key looks secret, in the view, the
        writer's file and ``export_jsonl``. Secret-named fields nested in a
        value are redacted either way.
        """
        if sensitive is False:
            self._log_declared_public_change(
                key, old_value, new_value, role=role, source=source, user_id="", session_id="",
            )
            return
        if sensitive:
            old_value = REDACTED_SECRET
            new_value = REDACTED_SECRET
        self.log(
            "control_change",
            key=key,
            old_value=old_value,
            new_value=new_value,
            role=role,
            source=source,
        )

    def _log_declared_public_change(
        self, key: str, old_value: Any, new_value: Any, *,
        role: str, source: str, user_id: str, session_id: str,
    ) -> None:
        evt = _make_event(
            "control_change", key=key, old_value=old_value, new_value=new_value,
            role=role, source=source, user_id=user_id, session_id=session_id,
        )
        if isinstance(key, str):
            self._declared_public_keys.add(key)
        self._store_event(
            redact_audit_event(evt, declared_public_keys=self._declared_public_keys),
            writer_locked=False,
        )

    def log_profile_save(
        self, profile_id: str, *, role: str = "", source: str = "ui"
    ) -> None:
        self.log("profile_save", detail=profile_id, role=role, source=source)

    def log_profile_load(
        self, profile_id: str, *, role: str = "", source: str = "ui"
    ) -> None:
        self.log("profile_load", detail=profile_id, role=role, source=source)

    def log_role_switch(
        self, old_role: str, new_role: str, *, source: str = "ui"
    ) -> None:
        self.log("role_switch", old_value=old_role, new_value=new_role, source=source)

    def log_freeze(self, frozen: bool, *, role: str = "", source: str = "ui") -> None:
        self.log("freeze_toggle", new_value=frozen, role=role, source=source)

    def start_writer(
        self,
        path: str,
        *,
        queue_size: int = 1000,
        role: str = "",
        source: str = "host",
        user_id: str = "",
        session_id: str = "",
    ) -> bool:
        """Start (or move) the JSONL writer and record an ``audit_writer_start`` event.

        Calling it again for the running path is a no-op and records nothing.
        A different path stops the current writer first, recording its stop.
        """
        attribution = _lifecycle_attribution(role, source, user_id, session_id)
        with self._writer_lock:
            writer_thread = self._writer_thread
            if writer_thread is not None:
                if (
                    writer_thread.is_alive()
                    and self._writer_path == path
                    and not self._writer_stop.is_set()
                ):
                    return True
                self._stop_writer_locked(attribution)
            else:
                self._clear_writer_state_locked()

            with self._lock:
                self._writer_error_count = 0
                self._last_writer_error = {}

            try:
                writer_store = FileAuditStore(path)
                writer_store._declared_public_keys = self._declared_public_keys
                writer_queue = queue.Queue(maxsize=queue_size)
                writer_thread = threading.Thread(
                    target=_run_writer_loop,
                    args=(weakref.ref(self), writer_queue, writer_store, self._writer_stop),
                    name="radt-audit-writer",
                    daemon=True,
                )
            except Exception as exc:
                self._writer_stop.set()
                self._clear_writer_state_locked()
                self._record_writer_startup_error(exc)
                raise

            self._writer_path = path
            self._writer_store = writer_store
            self._writer_queue = writer_queue
            self._writer_thread = writer_thread
            self._writer_stop.clear()
            try:
                writer_thread.start()
            except Exception as exc:
                self._rollback_failed_writer_start_locked(writer_thread)
                self._record_writer_startup_error(exc)
                raise
            self._register_writer_shutdown_locked(writer_thread)
            # The first line this writer persists names who started it.
            self._log_lifecycle_locked("audit_writer_start", path, attribution)
            return True

    def _register_writer_shutdown_locked(self, writer_thread: threading.Thread) -> None:
        # A daemon thread is killed at exit with events still queued: drain it
        # (bounded) unless stop_writer() ran first. Neither hook keeps this log
        # alive, so a dropped log is collected and its finalizer stops the thread.
        exit_hook = functools.partial(
            _drain_writer_at_exit, weakref.ref(self), writer_thread, self._writer_stop,
        )
        atexit.register(exit_hook)
        finalizer = weakref.finalize(self, _abandon_writer, self._writer_stop, exit_hook)
        finalizer.atexit = False
        self._writer_exit_hook = exit_hook
        self._writer_finalizer = finalizer

    def stop_writer(
        self,
        *,
        role: str = "",
        source: str = "host",
        user_id: str = "",
        session_id: str = "",
    ) -> None:
        """Drain and stop the writer, then record an ``audit_writer_stop`` event.

        The stop event is recorded only once the writer has drained and
        stopped; it is appended to the same file as the last line. Stopping
        when no writer runs records nothing.
        """
        attribution = _lifecycle_attribution(role, source, user_id, session_id)
        with self._writer_lock:
            self._stop_writer_locked(attribution)

    def _stop_writer_locked(self, attribution: Mapping[str, str] | None = None) -> None:
        was_running = self._writer_running_locked()
        stopped_store = self._writer_store
        stopped_path = self._writer_path
        actor = attribution or _lifecycle_attribution("", "host", "", "")
        self._writer_stop.set()
        writer_thread = self._writer_thread
        if writer_thread is not None:
            writer_thread.join(timeout=_WRITER_STOP_TIMEOUT_SECONDS)
            if writer_thread.is_alive():
                error = TimeoutError(
                    f"Audit writer did not stop within {_WRITER_STOP_TIMEOUT_SECONDS:g} seconds."
                )
                record = self._record_writer_error(error)
                _attach_writer_shutdown_error(error, record)
                if was_running and stopped_store is not None:
                    # Record the stop now, in the view only: the thread still
                    # writes the file. The stop that finds it ended (a retry
                    # or the exit drain) appends this record as the last line.
                    evt = _make_event(
                        "audit_writer_stop",
                        # Quoted, so redaction removes a path with spaces whole.
                        detail=(
                            f"timed out after {_WRITER_STOP_TIMEOUT_SECONDS:g} seconds "
                            f'waiting for the writer to drain: "{stopped_path or ""}"'
                        ),
                        **actor,
                    )
                    self._writer_stop_record = self._store_event(
                        redact_audit_event(evt), writer_locked=True,
                    )
                raise error
        self._clear_writer_state_locked()
        stored = self._writer_stop_record
        self._writer_stop_record = None
        if stored is None and was_running and stopped_store is not None:
            evt = _make_event("audit_writer_stop", detail=str(stopped_path or ""), **actor)
            stored = self._store_event(redact_audit_event(evt), writer_locked=True)
        if stored is not None and stopped_store is not None:
            try:
                # The thread has exited: this is the file's last line.
                stopped_store.append(stored)
            except Exception as exc:
                self._record_writer_error(exc)

    def _clear_writer_state_locked(self) -> None:
        self._writer_thread = None
        self._writer_queue = None
        self._writer_store = None
        self._writer_path = None
        if self._writer_finalizer is not None:
            self._writer_finalizer.detach()
            self._writer_finalizer = None
        if self._writer_exit_hook is not None:
            atexit.unregister(self._writer_exit_hook)
            self._writer_exit_hook = None

    def _rollback_failed_writer_start_locked(
        self, writer_thread: threading.Thread
    ) -> None:
        self._writer_stop.set()
        try:
            writer_alive = writer_thread.is_alive()
        except Exception as exc:
            _LOGGER.warning(
                "Audit writer startup rollback could not determine thread liveness; "
                "retaining ownership (%s: %s)",
                type(exc).__name__,
                _safe_writer_error_message(exc),
            )
            writer_alive = True
        if not writer_alive:
            self._clear_writer_state_locked()

    def writer_status(self) -> dict[str, Any]:
        with self._writer_lock:
            queue_ref = self._writer_queue
            queued_events = 0
            if queue_ref is not None:
                try:
                    queued_events = int(queue_ref.qsize())
                except (AttributeError, NotImplementedError):
                    queued_events = 0
            writer_thread = self._writer_thread
            with self._lock:
                return {
                    "writer_active": bool(
                        writer_thread is not None and writer_thread.is_alive()
                    ),
                    "writer_path": str(self._writer_path or ""),
                    "queued_events": max(0, queued_events),
                    "dropped_events": int(self.dropped),
                    "writer_error_count": int(self._writer_error_count),
                    "last_writer_error": dict(self._last_writer_error),
                    "queue_purpose": "audit_persistence_only",
                }

    def _writer_loop(self) -> None:
        queue_ref = self._writer_queue
        store = self._writer_store
        if queue_ref is None or store is None:
            return
        _run_writer_loop(weakref.ref(self), queue_ref, store, self._writer_stop)

    def _record_writer_error(self, exc: Exception) -> dict[str, str]:
        record = {
            "error_type": type(exc).__name__,
            "exception_type": type(exc).__name__,
            "message": _safe_writer_error_message(exc),
        }
        with self._lock:
            self._writer_error_count += 1
            self._last_writer_error = record
        return dict(record)

    def _record_writer_startup_error(self, exc: Exception) -> None:
        record = self._record_writer_error(exc)
        _attach_writer_startup_error(exc, record)

    def __len__(self) -> int:
        return len(self._events)


__all__ = ["AUDIT_EVENT_SCHEMA_VERSION", "AuditLog", "audit_event_view"]
