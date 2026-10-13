"""Per-render audit identity binding without changing a shared audit log."""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from .audit import AuditLog
from .sensitive_values import REDACTED_SECRET


_PRINCIPAL_ID = re.compile(r"[0-9a-f]{64}\Z")
_SESSION_ID = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class _IdentityBoundAudit:
    """Delegate storage and lifecycle while pinning event attribution.

    These identifiers are opaque references supplied by the trusted access
    layer: a principal HMAC-SHA256 digest and a random session UUID hex value.
    Format validation avoids accepting raw account data; it does not authenticate
    the caller or prove how a digest was produced.
    """

    _audit: AuditLog = field(repr=False)
    user_id: str
    session_id: str

    def __getattr__(self, name: str) -> Any:
        # Return methods bound to the parent so its retention, locks, writer,
        # diagnostics and extensions retain their existing behavior.
        return getattr(self._audit, name)

    def __len__(self) -> int:
        return len(self._audit)

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
        """Log with bound identity; caller-supplied actor IDs cannot replace it."""
        return self._audit.log(
            event_type,
            key=key,
            old_value=old_value,
            new_value=new_value,
            role=role,
            detail=detail,
            source=source,
            user_id=self.user_id,
            session_id=self.session_id,
            app_name=app_name,
            app_version=app_version,
        )

    def log_control_change(
        self,
        key: str,
        old_value: Any,
        new_value: Any,
        *,
        role: str = "",
        source: str = "ui",
        sensitive: bool = False,
    ) -> None:
        if sensitive:
            old_value = REDACTED_SECRET
            new_value = REDACTED_SECRET
        self.log(
            "control_change", key=key, old_value=old_value, new_value=new_value,
            role=role, source=source,
        )

    def log_profile_save(
        self, profile_id: str, *, role: str = "", source: str = "ui",
    ) -> None:
        self.log("profile_save", detail=profile_id, role=role, source=source)

    def log_profile_load(
        self, profile_id: str, *, role: str = "", source: str = "ui",
    ) -> None:
        self.log("profile_load", detail=profile_id, role=role, source=source)

    def log_role_switch(
        self, old_role: str, new_role: str, *, source: str = "ui",
    ) -> None:
        self.log(
            "role_switch", old_value=old_role, new_value=new_role,
            role=new_role, source=source,
        )

    def log_freeze(self, frozen: bool, *, role: str = "", source: str = "ui") -> None:
        # Preserve AuditLog's legacy argument/event semantics exactly.
        self.log("freeze_toggle", new_value=frozen, role=role, source=source)

    # Lifecycle methods act on the shared parent and record their own events
    # (audit_writer_start, audit_writer_stop, audit_cleared). Pin the bound
    # actor on those records as log() does; caller-supplied IDs are ignored.

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
        return self._audit.start_writer(
            path, queue_size=queue_size, role=role, source=source,
            user_id=self.user_id, session_id=self.session_id,
        )

    def stop_writer(
        self,
        *,
        role: str = "",
        source: str = "host",
        user_id: str = "",
        session_id: str = "",
    ) -> None:
        self._audit.stop_writer(
            role=role, source=source, user_id=self.user_id, session_id=self.session_id,
        )

    def clear(
        self,
        *,
        role: str = "",
        source: str = "host",
        user_id: str = "",
        session_id: str = "",
    ) -> int:
        return self._audit.clear(
            role=role, source=source, user_id=self.user_id, session_id=self.session_id,
        )


def bind_audit_identity(
    audit: AuditLog | _IdentityBoundAudit, user_id: str, session_id: str,
) -> _IdentityBoundAudit:
    """Create an independent audit view for an authenticated render.

    ``user_id`` must be the trusted access layer's lowercase HMAC-SHA256 hex
    principal ID. ``session_id`` must be a random UUID's lowercase 32-character
    hex value. Neither argument may contain raw identity claims or credentials.
    Rebinding unwraps an earlier view, without retaining or modifying its actor.
    """
    if not isinstance(user_id, str) or _PRINCIPAL_ID.fullmatch(user_id) is None:
        raise ValueError("user_id must be an opaque lowercase HMAC-SHA256 hex digest")
    if not isinstance(session_id, str) or _SESSION_ID.fullmatch(session_id) is None:
        raise ValueError("session_id must be an opaque lowercase UUID hex value")
    while isinstance(audit, _IdentityBoundAudit):
        audit = audit._audit
    return _IdentityBoundAudit(audit, user_id, session_id)


__all__ = ["bind_audit_identity"]
