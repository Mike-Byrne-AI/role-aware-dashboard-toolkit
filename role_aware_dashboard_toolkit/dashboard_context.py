from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .controls import ControlRegistry


@dataclass
class DashboardRenderState:
    registry: ControlRegistry
    audit: AuditLog
    groups: list[tuple]
    corrected_values: int = 0


def prepare_render_state(config: Any, session_state: dict[str, Any]) -> DashboardRenderState:
    registry = config.registry
    audit = config.audit
    corrected = 0
    if config.sanitize_session_state:
        registry.ensure_defaults(session_state)
        corrected = registry.sanitize_session_state(session_state)
        if corrected > 0:
            session_state["_radt_last_sanitize_count"] = int(corrected)
    groups = registry.iter_groups()
    return DashboardRenderState(
        registry=registry,
        audit=audit,
        groups=groups,
        corrected_values=int(corrected),
    )


__all__ = ["DashboardRenderState", "prepare_render_state"]
