"""Explicit presentation choices for built-in dashboard sections.

Visibility never grants permissions or disables trusted plugin setup. A hidden
runbook hides its children; role resolution, freeze and replay authorization
remain active independently of these presentation choices.
"""
from __future__ import annotations

from .diagnostics import attach_diagnostic

from dataclasses import dataclass, fields
from typing import Any


@dataclass(frozen=True)
class DashboardSections:
    """Choose visible dashboard surfaces; every existing section defaults on.

    ``audit_writer`` hides its configuration form only: writer settings, lifecycle
    and failure reporting remain active. ``observability`` also skips sampling.
    Plugin render flags do not disable plugin setup or change plugin trust.
    """

    controls: bool = True
    profiles: bool = True
    runbook: bool = True
    audit_writer: bool = True
    audit_log: bool = True
    observability: bool = True
    plugin_details: bool = True
    plugin_sidebar: bool = True
    plugin_panels: bool = True
    team_ops: bool = True
    decisions: bool = True
    operator_memory: bool = True
    caseboard: bool = True
    governance: bool = True

    def __post_init__(self) -> None:
        for item in fields(self):
            if type(getattr(self, item.name)) is not bool:
                raise attach_diagnostic(TypeError(f"DashboardSections.{item.name} must be bool"), "RADT-SECTIONS")


_SECTION_NAMES = frozenset(item.name for item in fields(DashboardSections))
_DEFAULT_SECTIONS = DashboardSections()


def section_visible(config: Any, name: str) -> bool:
    """Read a known section; omitted configuration preserves previous behavior."""
    if name not in _SECTION_NAMES:
        raise attach_diagnostic(ValueError(f"Unknown dashboard section: {name}"), "RADT-SECTIONS")
    sections = getattr(config, "sections", None)
    if sections is None:
        sections = _DEFAULT_SECTIONS
    if not isinstance(sections, DashboardSections):
        raise attach_diagnostic(TypeError("sections must be a DashboardSections instance or None"), "RADT-SECTIONS")
    return getattr(sections, name)


__all__ = ["DashboardSections"]
