"""Fixed, offline recovery guidance for library diagnostics.

The catalog contains no application values, exception payloads or environment
inspection. Guidance describes library behavior; it grants no authority to
change a host application. This module imports only the dependency-free core.
"""
from __future__ import annotations

from typing import Any, TypeVar

from .path_redaction import redact_text_local_paths
from .version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION

# Keep codes stable: installed assistants can resolve these without network
# access. Each tuple is (guide topic, operation, message, effect).
_CATALOG = {
    "RADT-CONTROL-DEFINITION": (
        "controls", "register_control", "The control definition was rejected.",
        "The rejected definition was not registered; earlier registrations are preserved.",
    ),
    "RADT-APPEARANCE": (
        "appearance", "configure_appearance", "Appearance configuration or rendering was rejected.",
        "The requested appearance was not accepted; plugin setup may already have run.",
    ),
    "RADT-SECTIONS": (
        "sections", "configure_sections", "A dashboard section flag was rejected.",
        "The requested section configuration was not accepted.",
    ),
    "RADT-STREAMLIT": (
        "start", "render_dashboard", "The dashboard could not use the required Streamlit API.",
        "The dashboard was not rendered.",
    ),
    "RADT-PERMISSION": (
        "permissions", "apply_controls", "The requested control changes were denied.",
        "No requested control changes were applied.",
    ),
    "RADT-PROFILE-IO": (
        "profiles", "access_profiles", "Profile storage could not complete the requested operation.",
        "Live controls were preserved; storage completion is unconfirmed.",
    ),
    "RADT-PLUGIN": (
        "plugins", "plugin_callback", "A plugin callback failed.",
        "Host effects may be partial; no rollback was performed.",
    ),
    "RADT-TELEMETRY": (
        "telemetry", "sample_telemetry", "Telemetry sampling did not produce a fresh sample.",
        "Any last successful sample is retained with its original timestamp; it is not fresh. Sampling may have caused partial host effects; no rollback was performed.",
    ),
    "RADT-AUDIT-IO": (
        "troubleshooting", "persist_audit", "Audit persistence could not be confirmed.",
        "Durability is unconfirmed; in-memory or queued events may not be persisted.",
    ),
    "RADT-AUTH": (
        "permissions", "authenticate", "Authentication could not be completed.",
        "The dashboard is locked.",
    ),
    "RADT-CALLBACK": (
        "troubleshooting", "call_callback", "A callback failed.",
        "Host effects may be partial; no rollback was performed.",
    ),
}
_Exception = TypeVar("_Exception", bound=Exception)


def build_diagnostic(code: str) -> dict[str, Any]:
    """Return a detached, JSON-safe diagnostic from the fixed catalog."""
    try:
        topic, operation, message, effect = _CATALOG[code]
    except (KeyError, TypeError):
        raise ValueError("Unknown diagnostic code.") from None
    return {
        "schema_version": 1,
        "toolkit_version": ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION,
        "code": code,
        "operation": operation,
        "message": message,
        "effect": effect,
        "guide_topic": topic,
        "guide_command": f"python -m role_aware_dashboard_toolkit guide {topic}",
    }


def list_diagnostics() -> list[dict[str, Any]]:
    """Return fresh catalog entries in their documented order."""
    return [build_diagnostic(code) for code in _CATALOG]


def diagnostic_text(code: str) -> str:
    """Return fixed human-readable help, without application-specific data."""
    record = build_diagnostic(code)
    return (
        f"[{record['code']}] {record['message']} {record['effect']} "
        f"Help: {record['guide_command']}"
    )


def attach_diagnostic(exc: _Exception, code: str) -> _Exception:
    """Annotate a library-created, already sanitized exception in place.

    Internal helper: never pass third-party exceptions here. Their messages may
    contain secrets; generated runtime records must use the fixed catalog
    instead. Preserve the exception class, identity and remaining arguments.
    Repeated application of the same code does not duplicate help.
    """
    diagnostic = build_diagnostic(code)
    help_text = diagnostic_text(code)
    message = redact_text_local_paths(str(exc.args[0]) if exc.args else str(exc))
    if help_text not in message:
        message = f"{message} {help_text}".strip()
    exc.args = (message, *exc.args[1:])
    # ImportError (including ModuleNotFoundError) renders .msg, not args[0].
    # Its name/path attributes remain intact for dependency troubleshooting.
    if isinstance(exc, ImportError):
        exc.msg = message
    exc.diagnostic = diagnostic
    return exc
