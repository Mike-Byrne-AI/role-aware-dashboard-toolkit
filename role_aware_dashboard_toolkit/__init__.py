"""Role-Aware Dashboard Toolkit: reusable dashboard controls, profiles, audit, and operator tooling."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._exports import PUBLIC_EXPORT_MAP, PUBLIC_EXPORTS
from .version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION

__version__ = ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION
__all__ = list(PUBLIC_EXPORTS)

# Root exports load lazily at run time. Type checkers instead read these
# imports, generated from _exports.PUBLIC_EXPORT_MAP, so each export keeps its
# real type. tests/test_public_export_typing.py checks that they match the map
# and prints the block to paste here when the map changes.
if TYPE_CHECKING:
    from .audit import AuditLog as AuditLog
    from .audit_store import BaseAuditStore as BaseAuditStore
    from .audit_store import FileAuditStore as FileAuditStore
    from .audit_store import InMemoryAuditStore as InMemoryAuditStore
    from .controls import ControlDef as ControlDef
    from .controls import ControlRegistry as ControlRegistry
    from .dashboard import DashboardConfig as DashboardConfig
    from .sections import DashboardSections as DashboardSections
    from .dashboard import render as render
    from .plugins import DashboardPlugin as DashboardPlugin
    from .plugins import PluginRegistry as PluginRegistry
    from .profile_store import BaseProfileStore as BaseProfileStore
    from .profile_store import FileProfileStore as FileProfileStore
    from .profile_store import InMemoryProfileStore as InMemoryProfileStore
    from .profiles import build_profile as build_profile
    from .profiles import delete_profile as delete_profile
    from .profiles import list_profiles as list_profiles
    from .profiles import load_profile as load_profile
    from .profiles import load_profile_data as load_profile_data
    from .profiles import merge_profile_values as merge_profile_values
    from .profiles import profile_diff as profile_diff
    from .profiles import save_profile as save_profile
    from .security import SecurityContext as SecurityContext
    from .security import RoleDef as RoleDef
    from .security import can_write as can_write
    from .security import get_role as get_role
    from .security import get_role_names as get_role_names
    from .security import has_perm as has_perm
    from .security import make_security_context as make_security_context
    from .runtime import cleanup_runtime as cleanup_runtime
    from .runtime import normalize_telemetry as normalize_telemetry
    from .runtime import safe_call as safe_call
    from .runtime import summarize_telemetry as summarize_telemetry
    from .observability import ObservabilityConfig as ObservabilityConfig
    from .observability import ObservabilityPanel as ObservabilityPanel
    from .observability import build_observability_snapshot as build_observability_snapshot
    from .api import FASTAPI_AVAILABLE as FASTAPI_AVAILABLE
    from .api import create_app as create_app
    from .packets import build_packet as build_packet
    from .packets import build_run_packet as build_run_packet
    from .packets import build_checkpoint_packet as build_checkpoint_packet
    from .packets import build_audit_slice_packet as build_audit_slice_packet
    from .packets import build_compare_packet as build_compare_packet
    from .packets import build_ledger_packet as build_ledger_packet
    from .packets import export_packet_json as export_packet_json
    from .packets import extract_packet_payload as extract_packet_payload
    from .packets import load_packet_json as load_packet_json
    from .runs import build_run as build_run
    from .runs import append_checkpoint as append_checkpoint
    from .runs import end_run as end_run
    from .compare import compare_runs as compare_runs
    from .compare import compare_checkpoints as compare_checkpoints
    from .compare import compare_dashboard_snapshots as compare_dashboard_snapshots
    from .checkpoints import build_dashboard_snapshot as build_dashboard_snapshot
    from .replay import build_replay_packet_from_checkpoint as build_replay_packet_from_checkpoint
    from .ledger import build_run_ledger as build_run_ledger
    from .run_store import BaseRunStore as BaseRunStore
    from .run_store import FileRunStore as FileRunStore
    from .run_store import InMemoryRunStore as InMemoryRunStore
else:
    # Hidden from type checkers, so an unknown root attribute is a type error
    # rather than Any.
    def __getattr__(name: str):
        target = PUBLIC_EXPORT_MAP.get(name)
        if target is None:
            raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
        module_name, attr_name = target
        module = __import__(f"{__name__}.{module_name}", fromlist=[attr_name])
        value = getattr(module, attr_name)
        globals()[name] = value
        return value


def __dir__() -> list[str]:
    return sorted({*globals(), *PUBLIC_EXPORTS})
