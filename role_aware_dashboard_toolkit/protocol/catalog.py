from __future__ import annotations

from typing import Any

from ..approvals import APPROVAL_SCHEMA_VERSION
from ..audit import AUDIT_EVENT_SCHEMA_VERSION
from ..caseboard import CASEBOARD_SCHEMA_VERSION
from ..checkpoints import CHECKPOINT_SCHEMA_VERSION
from ..decisions import DECISION_SCHEMA_VERSION
from ..governance import GOVERNANCE_SCHEMA_VERSION
from ..ledger import LEDGER_SCHEMA_VERSION
from ..observability import TELEMETRY_SCHEMA_VERSION
from ..operator_memory import OPERATOR_MEMORY_SCHEMA_VERSION
from ..packet_core import DIFF_PACKET_SCHEMA_VERSION, PACKET_SCHEMA_VERSION, VALID_PACKET_TYPES
from ..profile_store import PROFILE_SCHEMA_VERSION
from ..replay import REPLAY_SCHEMA_VERSION
from ..runs import RUN_SCHEMA_VERSION
from ..team_ops import TEAM_SCHEMA_VERSION

PROTOCOL_FAMILY = "role_aware_dashboard_toolkit.protocol"
RECORD_SCHEMA_VERSIONS = {
    "profile": PROFILE_SCHEMA_VERSION,
    "run": RUN_SCHEMA_VERSION,
    "checkpoint": CHECKPOINT_SCHEMA_VERSION,
    "approval": APPROVAL_SCHEMA_VERSION,
    "audit_event": AUDIT_EVENT_SCHEMA_VERSION,
    "audit_slice": AUDIT_EVENT_SCHEMA_VERSION,
    "telemetry_sample": TELEMETRY_SCHEMA_VERSION,
    "replay": REPLAY_SCHEMA_VERSION,
    "replay_packet": REPLAY_SCHEMA_VERSION,
    "compare": DIFF_PACKET_SCHEMA_VERSION,
    "diff_packet": DIFF_PACKET_SCHEMA_VERSION,
    "packet": PACKET_SCHEMA_VERSION,
    "ledger": LEDGER_SCHEMA_VERSION,
    "comment": TEAM_SCHEMA_VERSION,
    "assignment": TEAM_SCHEMA_VERSION,
    "signoff": TEAM_SCHEMA_VERSION,
    "handoff": TEAM_SCHEMA_VERSION,
    "decision": DECISION_SCHEMA_VERSION,
    "operator_note": OPERATOR_MEMORY_SCHEMA_VERSION,
    "incident": OPERATOR_MEMORY_SCHEMA_VERSION,
    "incident_timeline": OPERATOR_MEMORY_SCHEMA_VERSION,
    "narrative_handoff": OPERATOR_MEMORY_SCHEMA_VERSION,
    "case": CASEBOARD_SCHEMA_VERSION,
    "governance": GOVERNANCE_SCHEMA_VERSION,
}


def _entry(
    *,
    kind: str,
    schema_version: int,
    docs: str,
    validator: str,
    builder: str,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "schema_version": schema_version,
        "docs": docs,
        "validator": validator,
        "builder": builder,
    }


PROTOCOL_CATALOG: dict[str, dict[str, Any]] = {
    "profile": _entry(
        kind="record",
        schema_version=PROFILE_SCHEMA_VERSION,
        docs="docs/dashboard_tools.md",
        validator="validate_profile_record",
        builder="build_profile",
    ),
    "run": _entry(
        kind="record",
        schema_version=RUN_SCHEMA_VERSION,
        docs="docs/run_model.md",
        validator="validate_run_record",
        builder="build_run",
    ),
    "checkpoint": _entry(
        kind="record",
        schema_version=CHECKPOINT_SCHEMA_VERSION,
        docs="docs/run_model.md",
        validator="validate_checkpoint_record",
        builder="build_checkpoint",
    ),
    "approval": _entry(
        kind="record",
        schema_version=APPROVAL_SCHEMA_VERSION,
        docs="docs/run_model.md",
        validator="validate_approval_record",
        builder="build_approval_record",
    ),
    "audit_event": _entry(
        kind="record",
        schema_version=AUDIT_EVENT_SCHEMA_VERSION,
        docs="docs/replay.md",
        validator="validate_audit_event",
        builder="AuditLog.log",
    ),
    "audit_slice": _entry(
        kind="packet",
        schema_version=AUDIT_EVENT_SCHEMA_VERSION,
        docs="docs/protocol/packets.md",
        validator="validate_packet",
        builder="build_audit_slice_packet",
    ),
    "telemetry_sample": _entry(
        kind="record",
        schema_version=TELEMETRY_SCHEMA_VERSION,
        docs="docs/telemetry_contract.md",
        validator="validate_telemetry_sample",
        builder="build_observability_snapshot",
    ),
    "replay": _entry(
        kind="packet",
        schema_version=REPLAY_SCHEMA_VERSION,
        docs="docs/replay.md",
        validator="validate_packet",
        builder="build_replay_packet_from_checkpoint",
    ),
    "replay_packet": _entry(
        kind="record",
        schema_version=REPLAY_SCHEMA_VERSION,
        docs="docs/replay.md",
        validator="validate_replay_packet",
        builder="build_replay_packet_from_checkpoint",
    ),
    "compare": _entry(
        kind="packet",
        schema_version=DIFF_PACKET_SCHEMA_VERSION,
        docs="docs/protocol/packets.md",
        validator="validate_packet",
        builder="build_compare_packet",
    ),
    "diff_packet": _entry(
        kind="record",
        schema_version=DIFF_PACKET_SCHEMA_VERSION,
        docs="docs/protocol/packets.md",
        validator="validate_diff_packet",
        builder="build_compare_packet",
    ),
    "packet": _entry(
        kind="packet",
        schema_version=PACKET_SCHEMA_VERSION,
        docs="docs/protocol/packets.md",
        validator="validate_packet",
        builder="build_packet",
    ),
    "ledger": _entry(
        kind="record",
        schema_version=LEDGER_SCHEMA_VERSION,
        docs="docs/protocol/ledger.md",
        validator="validate_ledger",
        builder="build_run_ledger",
    ),
    "comment": _entry(
        kind="record",
        schema_version=TEAM_SCHEMA_VERSION,
        docs="docs/team_ops.md",
        validator="validate_comment_record",
        builder="build_team_comment",
    ),
    "assignment": _entry(
        kind="record",
        schema_version=TEAM_SCHEMA_VERSION,
        docs="docs/team_ops.md",
        validator="validate_assignment_record",
        builder="build_review_assignment",
    ),
    "signoff": _entry(
        kind="record",
        schema_version=TEAM_SCHEMA_VERSION,
        docs="docs/team_ops.md",
        validator="validate_signoff_record",
        builder="build_signoff_record",
    ),
    "handoff": _entry(
        kind="record",
        schema_version=TEAM_SCHEMA_VERSION,
        docs="docs/team_ops.md",
        validator="validate_handoff_record",
        builder="build_handoff_summary",
    ),
    "decision": _entry(
        kind="record",
        schema_version=DECISION_SCHEMA_VERSION,
        docs="docs/decision_model.md",
        validator="validate_decision_record",
        builder="build_decision_case",
    ),
    "operator_note": _entry(
        kind="record",
        schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
        docs="docs/operator_memory.md",
        validator="validate_operator_note_record",
        builder="build_operator_note",
    ),
    "incident": _entry(
        kind="record",
        schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
        docs="docs/operator_memory.md",
        validator="validate_incident_record",
        builder="build_incident_record",
    ),
    "incident_timeline": _entry(
        kind="record",
        schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
        docs="docs/operator_memory.md",
        validator="validate_incident_timeline_record",
        builder="build_incident_timeline",
    ),
    "narrative_handoff": _entry(
        kind="record",
        schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
        docs="docs/operator_memory.md",
        validator="validate_narrative_handoff_record",
        builder="build_narrative_handoff_packet",
    ),
    "case": _entry(
        kind="record",
        schema_version=CASEBOARD_SCHEMA_VERSION,
        docs="docs/caseboard.md",
        validator="validate_case_record",
        builder="build_case_record",
    ),
    "governance": _entry(
        kind="record",
        schema_version=GOVERNANCE_SCHEMA_VERSION,
        docs="docs/governance.md",
        validator="validate_governance_record",
        builder="build_governance_record",
    ),
}

ALLOWLISTED_UNCATALOGED_PACKET_TYPES: tuple[str, ...] = ()


def get_protocol_entry(name: str) -> dict[str, Any]:
    return dict(PROTOCOL_CATALOG[str(name or "")])


def list_protocol_entries() -> list[dict[str, Any]]:
    return [
        {"name": name, **entry}
        for name, entry in sorted(PROTOCOL_CATALOG.items())
    ]


def get_protocol_schema_version(name: str) -> int | None:
    entry = PROTOCOL_CATALOG.get(str(name or ""))
    if not isinstance(entry, dict):
        return None
    value = entry.get("schema_version")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def list_uncataloged_packet_types() -> list[str]:
    return sorted(
        packet_type
        for packet_type in VALID_PACKET_TYPES
        if packet_type not in PROTOCOL_CATALOG
    )


__all__ = [
    "ALLOWLISTED_UNCATALOGED_PACKET_TYPES",
    "PROTOCOL_CATALOG",
    "PROTOCOL_FAMILY",
    "RECORD_SCHEMA_VERSIONS",
    "get_protocol_entry",
    "get_protocol_schema_version",
    "list_protocol_entries",
    "list_uncataloged_packet_types",
]
