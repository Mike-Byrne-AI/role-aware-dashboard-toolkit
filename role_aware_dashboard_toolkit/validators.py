from __future__ import annotations

from typing import Any

from .approvals import APPROVAL_SCHEMA_VERSION, VALID_APPROVAL_STATES
from .audit import AUDIT_EVENT_SCHEMA_VERSION
from .caseboard import CASEBOARD_SCHEMA_VERSION, VALID_CASE_EVENT_TYPES, VALID_CASE_PRIORITIES, VALID_CASE_STATES
from .checkpoints import CHECKPOINT_SCHEMA_VERSION
from .decisions import DECISION_SCHEMA_VERSION, VALID_DECISION_EVENT_TYPES, VALID_DECISION_STATES
from .governance import (
    GOVERNANCE_SCHEMA_VERSION,
    VALID_ESCALATION_LEVELS,
    VALID_GOVERNANCE_EVENT_TYPES,
    VALID_GOVERNANCE_STATES,
    VALID_POLICY_CHECK_RESULTS,
)
from .observability import TELEMETRY_SCHEMA_VERSION
from .operator_memory import (
    OPERATOR_MEMORY_SCHEMA_VERSION,
    VALID_INCIDENT_SEVERITIES,
    VALID_INCIDENT_STATUSES,
    VALID_NOTE_EVENT_TYPES,
)
from .path_redaction import redact_text_local_paths
from .profile_store import PROFILE_SCHEMA_VERSION
from .replay import REPLAY_SCHEMA_VERSION
from .runs import RUN_SCHEMA_VERSION, VALID_RUN_STATUSES
from .team_ops import TEAM_SCHEMA_VERSION, VALID_ASSIGNMENT_STATUSES, VALID_HANDOFF_STATUSES, VALID_SIGNOFF_DECISIONS
from .validators_parts.common import (
    as_record_mapping as _as_record_mapping,
    check_enum_field as _check_enum_field,
    check_list_field as _check_list_field,
    check_list_fields as _check_list_fields,
    check_mapping_field as _check_mapping_field,
    check_literal_field as _check_literal_field,
    check_record_items as _check_record_items,
    finalize as _finalize,
    prefix_errors as _prefix_errors,
    validate_required_fields as _validate,
)

VALID_RECORD_TYPES = (
    "profile",
    "run",
    "checkpoint",
    "approval",
    "audit_event",
    "telemetry_sample",
    "replay_packet",
    "diff_packet",
    "packet",
    "ledger",
    "comment",
    "assignment",
    "signoff",
    "handoff",
    "decision",
    "operator_note",
    "incident",
    "incident_timeline",
    "narrative_handoff",
    "case",
    "governance",
)

def validate_profile_record(record: dict[str, Any]) -> dict[str, Any]:
    return _validate(
        "profile",
        record,
        required=("schema_version", "profile_id", "saved_at", "values", "control_meta"),
        expected_schema_version=PROFILE_SCHEMA_VERSION,
    )



def validate_run_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "run",
        record,
        required=(
            "schema_version",
            "run_id",
            "started_at",
            "status",
            "initial_controls",
            "latest_controls",
            "checkpoints",
        ),
        expected_schema_version=RUN_SCHEMA_VERSION,
    )
    _check_enum_field(result, record, "status", VALID_RUN_STATUSES, "Invalid run status")
    _check_list_field(result, record, "checkpoints")
    return _finalize(result)



def validate_checkpoint_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "checkpoint",
        record,
        required=("schema_version", "checkpoint_id", "ts", "controls", "approval_state", "approval"),
        expected_schema_version=CHECKPOINT_SCHEMA_VERSION,
    )
    record = _as_record_mapping(record)
    if record is None:
        return _finalize(result)
    _check_enum_field(result, record, "approval_state", VALID_APPROVAL_STATES, "Invalid checkpoint approval_state")
    approval = record.get("approval")
    if approval is not None:
        if not isinstance(approval, dict):
            result["errors"].append("Field 'approval' must be a mapping.")
        else:
            approval_result = validate_approval_record(dict(approval))
            result["errors"].extend(_prefix_errors("approval", approval_result["errors"]))
    return _finalize(result)



def validate_approval_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "approval",
        record,
        required=("schema_version", "ts", "state"),
        expected_schema_version=APPROVAL_SCHEMA_VERSION,
    )
    _check_enum_field(result, record, "state", VALID_APPROVAL_STATES, "Invalid approval state")
    return _finalize(result)



def validate_comment_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "comment",
        record,
        required=("schema_version", "event_type", "comment_id", "ts", "run_id", "body"),
        expected_schema_version=TEAM_SCHEMA_VERSION,
    )
    _check_literal_field(result, record, "event_type", "comment")
    return _finalize(result)



def validate_assignment_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "assignment",
        record,
        required=("schema_version", "event_type", "assignment_id", "ts", "run_id", "title", "status"),
        expected_schema_version=TEAM_SCHEMA_VERSION,
    )
    _check_literal_field(result, record, "event_type", "assignment")
    _check_enum_field(result, record, "status", VALID_ASSIGNMENT_STATUSES, "Invalid assignment status")
    return _finalize(result)



def validate_signoff_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "signoff",
        record,
        required=("schema_version", "event_type", "signoff_id", "ts", "run_id", "decision"),
        expected_schema_version=TEAM_SCHEMA_VERSION,
    )
    _check_literal_field(result, record, "event_type", "signoff")
    _check_enum_field(result, record, "decision", VALID_SIGNOFF_DECISIONS, "Invalid signoff decision")
    return _finalize(result)



def validate_handoff_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "handoff",
        record,
        required=("schema_version", "event_type", "handoff_id", "ts", "run_id", "status", "summary"),
        expected_schema_version=TEAM_SCHEMA_VERSION,
    )
    _check_literal_field(result, record, "event_type", "handoff")
    _check_enum_field(result, record, "status", VALID_HANDOFF_STATUSES, "Invalid handoff status")
    _check_mapping_field(result, record, "summary")
    return _finalize(result)



def validate_decision_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "decision",
        record,
        required=(
            "schema_version",
            "decision_id",
            "run_id",
            "checkpoint_id",
            "created_at",
            "updated_at",
            "state",
            "approval_state",
            "history",
            "allowed_actions",
            "blockers",
        ),
        expected_schema_version=DECISION_SCHEMA_VERSION,
    )
    _check_enum_field(result, record, "state", VALID_DECISION_STATES, "Invalid decision state")
    _check_record_items(result, record, "history", value_field="event_type", valid_values=VALID_DECISION_EVENT_TYPES)
    _check_list_fields(result, record, ("allowed_actions", "blockers"))
    return _finalize(result)



def validate_governance_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "governance",
        record,
        required=(
            "schema_version",
            "governance_id",
            "case_id",
            "created_at",
            "updated_at",
            "state",
            "severity",
            "escalation_level",
            "policy_checks",
            "approval_requirements",
            "blocked_actions",
            "allowed_next_actions",
            "history",
        ),
        expected_schema_version=GOVERNANCE_SCHEMA_VERSION,
    )
    _check_enum_field(result, record, "state", VALID_GOVERNANCE_STATES, "Invalid governance state")
    _check_enum_field(result, record, "escalation_level", VALID_ESCALATION_LEVELS, "Invalid escalation level")
    _check_record_items(result, record, "policy_checks", value_field="result", valid_values=VALID_POLICY_CHECK_RESULTS)
    _check_record_items(result, record, "history", value_field="event_type", valid_values=VALID_GOVERNANCE_EVENT_TYPES)
    _check_mapping_field(result, record, "approval_requirements")
    _check_list_fields(result, record, ("blocked_actions", "allowed_next_actions"))
    return _finalize(result)



def validate_operator_note_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "operator_note",
        record,
        required=("schema_version", "event_type", "note_id", "ts", "run_id", "body"),
        expected_schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
    )
    _check_enum_field(result, record, "event_type", VALID_NOTE_EVENT_TYPES, "Invalid operator note event_type")
    return _finalize(result)



def validate_incident_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "incident",
        record,
        required=("schema_version", "event_type", "incident_id", "ts", "run_id", "title", "severity", "status"),
        expected_schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
    )
    _check_literal_field(result, record, "event_type", "incident")
    _check_enum_field(result, record, "severity", VALID_INCIDENT_SEVERITIES, "Invalid incident severity")
    _check_enum_field(result, record, "status", VALID_INCIDENT_STATUSES, "Invalid incident status")
    return _finalize(result)



def validate_case_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "case",
        record,
        required=(
            "schema_version",
            "case_id",
            "created_at",
            "updated_at",
            "title",
            "state",
            "priority",
            "history",
            "linked_run_ids",
            "linked_incident_ids",
            "linked_narrative_ids",
        ),
        expected_schema_version=CASEBOARD_SCHEMA_VERSION,
    )
    _check_enum_field(result, record, "state", VALID_CASE_STATES, "Invalid case state")
    _check_enum_field(result, record, "priority", VALID_CASE_PRIORITIES, "Invalid case priority")
    _check_record_items(result, record, "history", value_field="event_type", valid_values=VALID_CASE_EVENT_TYPES)
    _check_list_fields(
        result,
        record,
        (
            "linked_run_ids",
            "linked_checkpoint_ids",
            "linked_decision_ids",
            "linked_incident_ids",
            "linked_narrative_ids",
            "linked_note_ids",
            "hypotheses",
            "findings",
            "tags",
        ),
    )
    return _finalize(result)



def validate_incident_timeline_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "incident_timeline",
        record,
        required=("schema_version", "event_type", "timeline_id", "run_id", "generated_at", "events", "summary"),
        expected_schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
    )
    _check_literal_field(result, record, "event_type", "incident_timeline")
    _check_list_field(result, record, "events")
    _check_mapping_field(result, record, "summary")
    return _finalize(result)



def validate_narrative_handoff_record(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "narrative_handoff",
        record,
        required=("schema_version", "event_type", "narrative_id", "exported_at", "run_id", "headline", "narrative", "summary"),
        expected_schema_version=OPERATOR_MEMORY_SCHEMA_VERSION,
    )
    _check_literal_field(result, record, "event_type", "narrative_handoff")
    _check_mapping_field(result, record, "summary")
    _check_list_field(result, record, "highlights")
    return _finalize(result)



def validate_audit_event(record: dict[str, Any]) -> dict[str, Any]:
    return _validate(
        "audit_event",
        record,
        required=("schema_version", "ts", "type", "source"),
        expected_schema_version=AUDIT_EVENT_SCHEMA_VERSION,
    )



def validate_telemetry_sample(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "telemetry_sample",
        record,
        required=("schema_version", "ts", "metrics"),
        expected_schema_version=TELEMETRY_SCHEMA_VERSION,
    )
    _check_mapping_field(result, record, "metrics")
    return _finalize(result)



def validate_replay_packet(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "replay_packet",
        record,
        required=("schema_version", "source_type", "source_id", "controls", "touched_keys"),
        expected_schema_version=REPLAY_SCHEMA_VERSION,
    )
    _check_mapping_field(result, record, "controls")
    _check_list_field(result, record, "touched_keys")
    return _finalize(result)



def validate_diff_packet(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "diff_packet",
        record,
        required=("schema_version", "diff_type", "source_ids", "diff"),
        expected_schema_version=1,
    )
    _check_list_field(result, record, "source_ids")
    _check_mapping_field(result, record, "diff")
    return _finalize(result)



def validate_packet(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "packet",
        record,
        required=("schema_version", "packet_type", "packet_id", "exported_at", "payload"),
        expected_schema_version=1,
    )
    warnings: list[str] = []
    record = _as_record_mapping(record)
    if record is None:
        result["warnings"] = warnings
        return _finalize(result)
    _check_mapping_field(result, record, "payload")
    packet_type = str(record.get("packet_type") or "").strip().lower()
    if not packet_type:
        result["errors"].append("Field 'packet_type' must be present.")
    else:
        known_packet_types, packet_type_registry_error = _known_packet_types()
        if packet_type_registry_error:
            result["errors"].append(packet_type_registry_error)
        extension_packet = _is_extension_packet_type(packet_type)
        if not packet_type_registry_error and packet_type not in known_packet_types:
            if extension_packet:
                warnings.append(f"Unknown extension packet_type '{packet_type}' accepted by extension policy.")
            else:
                result["errors"].append(f"Invalid packet_type: {packet_type}")

        payload = record.get("payload")
        payload_schema_version = _coerce_int_schema_version(record.get("payload_schema_version"))
        payload_body_schema_version = _coerce_int_schema_version((payload or {}).get("schema_version")) if isinstance(payload, dict) else None
        expected_schema_version: int | None = None
        protocol_catalog_error: str | None = None
        if not extension_packet and not packet_type_registry_error and packet_type in known_packet_types:
            expected_schema_version, protocol_catalog_error = _protocol_schema_version(packet_type)
            if protocol_catalog_error:
                result["errors"].append(protocol_catalog_error)

        if expected_schema_version is not None:
            if payload_schema_version is None:
                result["errors"].append(f"Missing or invalid payload_schema_version for packet_type '{packet_type}'.")
            elif payload_schema_version != expected_schema_version:
                result["errors"].append(
                    f"Unexpected payload_schema_version for packet_type '{packet_type}': "
                    f"{payload_schema_version} != {expected_schema_version}"
                )
            if payload_body_schema_version is not None and payload_body_schema_version != expected_schema_version:
                result["errors"].append(
                    f"Unexpected payload.schema_version for packet_type '{packet_type}': "
                    f"{payload_body_schema_version} != {expected_schema_version}"
                )
        elif extension_packet:
            if payload_schema_version is None:
                result["errors"].append(
                    f"Extension packet_type '{packet_type}' must provide an integer payload_schema_version."
                )
            elif payload_schema_version < 1:
                result["errors"].append(
                    f"Extension packet_type '{packet_type}' must use payload_schema_version >= 1."
                )

        if (
            payload_schema_version is not None
            and payload_body_schema_version is not None
            and payload_schema_version != payload_body_schema_version
        ):
            result["errors"].append(
                f"payload_schema_version ({payload_schema_version}) does not match "
                f"payload.schema_version ({payload_body_schema_version}) for packet_type '{packet_type}'."
            )
        if (
            not packet_type_registry_error
            and packet_type in known_packet_types
            and expected_schema_version is None
            and protocol_catalog_error is None
        ):
            warnings.append(
                f"No protocol catalog schema metadata found for packet_type '{packet_type}'; "
                "schema version compatibility was not verified."
            )

    result["warnings"] = warnings
    return _finalize(result)



def validate_ledger(record: dict[str, Any]) -> dict[str, Any]:
    result = _validate(
        "ledger",
        record,
        required=("schema_version", "run_id", "generated_at", "entries", "latest_controls"),
        expected_schema_version=1,
    )
    _check_list_field(result, record, "entries")
    return _finalize(result)



def validate_record(record_type: str, record: dict[str, Any]) -> dict[str, Any]:
    dispatch = {
        "profile": validate_profile_record,
        "run": validate_run_record,
        "checkpoint": validate_checkpoint_record,
        "approval": validate_approval_record,
        "audit_event": validate_audit_event,
        "telemetry_sample": validate_telemetry_sample,
        "replay_packet": validate_replay_packet,
        "diff_packet": validate_diff_packet,
        "packet": validate_packet,
        "ledger": validate_ledger,
        "comment": validate_comment_record,
        "assignment": validate_assignment_record,
        "signoff": validate_signoff_record,
        "handoff": validate_handoff_record,
        "decision": validate_decision_record,
        "operator_note": validate_operator_note_record,
        "incident": validate_incident_record,
        "incident_timeline": validate_incident_timeline_record,
        "narrative_handoff": validate_narrative_handoff_record,
        "case": validate_case_record,
        "governance": validate_governance_record,
    }
    normalized = str(record_type or "").strip().lower()
    if normalized not in dispatch:
        return {"ok": False, "record_type": normalized, "errors": [f"Unknown record type: {record_type}"]}
    return dispatch[normalized](record)



def _known_packet_types() -> tuple[set[str], str | None]:
    try:
        from .packet_core import VALID_PACKET_TYPES
    except Exception as exc:
        return set(), _packet_validation_import_error("packet type registry", exc)
    return {str(item).strip().lower() for item in VALID_PACKET_TYPES}, None


def _protocol_schema_version(packet_type: str) -> tuple[int | None, str | None]:
    try:
        from .protocol.catalog import get_protocol_schema_version
    except Exception as exc:
        return None, _packet_validation_import_error("protocol catalog metadata", exc)
    return get_protocol_schema_version(packet_type), None


def _packet_validation_import_error(subject: str, exc: Exception) -> str:
    detail = redact_text_local_paths(str(exc))
    exception_detail = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
    return (
        f"Failed to import {subject or 'required metadata'!s} for packet validation: "
        f"{exception_detail}"
    )


def _coerce_int_schema_version(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
    return None


def _is_extension_packet_type(packet_type: str) -> bool:
    return str(packet_type or "").startswith("x_")


__all__ = [
    "VALID_RECORD_TYPES",
    "validate_approval_record",
    "validate_assignment_record",
    "validate_audit_event",
    "validate_case_record",
    "validate_checkpoint_record",
    "validate_comment_record",
    "validate_decision_record",
    "validate_diff_packet",
    "validate_governance_record",
    "validate_handoff_record",
    "validate_incident_record",
    "validate_incident_timeline_record",
    "validate_ledger",
    "validate_narrative_handoff_record",
    "validate_operator_note_record",
    "validate_packet",
    "validate_profile_record",
    "validate_record",
    "validate_replay_packet",
    "validate_run_record",
    "validate_signoff_record",
    "validate_telemetry_sample",
]
