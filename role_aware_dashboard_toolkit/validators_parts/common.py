from __future__ import annotations

from typing import Any
from collections.abc import Iterable


def check_enum_field(
    result: dict[str, Any],
    record: dict[str, Any],
    field: str,
    valid_values: Iterable[str],
    message_prefix: str,
) -> None:
    record = as_record_mapping(record)
    if record is None:
        return
    if field not in record:
        return
    value = record[field]
    if not isinstance(value, str) or value not in valid_values:
        result["errors"].append(
            f"{message_prefix}: field '{field}' must be one of {_choices(valid_values)}."
        )


def check_literal_field(result: dict[str, Any], record: dict[str, Any], field: str, expected: str) -> None:
    record = as_record_mapping(record)
    if record is None:
        return
    if field in record and str(record[field] or "") != expected:
        result["errors"].append(f"Field '{field}' must be '{expected}'.")


def check_list_field(result: dict[str, Any], record: dict[str, Any], field: str) -> None:
    record = as_record_mapping(record)
    if record is None:
        return
    if record.get(field) is not None and not isinstance(record.get(field), list):
        result["errors"].append(f"Field '{field}' must be a list.")


def check_mapping_field(result: dict[str, Any], record: dict[str, Any], field: str) -> None:
    record = as_record_mapping(record)
    if record is None:
        return
    if record.get(field) is not None and not isinstance(record.get(field), dict):
        result["errors"].append(f"Field '{field}' must be a mapping.")


def check_list_fields(result: dict[str, Any], record: dict[str, Any], fields: Iterable[str]) -> None:
    for field in fields:
        check_list_field(result, record, field)


def check_record_items(
    result: dict[str, Any],
    record: dict[str, Any],
    field: str,
    *,
    value_field: str,
    valid_values: Iterable[str],
    required: Iterable[str] = (),
) -> None:
    record = as_record_mapping(record)
    if record is None:
        return
    items = record.get(field)
    check_list_field(result, record, field)
    if not isinstance(items, list):
        return
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            result["errors"].append(f"{field}[{index}] must be a mapping.")
            continue
        for key in required:
            if key not in item:
                result["errors"].append(f"{field}[{index}].Missing required field: {key}")
        if value_field not in item:
            continue
        value = item[value_field]
        if not isinstance(value, str) or value not in valid_values:
            result["errors"].append(
                f"{field}[{index}] invalid {value_field}: must be one of {_choices(valid_values)}."
            )


def validate_required_fields(
    record_type: str,
    record: Any,
    *,
    required: Iterable[str],
    expected_schema_version: int,
) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(record, dict):
        return {"ok": False, "record_type": record_type, "errors": ["Record must be a mapping."]}
    for key in required:
        if key not in record:
            errors.append(f"Missing required field: {key}")
    errors.extend(record_shape_errors(record_type, record, required=required))
    if "schema_version" in record and (
        type(record["schema_version"]) is not int
        or record["schema_version"] != expected_schema_version
    ):
        errors.append(
            f"Unexpected schema_version for {record_type}: expected {expected_schema_version}, "
            f"found {_schema_version_label(record['schema_version'])}."
        )
    return {"ok": not errors, "record_type": record_type, "errors": errors}


# Shapes are checked independently of required metadata so native profile loading
# and packet envelopes can safely accept older/partial records. Unknown extension
# fields remain application-owned; only declared toolkit fields are constrained.
_MAPPING_FIELDS = {
    "profile": ("values", "diff_from_parent", "extra"),
    "run": ("initial_controls", "latest_controls"),
    "checkpoint": ("controls", "approval", "telemetry_slice"),
    "handoff": ("summary",),
    "decision": ("summary",),
    "governance": ("approval_requirements",),
    "incident_timeline": ("summary",),
    "narrative_handoff": ("summary",),
    "telemetry_sample": ("metrics", "labels", "health", "units"),
    "replay_packet": ("controls",),
    "diff_packet": ("diff",),
    "packet": ("payload", "meta", "extensions"),
    "ledger": ("latest_controls",),
    "ledger_entry": ("controls", "controls_diff", "telemetry", "audit_event"),
    "governance_policy_check": ("refs",),
}
_RECORD_LIST_FIELDS = {
    "profile": ("control_meta",),
    "run": ("checkpoints",),
    "checkpoint": ("audit_slice",),
    "decision": ("history", "blockers"),
    "governance": ("policy_checks", "history"),
    "case": ("history",),
    "incident_timeline": ("events",),
    "narrative_handoff": ("highlights",),
    "ledger": ("entries",),
    "audit_slice": ("events",),
}
_STRING_LIST_FIELDS = {
    "run": ("tags",),
    "decision": ("allowed_actions", "tags"),
    "governance": ("blocked_actions", "allowed_next_actions", "linked_run_ids"),
    "governance_approval_requirements": ("required_roles", "missing_roles", "satisfied_roles"),
    "governance_policy_check": ("required_roles",),
    "operator_note": ("tags",),
    "case": ("linked_run_ids", "linked_checkpoint_ids", "linked_decision_ids",
             "linked_incident_ids", "linked_narrative_ids", "linked_note_ids",
             "hypotheses", "findings", "tags"),
    "replay_packet": ("touched_keys",),
    "diff_packet": ("source_ids",),
}
_STRING_FIELDS = {
    "profile": ("profile_id", "saved_at", "role", "parent_profile_id", "app_name",
                "app_version", "session_id", "source"),
    "run": ("run_id", "started_at", "ended_at", "actor", "role", "status", "notes",
            "outcome", "source_profile_id", "active_profile_id", "app_name",
            "app_version", "session_id", "source", "last_checkpoint_id"),
    "checkpoint": ("checkpoint_id", "ts", "label", "reason", "approval_state", "actor", "role", "source"),
    "approval": ("ts", "state", "actor", "role", "reason", "source"),
    "decision": ("latest_signoff_decision", "latest_handoff_status"),
    "case": ("summary", "actor", "role", "source"),
    "incident": ("summary",),
    "operator_note": ("checkpoint_id", "decision_id", "importance"),
    "packet": ("source_app", "source_version"),
    "audit_event": ("ts", "type", "source", "key", "role", "detail", "user_id", "session_id", "app_name", "app_version"),
    "ledger_entry": ("entry_type", "entry_id", "ts", "run_id", "checkpoint_id", "actor", "role",
                     "approval_state", "label", "reason", "detail"),
    "governance_policy_check": ("check_id", "title", "result", "detail"),
}
_INTEGER_FIELDS = {
    "decision": ("open_assignment_count", "comment_count", "signoff_count", "handoff_count"),
    "governance": ("blocker_count", "warning_count"),
    "audit_slice": ("event_count",),
    "ledger_entry": ("source_sequence", "audit_count"),
}
_BOOLEAN_FIELDS = {"governance_policy_check": ("blocker",)}
_NONNEGATIVE_INTEGER_FIELDS = {"ledger_entry": ("source_sequence",)}
_NESTED_RECORDS = {
    "run": {"checkpoints": "checkpoint"},
    "checkpoint": {"approval": "approval", "audit_slice": "audit_event"},
    "audit_slice": {"events": "audit_event"},
    "governance": {"approval_requirements": "governance_approval_requirements",
                   "policy_checks": "governance_policy_check"},
    "ledger": {"entries": "ledger_entry"},
    "ledger_entry": {"audit_event": "audit_event"},
}
_UNVERSIONED_NESTED_RECORDS = {
    "governance_approval_requirements", "governance_policy_check", "ledger_entry",
}


def record_shape_errors(
    record_type: str, record: Any, *, required: Iterable[str] = (),
    _ancestors: frozenset[int] = frozenset(),
) -> list[str]:
    """Check declared field types without requiring new metadata on old records.

    Error text contains field names and expected shapes, never saved values.
    The ancestor guard also makes this safe for non-JSON caller dictionaries.
    """
    if not isinstance(record, dict):
        return ["Record must be a mapping."]
    if id(record) in _ancestors:
        return ["Record must not contain circular references."]
    ancestors = _ancestors | {id(record)}
    shapes = {key: dict for key in _MAPPING_FIELDS.get(record_type, ())}
    shapes.update({key: list for key in _RECORD_LIST_FIELDS.get(record_type, ())})
    shapes.update({key: list for key in _STRING_LIST_FIELDS.get(record_type, ())})
    shapes.update({key: str for key in _STRING_FIELDS.get(record_type, ())})
    shapes.update({key: int for key in _INTEGER_FIELDS.get(record_type, ())})
    shapes.update({key: bool for key in _BOOLEAN_FIELDS.get(record_type, ())})
    for key in required:
        shapes.setdefault(key, str)
    # Nested entries are not independently versioned protocol records. Their
    # unknown fields, including an application-owned schema_version, stay free.
    if record_type not in _UNVERSIONED_NESTED_RECORDS:
        shapes["schema_version"] = int
    errors = []
    labels = {dict: "a mapping", list: "a list", str: "a string", int: "an integer", bool: "a boolean"}
    for key, expected in shapes.items():
        if key in record and (not isinstance(record[key], expected)
                              or expected is int and isinstance(record[key], bool)):
            errors.append(f"Field '{key}' must be {labels[expected]}.")
    for key in _NONNEGATIVE_INTEGER_FIELDS.get(record_type, ()):
        if type(record.get(key)) is int and record[key] < 0:
            errors.append(f"Field '{key}' must be nonnegative.")
    for fields, expected in ((_RECORD_LIST_FIELDS, dict), (_STRING_LIST_FIELDS, str)):
        for key in fields.get(record_type, ()):
            if isinstance(record.get(key), list):
                for index, item in enumerate(record[key]):
                    if not isinstance(item, expected):
                        errors.append(f"{key}[{index}] must be {labels[expected]}.")
    for key, nested_type in _NESTED_RECORDS.get(record_type, {}).items():
        value = record.get(key)
        children = enumerate(value) if isinstance(value, list) else [(None, value)]
        for index, child in children:
            if isinstance(child, dict):
                prefix = key if index is None else f"{key}[{index}]"
                errors.extend(prefix_errors(prefix, record_shape_errors(
                    nested_type, child, _ancestors=ancestors)))
    return errors


def _choices(valid_values: Iterable[str]) -> str:
    # Allowed values are toolkit constants; the rejected value is saved data.
    return ", ".join(f"'{value}'" for value in valid_values)


def _schema_version_label(value: Any) -> str:
    # A version number is shown; any other saved value is described, not echoed.
    if type(value) is int:
        return str(value) if abs(value) < 10**9 else "another integer"
    labels = {str: "a string", bool: "a boolean", float: "a number", dict: "a mapping", list: "a list"}
    return labels.get(type(value), "a value of another type")


def finalize(result: dict[str, Any]) -> dict[str, Any]:
    result["ok"] = not result["errors"]
    return result


def as_record_mapping(record: Any) -> dict[str, Any] | None:
    if isinstance(record, dict):
        return record
    return None


def prefix_errors(prefix: str, errors: list[str]) -> list[str]:
    return [f"{prefix}.{error}" for error in errors]


__all__ = [
    "as_record_mapping",
    "check_enum_field",
    "check_list_field",
    "check_list_fields",
    "check_mapping_field",
    "check_literal_field",
    "check_record_items",
    "finalize",
    "prefix_errors",
    "validate_required_fields",
]
