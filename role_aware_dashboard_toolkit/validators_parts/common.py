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
    value = str(record.get(field) or "")
    if value and value not in valid_values:
        result["errors"].append(f"{message_prefix}: {value}")


def check_literal_field(result: dict[str, Any], record: dict[str, Any], field: str, expected: str) -> None:
    record = as_record_mapping(record)
    if record is None:
        return
    if str(record.get(field) or "") != expected:
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
) -> None:
    record = as_record_mapping(record)
    if record is None:
        return
    items = record.get(field)
    check_list_field(result, record, field)
    for index, item in enumerate(items or []):
        if not isinstance(item, dict):
            result["errors"].append(f"{field}[{index}] must be a mapping.")
            continue
        value = str(item.get(value_field) or "")
        if value and value not in valid_values:
            result["errors"].append(f"{field}[{index}] invalid {value_field}: {value}")


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
    if "schema_version" in record and record.get("schema_version") != expected_schema_version:
        errors.append(f"Unexpected schema_version for {record_type}: {record.get('schema_version')} != {expected_schema_version}")
    return {"ok": not errors, "record_type": record_type, "errors": errors}


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
