from __future__ import annotations

import json
from typing import Any

from ._json_safety import strict_json_loads
from .packet_core import (
    DIFF_PACKET_SCHEMA_VERSION,
    MAX_PACKET_NESTING_DEPTH,
    PACKET_SCHEMA_VERSION,
    VALID_PACKET_TYPES,
    _nesting_error,
    _nesting_exceeds,
    _normalize_packet_type,
    build_packet,
)
from .validators import validate_packet


def build_profile_packet(
    profile: dict[str, Any],
    *,
    source_app: str = "role_aware_dashboard_toolkit",
    source_version: str = "",
) -> dict[str, Any]:
    return build_packet(
        "profile",
        profile,
        source_app=source_app,
        source_version=source_version,
        meta={"profile_id": str(profile.get("profile_id") or "")},
    )


def build_run_packet(
    run: dict[str, Any],
    *,
    source_app: str = "role_aware_dashboard_toolkit",
    source_version: str = "",
) -> dict[str, Any]:
    return build_packet(
        "run",
        run,
        source_app=source_app,
        source_version=source_version,
        meta={"run_id": str(run.get("run_id") or "")},
    )


def build_checkpoint_packet(
    checkpoint: dict[str, Any],
    *,
    run_id: str = "",
    source_app: str = "role_aware_dashboard_toolkit",
    source_version: str = "",
) -> dict[str, Any]:
    meta = {"checkpoint_id": str(checkpoint.get("checkpoint_id") or "")}
    if run_id:
        meta["run_id"] = str(run_id)
    return build_packet(
        "checkpoint",
        checkpoint,
        source_app=source_app,
        source_version=source_version,
        meta=meta,
    )


def build_audit_slice_packet(
    events: list[dict[str, Any]],
    *,
    run_id: str = "",
    checkpoint_id: str = "",
    source_app: str = "role_aware_dashboard_toolkit",
    source_version: str = "",
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "event_count": len(events or []),
        "events": list(events or []),
    }
    meta: dict[str, Any] = {}
    if run_id:
        meta["run_id"] = str(run_id)
    if checkpoint_id:
        meta["checkpoint_id"] = str(checkpoint_id)
    return build_packet(
        "audit_slice",
        payload,
        source_app=source_app,
        source_version=source_version,
        meta=meta,
    )


def build_compare_packet(
    *,
    diff_type: str,
    source_ids: list[str],
    diff: dict[str, Any],
    source_app: str = "role_aware_dashboard_toolkit",
    source_version: str = "",
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "schema_version": DIFF_PACKET_SCHEMA_VERSION,
        "diff_type": str(diff_type or ""),
        "source_ids": list(source_ids or []),
        "diff": dict(diff or {}),
    }
    return build_packet(
        "compare",
        payload,
        source_app=source_app,
        source_version=source_version,
        meta=meta,
    )


def build_ledger_packet(
    ledger: dict[str, Any],
    *,
    source_app: str = "role_aware_dashboard_toolkit",
    source_version: str = "",
) -> dict[str, Any]:
    return build_packet(
        "ledger",
        ledger,
        source_app=source_app,
        source_version=source_version,
        meta={"run_id": str(ledger.get("run_id") or "")},
    )


def export_packet_json(packet: dict[str, Any], *, indent: int = 2) -> str:
    if _nesting_exceeds(packet, MAX_PACKET_NESTING_DEPTH):
        raise _nesting_error("Cannot export invalid packet: ")
    validated = validate_packet(packet)
    if not validated["ok"]:
        raise ValueError("Cannot export invalid packet: " + "; ".join(validated["errors"]))
    canonical = {**packet, "packet_type": _normalize_packet_type(packet["packet_type"])}
    return json.dumps(canonical, indent=indent, sort_keys=True, allow_nan=False)


def load_packet_json(raw: str) -> dict[str, Any]:
    try:
        data = strict_json_loads(raw)
    except RecursionError:
        raise _nesting_error("Invalid packet JSON: ", may_cycle=False) from None
    if _nesting_exceeds(data, MAX_PACKET_NESTING_DEPTH):
        raise _nesting_error("Invalid packet JSON: ", may_cycle=False)
    validated = validate_packet(data)
    if not validated["ok"]:
        raise ValueError("Invalid packet JSON: " + "; ".join(validated["errors"]))
    data["packet_type"] = _normalize_packet_type(data["packet_type"])
    return data


def extract_packet_payload(packet: dict[str, Any]) -> dict[str, Any]:
    return dict(packet.get("payload") or {})


__all__ = [
    "DIFF_PACKET_SCHEMA_VERSION",
    "MAX_PACKET_NESTING_DEPTH",
    "PACKET_SCHEMA_VERSION",
    "VALID_PACKET_TYPES",
    "build_audit_slice_packet",
    "build_checkpoint_packet",
    "build_compare_packet",
    "build_ledger_packet",
    "build_packet",
    "build_profile_packet",
    "build_run_packet",
    "export_packet_json",
    "extract_packet_payload",
    "load_packet_json",
]
