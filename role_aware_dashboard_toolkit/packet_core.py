from __future__ import annotations

import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .path_redaction import redact_payload_local_paths

_PACKET_RESERVED_PAYLOAD_KEYS = frozenset({"repo_root", "schema_version"})
_PACKET_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

PACKET_SCHEMA_VERSION = 1
# A packet nests at most this many mappings and lists, counting the envelope.
# Deeper or cyclic values are refused with ValueError before redaction or JSON
# encoding could recurse past Python's limit.
MAX_PACKET_NESTING_DEPTH = 100
_CONTAINER_TYPES = (Mapping, list, tuple, set, frozenset)
DIFF_PACKET_SCHEMA_VERSION = 1
VALID_PACKET_TYPES = (
    "profile",
    "run",
    "checkpoint",
    "audit_slice",
    "compare",
    "replay",
    "ledger",
    "narrative_handoff",
)


def _normalize_packet_type(packet_type: Any) -> str:
    """Apply the same identifier rules to construction, import and export."""
    normalized_type = str(packet_type or "").strip().lower()
    if not _PACKET_TYPE_PATTERN.fullmatch(normalized_type):
        raise ValueError(
            "packet_type must be 1-64 characters, start with a lowercase letter "
            "and contain only lowercase letters, digits, and underscores"
        )
    if normalized_type not in VALID_PACKET_TYPES and not normalized_type.startswith("x_"):
        raise ValueError(
            f"Unknown packet_type '{normalized_type}'. "
            "Custom packet types must use an 'x_' prefix."
        )
    return normalized_type


def _nesting_exceeds(value: Any, limit: int) -> bool:
    """Return whether ``value`` nests more than ``limit`` containers deep.

    Levels are walked breadth-first without recursion. A container reached
    twice on one level is walked once, so shared values stay cheap and a cycle
    simply counts as too deep.
    """
    level = [value] if isinstance(value, _CONTAINER_TYPES) else []
    depth = 0
    while level:
        depth += 1
        if depth > limit:
            return True
        seen: set[int] = set()
        next_level: list[Any] = []
        for container in level:
            items = container.values() if isinstance(container, Mapping) else container
            for item in items:
                if isinstance(item, _CONTAINER_TYPES) and id(item) not in seen:
                    seen.add(id(item))
                    next_level.append(item)
        level = next_level
    return False


def _nesting_error(prefix: str, *, may_cycle: bool = True) -> ValueError:
    cycle = ", or contains a cycle" if may_cycle else ""
    return ValueError(
        f"{prefix}nesting exceeds {MAX_PACKET_NESTING_DEPTH} levels of mappings "
        f"and lists, counting the envelope{cycle}."
    )


def build_packet(
    packet_type: str,
    payload: dict[Any, Any],
    *,
    packet_id: str = "",
    source_app: str = "role_aware_dashboard_toolkit",
    source_version: str = "",
    meta: dict[str, Any] | None = None,
    repo_root: str | os.PathLike[Any] = "",
    include_local_paths: bool = False,
) -> dict[str, Any]:
    """Build a redacted packet envelope for a built-in or namespaced extension.

    Applications can define extension packets with an ``x_`` prefix. Role-Aware Dashboard Toolkit
    validates the envelope while leaving the extension payload contract with
    the application.
    """

    normalized_type = _normalize_packet_type(packet_type)

    payload_copy = dict(payload or {})
    # Payload and metadata sit one level below the envelope.
    if _nesting_exceeds(payload_copy, MAX_PACKET_NESTING_DEPTH - 1):
        raise _nesting_error("Packet payload ")
    if _nesting_exceeds(dict(meta or {}), MAX_PACKET_NESTING_DEPTH - 1):
        raise _nesting_error("Packet metadata ")
    if isinstance(repo_root, os.PathLike):
        resolved_repo_root: str | os.PathLike[Any] = repo_root
    elif isinstance(repo_root, str):
        resolved_repo_root = str.__str__(repo_root) or payload_copy.get("repo_root", "")
    else:
        resolved_repo_root = repo_root or payload_copy.get("repo_root", "")

    payload_copy = redact_payload_local_paths(
        payload_copy,
        repo_root=resolved_repo_root,
        include_local_paths=include_local_paths,
        _reserved_top_level_keys=_PACKET_RESERVED_PAYLOAD_KEYS,
    )
    meta_copy = redact_payload_local_paths(
        dict(meta or {}),
        repo_root=resolved_repo_root,
        include_local_paths=include_local_paths,
    )
    return {
        "schema_version": PACKET_SCHEMA_VERSION,
        "packet_type": normalized_type,
        "packet_id": str(packet_id or f"pkt_{uuid4().hex[:12]}"),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source_app": str(source_app or "role_aware_dashboard_toolkit"),
        "source_version": str(source_version or ""),
        "payload_schema_version": payload_copy.get("schema_version", ""),
        "payload": payload_copy,
        "meta": meta_copy,
    }


__all__ = [
    "DIFF_PACKET_SCHEMA_VERSION",
    "MAX_PACKET_NESTING_DEPTH",
    "PACKET_SCHEMA_VERSION",
    "VALID_PACKET_TYPES",
    "build_packet",
]
