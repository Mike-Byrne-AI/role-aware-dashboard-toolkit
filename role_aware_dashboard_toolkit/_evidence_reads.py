"""Read native review evidence without mistaking failed reads for empty stores."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .security import has_perm
from .validators import validate_record


class EvidenceUnavailable(RuntimeError):
    """Safe internal signal; never retain store diagnostics or exception text."""

    def __init__(self) -> None:
        super().__init__("Review evidence is unavailable or incomplete.")


@dataclass(frozen=True)
class EvidenceRead:
    status: Literal["complete", "unconfigured", "missing", "failed", "denied"]
    records: list[dict[str, Any]] = field(default_factory=list)

    def require_complete(self) -> list[dict[str, Any]]:
        # An optional, unconfigured source is intentionally absent. A configured
        # source whose records could not be read is never equivalent to it.
        if self.status not in {"complete", "unconfigured"}:
            raise EvidenceUnavailable()
        return self.records


def read_evidence(
    store: Any,
    method: str,
    *args: Any,
    record_type: str,
    ctx: Any = None,
    permission: str | None = None,
    single: bool = False,
    **kwargs: Any,
) -> EvidenceRead:
    if store is None:
        return EvidenceRead("unconfigured")
    try:
        if ctx is not None and permission and not has_perm(ctx, permission):
            return EvidenceRead("denied")
        errors_before = len(getattr(store, "read_errors", ()) or ())
        records = getattr(store, method)(*args, **kwargs)
        if len(getattr(store, "read_errors", ()) or ()) > errors_before:
            return EvidenceRead("failed")
        if single:
            if records is None:
                return EvidenceRead("missing")
            records = [records]
        if not isinstance(records, list) or any(
            not isinstance(record, dict) or not validate_record(record_type, record)["ok"]
            for record in records
        ):
            return EvidenceRead("failed")
        # A provider read can outlast a grant, account, or freeze-state change.
        # Discard the fetched contents if its read authority has since expired.
        if ctx is not None and permission and not has_perm(ctx, permission):
            return EvidenceRead("denied")
        return EvidenceRead("complete", records)
    except Exception:
        # Provider/store exceptions and diagnostics may contain private paths or
        # record contents. Only the operation's completeness crosses into UI.
        return EvidenceRead("failed")


def read_records(store: Any, method: str, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    return read_evidence(store, method, *args, **kwargs).require_complete()


def read_record(store: Any, method: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
    result = read_evidence(store, method, *args, single=True, **kwargs)
    records = result.require_complete()
    if len(records) != 1:
        raise EvidenceUnavailable()
    return records[0]


def require_evidence_permissions(ctx: Any, *permissions: str) -> None:
    """Recheck every contributing source after a multi-source read completes."""
    if ctx is not None and any(not has_perm(ctx, permission) for permission in permissions):
        raise EvidenceUnavailable()


def warn_incomplete_evidence(st: Any) -> None:
    st.warning(
        "Review evidence could not be read completely or is not available to your role. "
        "This view and its dependent saves are unavailable. Check access and storage, then retry."
    )
