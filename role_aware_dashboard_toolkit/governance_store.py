from __future__ import annotations

from pathlib import Path
from typing import Any

from ._record_utils import _record_timestamp_key
from .store_diagnostics import (
    _JsonRecordFileStoreMixin,
    canonical_store_id,
    json_roundtrip_copy,
)

DEFAULT_GOVERNANCE_DIR = "governance"


class BaseGovernanceStore:
    def save(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def load(self, governance_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def list_ids(self) -> list[str]:
        raise NotImplementedError

    def list_records(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_by_case(self, case_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_by_run(self, run_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError


class FileGovernanceStore(_JsonRecordFileStoreMixin, BaseGovernanceStore):
    _record_store_dir_attr = "root_dir"
    _record_id_field = "governance_id"

    def __init__(self, root_dir: str = DEFAULT_GOVERNANCE_DIR) -> None:
        self._init_read_diagnostics()
        self.root_dir = root_dir

    def save(self, record: dict[str, Any]) -> str:
        governance_id = canonical_store_id(record.get("governance_id"))
        return self._save_record(record, governance_id)

    def load(self, governance_id: str) -> dict[str, Any] | None:
        return self._load_record(governance_id)

    def list_ids(self) -> list[str]:
        return [str(item.get("governance_id") or "") for item in self.list_records() if str(item.get("governance_id") or "")]

    def list_records(self) -> list[dict[str, Any]]:
        rows = self._list_records()
        rows.sort(key=lambda item: (_record_timestamp_key(item.get("updated_at") or item.get("created_at")), str(item.get("governance_id") or "")))
        return rows

    def list_by_case(self, case_id: str) -> list[dict[str, Any]]:
        needle = str(case_id or "")
        return [item for item in self.list_records() if str(item.get("case_id") or "") == needle]

    def list_by_run(self, run_id: str) -> list[dict[str, Any]]:
        needle = str(run_id or "")
        return [item for item in self.list_records() if needle in set(str(value) for value in list(item.get("linked_run_ids") or []))]

    def resolve_path(self, governance_id: str) -> Path | None:
        return self._resolve_record_path(governance_id)


class InMemoryGovernanceStore(BaseGovernanceStore):
    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}

    def save(self, record: dict[str, Any]) -> str:
        governance_id = canonical_store_id(record.get("governance_id"))
        self._records[governance_id] = json_roundtrip_copy({**record, "governance_id": governance_id})
        return governance_id

    def load(self, governance_id: str) -> dict[str, Any] | None:
        record = self._records.get(canonical_store_id(governance_id))
        if record is None:
            return None
        return json_roundtrip_copy(record)

    def list_ids(self) -> list[str]:
        return [str(item.get("governance_id") or "") for item in self.list_records() if str(item.get("governance_id") or "")]

    def list_records(self) -> list[dict[str, Any]]:
        rows = [json_roundtrip_copy(record) for record in self._records.values()]
        rows.sort(key=lambda item: (_record_timestamp_key(item.get("updated_at") or item.get("created_at")), str(item.get("governance_id") or "")))
        return rows

    def list_by_case(self, case_id: str) -> list[dict[str, Any]]:
        needle = str(case_id or "")
        return [item for item in self.list_records() if str(item.get("case_id") or "") == needle]

    def list_by_run(self, run_id: str) -> list[dict[str, Any]]:
        needle = str(run_id or "")
        return [item for item in self.list_records() if needle in set(str(value) for value in list(item.get("linked_run_ids") or []))]

__all__ = [
    "DEFAULT_GOVERNANCE_DIR",
    "BaseGovernanceStore",
    "FileGovernanceStore",
    "InMemoryGovernanceStore",
]
