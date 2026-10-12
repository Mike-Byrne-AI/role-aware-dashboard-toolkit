from __future__ import annotations

from pathlib import Path
from typing import Any

from ._record_utils import _record_timestamp_key
from .store_diagnostics import (
    _JsonRecordFileStoreMixin,
    canonical_store_id,
    json_roundtrip_copy,
)

DEFAULT_CASEBOARD_DIR = "caseboard"


class BaseCaseStore:
    def save(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def load(self, case_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def list_ids(self) -> list[str]:
        raise NotImplementedError

    def list_cases(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_by_run(self, run_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError

    def list_by_incident(self, incident_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError


class FileCaseStore(_JsonRecordFileStoreMixin, BaseCaseStore):
    _record_store_dir_attr = "root_dir"
    _record_id_field = "case_id"

    def __init__(self, root_dir: str = DEFAULT_CASEBOARD_DIR) -> None:
        self._init_read_diagnostics()
        self.root_dir = root_dir

    def save(self, record: dict[str, Any]) -> str:
        case_id = canonical_store_id(record.get("case_id"))
        return self._save_record(record, case_id)

    def load(self, case_id: str) -> dict[str, Any] | None:
        return self._load_record(case_id)

    def list_ids(self) -> list[str]:
        return [str(item.get("case_id") or "") for item in self.list_cases() if str(item.get("case_id") or "")]

    def list_cases(self) -> list[dict[str, Any]]:
        rows = self._list_records()
        rows.sort(key=lambda item: (_record_timestamp_key(item.get("updated_at") or item.get("created_at")), str(item.get("case_id") or "")))
        return rows

    def list_by_run(self, run_id: str) -> list[dict[str, Any]]:
        needle = str(run_id or "")
        return [item for item in self.list_cases() if needle in set(str(value) for value in list(item.get("linked_run_ids") or []))]

    def list_by_incident(self, incident_id: str) -> list[dict[str, Any]]:
        needle = str(incident_id or "")
        return [item for item in self.list_cases() if needle in set(str(value) for value in list(item.get("linked_incident_ids") or []))]

    def resolve_path(self, case_id: str) -> Path | None:
        return self._resolve_record_path(case_id)


class InMemoryCaseStore(BaseCaseStore):
    def __init__(self) -> None:
        self._cases: dict[str, dict[str, Any]] = {}

    def save(self, record: dict[str, Any]) -> str:
        case_id = canonical_store_id(record.get("case_id"))
        self._cases[case_id] = json_roundtrip_copy({**record, "case_id": case_id})
        return case_id

    def load(self, case_id: str) -> dict[str, Any] | None:
        record = self._cases.get(canonical_store_id(case_id))
        if record is None:
            return None
        return json_roundtrip_copy(record)

    def list_ids(self) -> list[str]:
        return [str(item.get("case_id") or "") for item in self.list_cases() if str(item.get("case_id") or "")]

    def list_cases(self) -> list[dict[str, Any]]:
        rows = [json_roundtrip_copy(record) for record in self._cases.values()]
        rows.sort(key=lambda item: (_record_timestamp_key(item.get("updated_at") or item.get("created_at")), str(item.get("case_id") or "")))
        return rows

    def list_by_run(self, run_id: str) -> list[dict[str, Any]]:
        needle = str(run_id or "")
        return [item for item in self.list_cases() if needle in set(str(value) for value in list(item.get("linked_run_ids") or []))]

    def list_by_incident(self, incident_id: str) -> list[dict[str, Any]]:
        needle = str(incident_id or "")
        return [item for item in self.list_cases() if needle in set(str(value) for value in list(item.get("linked_incident_ids") or []))]

__all__ = [
    "DEFAULT_CASEBOARD_DIR",
    "BaseCaseStore",
    "FileCaseStore",
    "InMemoryCaseStore",
]
