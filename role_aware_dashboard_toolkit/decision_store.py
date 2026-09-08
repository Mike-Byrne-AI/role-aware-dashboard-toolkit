from __future__ import annotations

from typing import Any

from .store_diagnostics import (
    _JsonRecordFileStoreMixin,
    json_roundtrip_copy,
    sorted_store_ids,
)

DEFAULT_DECISION_DIR = "decisions"


class BaseDecisionStore:
    def save(self, decision: dict[str, Any]) -> str:
        raise NotImplementedError

    def load(self, decision_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def delete(self, decision_id: str) -> bool:
        raise NotImplementedError

    def list_ids(self) -> list[str]:
        raise NotImplementedError

    def list_by_run(self, run_id: str, checkpoint_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError


class FileDecisionStore(_JsonRecordFileStoreMixin, BaseDecisionStore):
    _record_store_dir_attr = "decision_dir"
    _record_id_field = "decision_id"

    def __init__(self, decision_dir: str = DEFAULT_DECISION_DIR) -> None:
        self._init_read_diagnostics()
        self.decision_dir = decision_dir

    def save(self, decision: dict[str, Any]) -> str:
        decision_id = str(decision.get("decision_id") or "").strip() or "default"
        return self._save_record(decision, decision_id)

    def load(self, decision_id: str) -> dict[str, Any] | None:
        return self._load_record(decision_id)

    def delete(self, decision_id: str) -> bool:
        return self._delete_record(decision_id)

    def list_ids(self) -> list[str]:
        names = [str(loaded.get("decision_id") or path.stem) for path, loaded in self._list_record_items()]
        return sorted_store_ids(names)

    def list_by_run(self, run_id: str, checkpoint_id: str = "") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for loaded in self._list_records():
            if str(loaded.get("run_id") or "") != str(run_id):
                continue
            if checkpoint_id and str(loaded.get("checkpoint_id") or "") != str(checkpoint_id):
                continue
            rows.append(loaded)
        rows.sort(key=lambda item: (str(item.get("updated_at", "")), str(item.get("decision_id", ""))))
        return rows

    def resolve_path(self, decision_id: str) -> str | None:
        path = self._resolve_record_path(decision_id)
        return str(path) if path is not None else None


class InMemoryDecisionStore(BaseDecisionStore):
    def __init__(self) -> None:
        self._decisions: dict[str, dict[str, Any]] = {}

    def save(self, decision: dict[str, Any]) -> str:
        decision_id = str(decision.get("decision_id") or "").strip() or "default"
        self._decisions[decision_id] = json_roundtrip_copy(decision)
        return decision_id

    def load(self, decision_id: str) -> dict[str, Any] | None:
        data = self._decisions.get(str(decision_id))
        if data is None:
            return None
        return json_roundtrip_copy(data)

    def delete(self, decision_id: str) -> bool:
        return self._decisions.pop(str(decision_id), None) is not None

    def list_ids(self) -> list[str]:
        return sorted_store_ids(self._decisions.keys())

    def list_by_run(self, run_id: str, checkpoint_id: str = "") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for record in self._decisions.values():
            if str(record.get("run_id") or "") != str(run_id):
                continue
            if checkpoint_id and str(record.get("checkpoint_id") or "") != str(checkpoint_id):
                continue
            rows.append(json_roundtrip_copy(record))
        rows.sort(key=lambda item: (str(item.get("updated_at", "")), str(item.get("decision_id", ""))))
        return rows

__all__ = [
    "DEFAULT_DECISION_DIR",
    "BaseDecisionStore",
    "FileDecisionStore",
    "InMemoryDecisionStore",
]
