from __future__ import annotations

from typing import Any

from .store_diagnostics import (
    _JsonRecordFileStoreMixin,
    json_roundtrip_copy,
    sorted_store_ids,
)

DEFAULT_RUN_DIR = "runs"


class BaseRunStore:
    def save(self, run: dict[str, Any]) -> str:
        raise NotImplementedError

    def load(self, run_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def delete(self, run_id: str) -> bool:
        raise NotImplementedError

    def list_ids(self) -> list[str]:
        raise NotImplementedError


class FileRunStore(_JsonRecordFileStoreMixin, BaseRunStore):
    _record_store_dir_attr = "run_dir"
    _record_id_field = "run_id"

    def __init__(self, run_dir: str = DEFAULT_RUN_DIR) -> None:
        self._init_read_diagnostics()
        self.run_dir = run_dir

    def save(self, run: dict[str, Any]) -> str:
        run_id = str(run.get("run_id") or "").strip() or "default"
        return self._save_record(run, run_id)

    def load(self, run_id: str) -> dict[str, Any] | None:
        return self._load_record(run_id)

    def delete(self, run_id: str) -> bool:
        return self._delete_record(run_id)

    def list_ids(self) -> list[str]:
        names = [str(loaded.get("run_id") or path.stem) for path, loaded in self._list_record_items()]
        return sorted_store_ids(names)

    def resolve_path(self, run_id: str) -> str | None:
        path = self._resolve_record_path(run_id)
        return str(path) if path is not None else None


class InMemoryRunStore(BaseRunStore):
    def __init__(self) -> None:
        self._runs: dict[str, dict[str, Any]] = {}

    def save(self, run: dict[str, Any]) -> str:
        run_id = str(run.get("run_id") or "").strip() or "default"
        self._runs[run_id] = json_roundtrip_copy(run)
        return run_id

    def load(self, run_id: str) -> dict[str, Any] | None:
        data = self._runs.get(str(run_id))
        if data is None:
            return None
        return json_roundtrip_copy(data)

    def delete(self, run_id: str) -> bool:
        return self._runs.pop(str(run_id), None) is not None

    def list_ids(self) -> list[str]:
        return sorted_store_ids(self._runs.keys())

__all__ = [
    "DEFAULT_RUN_DIR",
    "BaseRunStore",
    "FileRunStore",
    "InMemoryRunStore",
]
