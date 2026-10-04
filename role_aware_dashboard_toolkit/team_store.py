from __future__ import annotations

from typing import Any

from .store_diagnostics import (
    _JsonCollectionFileStoreMixin,
    canonical_store_id,
    json_roundtrip_copy,
)

DEFAULT_TEAM_OPS_DIR = "team_ops"


class BaseTeamStore:
    def save_comment(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def list_comments(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    def save_assignment(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def list_assignments(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    def save_signoff(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def list_signoffs(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    def save_handoff(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def list_handoffs(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError


class FileTeamStore(_JsonCollectionFileStoreMixin, BaseTeamStore):
    def __init__(self, root_dir: str = DEFAULT_TEAM_OPS_DIR) -> None:
        self._init_read_diagnostics()
        self.root_dir = root_dir

    def save_comment(self, record: dict[str, Any]) -> str:
        return self._save("comments", "comment_id", record)

    def list_comments(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list("comments", run_id=run_id, checkpoint_id=checkpoint_id)

    def save_assignment(self, record: dict[str, Any]) -> str:
        return self._save("assignments", "assignment_id", record)

    def list_assignments(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list("assignments", run_id=run_id, checkpoint_id=checkpoint_id)

    def save_signoff(self, record: dict[str, Any]) -> str:
        return self._save("signoffs", "signoff_id", record)

    def list_signoffs(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list("signoffs", run_id=run_id, checkpoint_id=checkpoint_id)

    def save_handoff(self, record: dict[str, Any]) -> str:
        return self._save("handoffs", "handoff_id", record)

    def list_handoffs(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list("handoffs", run_id=run_id, checkpoint_id=checkpoint_id)

    def _save(self, subdir: str, id_key: str, record: dict[str, Any]) -> str:
        return self._save_collection_record(subdir, id_key, record)

    def _list(self, subdir: str, *, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        rows = self._list_collection_records(subdir, id_key={'comments': 'comment_id', 'assignments': 'assignment_id', 'signoffs': 'signoff_id', 'handoffs': 'handoff_id'}[subdir], run_id=run_id, checkpoint_id=checkpoint_id)
        rows.sort(key=lambda item: (str(item.get("ts", "")), _stable_id(item)))
        return rows


class InMemoryTeamStore(BaseTeamStore):
    def __init__(self) -> None:
        self._comments: dict[str, dict[str, Any]] = {}
        self._assignments: dict[str, dict[str, Any]] = {}
        self._signoffs: dict[str, dict[str, Any]] = {}
        self._handoffs: dict[str, dict[str, Any]] = {}

    def save_comment(self, record: dict[str, Any]) -> str:
        return self._save(self._comments, "comment_id", record)

    def list_comments(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list(self._comments, run_id=run_id, checkpoint_id=checkpoint_id)

    def save_assignment(self, record: dict[str, Any]) -> str:
        return self._save(self._assignments, "assignment_id", record)

    def list_assignments(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list(self._assignments, run_id=run_id, checkpoint_id=checkpoint_id)

    def save_signoff(self, record: dict[str, Any]) -> str:
        return self._save(self._signoffs, "signoff_id", record)

    def list_signoffs(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list(self._signoffs, run_id=run_id, checkpoint_id=checkpoint_id)

    def save_handoff(self, record: dict[str, Any]) -> str:
        return self._save(self._handoffs, "handoff_id", record)

    def list_handoffs(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list(self._handoffs, run_id=run_id, checkpoint_id=checkpoint_id)

    @staticmethod
    def _save(bucket: dict[str, dict[str, Any]], id_key: str, record: dict[str, Any]) -> str:
        object_id = canonical_store_id(record.get(id_key))
        bucket[object_id] = json_roundtrip_copy({**record, id_key: object_id})
        return object_id

    @staticmethod
    def _list(bucket: dict[str, dict[str, Any]], *, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for record in bucket.values():
            if run_id and str(record.get("run_id") or "") != str(run_id):
                continue
            if checkpoint_id and str(record.get("checkpoint_id") or "") != str(checkpoint_id):
                continue
            rows.append(json_roundtrip_copy(record))
        rows.sort(key=lambda item: (str(item.get("ts", "")), _stable_id(item)))
        return rows

def _stable_id(record: dict[str, Any]) -> str:
    for key in ("comment_id", "assignment_id", "signoff_id", "handoff_id"):
        value = str(record.get(key) or "")
        if value:
            return value
    return ""


__all__ = [
    "DEFAULT_TEAM_OPS_DIR",
    "BaseTeamStore",
    "FileTeamStore",
    "InMemoryTeamStore",
]
