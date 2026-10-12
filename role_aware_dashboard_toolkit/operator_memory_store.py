from __future__ import annotations

from typing import Any

from ._record_utils import _record_timestamp_key
from .store_diagnostics import (
    _JsonCollectionFileStoreMixin,
    canonical_store_id,
    json_roundtrip_copy,
)

DEFAULT_OPERATOR_MEMORY_DIR = "operator_memory"


class BaseOperatorMemoryStore:
    def save_note(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def list_notes(self, run_id: str = "", checkpoint_id: str = "", decision_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    def save_incident(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def list_incidents(self, run_id: str = "", checkpoint_id: str = "", decision_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError

    def save_narrative(self, record: dict[str, Any]) -> str:
        raise NotImplementedError

    def list_narratives(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        raise NotImplementedError


class FileOperatorMemoryStore(_JsonCollectionFileStoreMixin, BaseOperatorMemoryStore):
    _collection_store_dir_attr = "base_dir"

    def __init__(self, base_dir: str = DEFAULT_OPERATOR_MEMORY_DIR) -> None:
        self._init_read_diagnostics()
        self.base_dir = base_dir

    def save_note(self, record: dict[str, Any]) -> str:
        return self._save('notes', 'note_id', record)

    def list_notes(self, run_id: str = "", checkpoint_id: str = "", decision_id: str = "") -> list[dict[str, Any]]:
        return self._list('notes', run_id=run_id, checkpoint_id=checkpoint_id, decision_id=decision_id)

    def save_incident(self, record: dict[str, Any]) -> str:
        return self._save('incidents', 'incident_id', record)

    def list_incidents(self, run_id: str = "", checkpoint_id: str = "", decision_id: str = "") -> list[dict[str, Any]]:
        return self._list('incidents', run_id=run_id, checkpoint_id=checkpoint_id, decision_id=decision_id)

    def save_narrative(self, record: dict[str, Any]) -> str:
        return self._save('narratives', 'narrative_id', record)

    def list_narratives(self, run_id: str = "", checkpoint_id: str = "") -> list[dict[str, Any]]:
        return self._list('narratives', run_id=run_id, checkpoint_id=checkpoint_id)

    def _save(self, subdir: str, id_key: str, record: dict[str, Any]) -> str:
        return self._save_collection_record(subdir, id_key, record)

    def _list(self, subdir: str, *, run_id: str = '', checkpoint_id: str = '', decision_id: str = '') -> list[dict[str, Any]]:
        rows = self._list_collection_records(
            subdir,
            id_key={'notes': 'note_id', 'incidents': 'incident_id', 'narratives': 'narrative_id'}[subdir],
            run_id=run_id,
            checkpoint_id=checkpoint_id,
            decision_id=decision_id,
        )
        rows.sort(key=lambda item: (_record_timestamp_key(item.get('ts') or item.get('exported_at')), _stable_id(item)))
        return rows


class InMemoryOperatorMemoryStore(BaseOperatorMemoryStore):
    def __init__(self) -> None:
        self._notes: dict[str, dict[str, Any]] = {}
        self._incidents: dict[str, dict[str, Any]] = {}
        self._narratives: dict[str, dict[str, Any]] = {}

    def save_note(self, record: dict[str, Any]) -> str:
        return self._save(self._notes, 'note_id', record)

    def list_notes(self, run_id: str = '', checkpoint_id: str = '', decision_id: str = '') -> list[dict[str, Any]]:
        return self._list(self._notes, run_id=run_id, checkpoint_id=checkpoint_id, decision_id=decision_id)

    def save_incident(self, record: dict[str, Any]) -> str:
        return self._save(self._incidents, 'incident_id', record)

    def list_incidents(self, run_id: str = '', checkpoint_id: str = '', decision_id: str = '') -> list[dict[str, Any]]:
        return self._list(self._incidents, run_id=run_id, checkpoint_id=checkpoint_id, decision_id=decision_id)

    def save_narrative(self, record: dict[str, Any]) -> str:
        return self._save(self._narratives, 'narrative_id', record)

    def list_narratives(self, run_id: str = '', checkpoint_id: str = '') -> list[dict[str, Any]]:
        return self._list(self._narratives, run_id=run_id, checkpoint_id=checkpoint_id)

    @staticmethod
    def _save(bucket: dict[str, dict[str, Any]], id_key: str, record: dict[str, Any]) -> str:
        object_id = canonical_store_id(record.get(id_key))
        bucket[object_id] = json_roundtrip_copy({**record, id_key: object_id})
        return object_id

    @staticmethod
    def _list(bucket: dict[str, dict[str, Any]], *, run_id: str = '', checkpoint_id: str = '', decision_id: str = '') -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for record in bucket.values():
            if run_id and str(record.get('run_id') or '') != str(run_id):
                continue
            if checkpoint_id and str(record.get('checkpoint_id') or '') != str(checkpoint_id):
                continue
            if decision_id and str(record.get('decision_id') or '') != str(decision_id):
                continue
            rows.append(json_roundtrip_copy(record))
        rows.sort(key=lambda item: (_record_timestamp_key(item.get('ts') or item.get('exported_at')), _stable_id(item)))
        return rows


def _stable_id(record: dict[str, Any]) -> str:
    for key in ('note_id', 'incident_id', 'narrative_id'):
        value = str(record.get(key) or '')
        if value:
            return value
    return ''


__all__ = [
    'DEFAULT_OPERATOR_MEMORY_DIR',
    'BaseOperatorMemoryStore',
    'FileOperatorMemoryStore',
    'InMemoryOperatorMemoryStore',
]
