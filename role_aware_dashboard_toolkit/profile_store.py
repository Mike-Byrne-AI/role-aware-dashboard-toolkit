from __future__ import annotations

from typing import Any

from .store_diagnostics import (
    _JsonRecordFileStoreMixin,
    json_roundtrip_copy,
    sorted_store_ids,
)

PROFILE_SCHEMA_VERSION = 3
DEFAULT_PROFILE_DIR = "profiles"


class BaseProfileStore:
    """Storage adapter for Role-Aware Dashboard Toolkit profiles."""

    def save(self, profile: dict[str, Any]) -> str:
        raise NotImplementedError

    def load(self, profile_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def delete(self, profile_id: str) -> bool:
        raise NotImplementedError

    def list_ids(self) -> list[str]:
        raise NotImplementedError


class FileProfileStore(_JsonRecordFileStoreMixin, BaseProfileStore):
    _record_store_dir_attr = "profile_dir"
    _record_id_field = "profile_id"

    def __init__(self, profile_dir: str = DEFAULT_PROFILE_DIR) -> None:
        self._init_read_diagnostics()
        self.profile_dir = profile_dir

    def save(self, profile: dict[str, Any]) -> str:
        profile_id = str(profile.get("profile_id") or "").strip() or "default"
        return self._save_record(profile, profile_id)

    def load(self, profile_id: str) -> dict[str, Any] | None:
        return self._load_record(profile_id)

    def delete(self, profile_id: str) -> bool:
        return self._delete_record(profile_id)

    def list_ids(self) -> list[str]:
        names = [str(loaded.get("profile_id") or path.stem) for path, loaded in self._list_record_items()]
        return sorted_store_ids(names, dedupe=True)

    def resolve_path(self, profile_id: str) -> str | None:
        path = self._resolve_record_path(profile_id)
        return str(path) if path is not None else None


class InMemoryProfileStore(BaseProfileStore):
    def __init__(self) -> None:
        self._profiles: dict[str, dict[str, Any]] = {}

    def save(self, profile: dict[str, Any]) -> str:
        profile_id = str(profile.get("profile_id") or "").strip() or "default"
        self._profiles[profile_id] = json_roundtrip_copy(profile)
        return profile_id

    def load(self, profile_id: str) -> dict[str, Any] | None:
        data = self._profiles.get(str(profile_id))
        if data is None:
            return None
        return json_roundtrip_copy(data)

    def delete(self, profile_id: str) -> bool:
        return self._profiles.pop(str(profile_id), None) is not None

    def list_ids(self) -> list[str]:
        return sorted_store_ids(self._profiles.keys(), dedupe=False)


__all__ = [
    "DEFAULT_PROFILE_DIR",
    "PROFILE_SCHEMA_VERSION",
    "BaseProfileStore",
    "FileProfileStore",
    "InMemoryProfileStore",
]
