from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import stat
import tempfile
import warnings
from pathlib import Path
from typing import Any
from collections.abc import Iterable, MutableSequence

from ._json_safety import strict_json_loads
from .path_redaction import redact_diagnostic_path, redact_text_local_paths


StoreReadError = dict[str, str]

_LOGGER = logging.getLogger(__name__)
_STORE_RECORD_DESCRIPTOR_FLAGS = (
    getattr(os, "O_BINARY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOINHERIT", 0)
    | getattr(os, "O_NOCTTY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_STORE_RECORD_OPEN_FLAGS = os.O_RDONLY | _STORE_RECORD_DESCRIPTOR_FLAGS
_STORE_RECORD_APPEND_FLAGS = (
    os.O_WRONLY | os.O_APPEND | _STORE_RECORD_DESCRIPTOR_FLAGS
)
_STORE_RECORD_CREATE_FLAGS = (
    _STORE_RECORD_APPEND_FLAGS | os.O_CREAT | os.O_EXCL
)
_STORE_RECORD_READ_CHUNK_BYTES = 64 * 1024
_STORE_FILENAME_MAX_BYTES = 255
_STORE_RECORD_CHANGED_MESSAGE = "store record changed between validation and read"
_STORE_RECORD_APPEND_CHANGED_MESSAGE = (
    "store append target changed between validation and write"
)
_STORE_RECORD_UNSAFE_MESSAGE = (
    "store record must be a single-link regular file with stable identity"
)
_STORE_RECORD_APPEND_UNSAFE_MESSAGE = (
    "store append target must be a single-link regular file"
)


class StorePathSecurityError(Exception):
    """Raised when a store path fails boundary or file-identity checks."""


class StoreReadDiagnosticsMixin:
    def _init_read_diagnostics(self) -> None:
        self._read_errors: list[StoreReadError] = []

    @property
    def read_errors(self) -> list[StoreReadError]:
        return list(self._read_errors)

    def clear_read_errors(self) -> None:
        self._read_errors.clear()


def _directory_enumeration_error_message(exc: OSError | ValueError | RuntimeError) -> str:
    error_code = getattr(exc, "errno", None)
    code_suffix = (
        f" (errno {error_code})"
        if isinstance(error_code, int) and not isinstance(error_code, bool)
        else ""
    )
    return f"{type(exc).__name__}: JSON store directory enumeration failed{code_suffix}"


def _directory_enumeration_error_path(directory: Path, *, root_dir: Path) -> str:
    try:
        relative = directory.relative_to(root_dir)
    except ValueError:
        return "<outside-store-root>"
    if relative.parts:
        return relative.as_posix()
    label = directory.name or "."
    if not label.isprintable():
        return "<invalid-store-path>"
    return label


def _directory_enumeration_read_error(
    directory: Path,
    exc: OSError | ValueError | RuntimeError,
    *,
    root_dir: Path,
) -> StoreReadError:
    error_type = type(exc).__name__
    return {
        "path": _directory_enumeration_error_path(directory, root_dir=root_dir),
        "error_type": error_type,
        "exception_type": error_type,
        "message": _directory_enumeration_error_message(exc),
    }


def _list_json_record_paths(
    directory: Path,
    errors: MutableSequence[StoreReadError],
    *,
    root_dir: Path,
) -> list[Path]:
    paths: list[Path] = []
    try:
        entries = os.scandir(directory)
    except (FileNotFoundError, NotADirectoryError):
        return paths
    except (OSError, ValueError, RuntimeError) as exc:
        errors.append(_directory_enumeration_read_error(directory, exc, root_dir=root_dir))
        return paths

    try:
        with entries:
            for entry in entries:
                if Path(entry.name).match("*.json"):
                    paths.append(directory / entry.name)
    except (OSError, ValueError, RuntimeError) as exc:
        errors.append(_directory_enumeration_read_error(directory, exc, root_dir=root_dir))
    return sorted(paths)


class _JsonRecordFileStoreMixin(StoreReadDiagnosticsMixin):
    _record_store_dir_attr = "root_dir"
    _record_id_field = ""

    def _record_store_root(self) -> Path:
        return Path(str(getattr(self, self._record_store_dir_attr)))

    def _default_record_id(self, value: Any) -> str:
        return canonical_store_id(value)

    def _record_id_from_payload(self, payload: dict[str, Any]) -> str:
        return self._default_record_id(payload.get(self._record_id_field))

    def _save_record(self, record: dict[str, Any], record_id: str | None = None) -> str:
        resolved_id = self._default_record_id(record_id) if record_id is not None else self._record_id_from_payload(record)
        path = self._path_for_write(resolved_id)
        atomic_write_json_record(path, {**record, self._record_id_field: resolved_id}, root_dir=self._record_store_root())
        return str(path)

    def _load_record(self, record_id: str) -> dict[str, Any] | None:
        path = self._resolve_record_path(record_id, diagnose_read_errors=True)
        if path is None:
            return None
        return self._read_path(path)

    def _delete_record(self, record_id: str) -> bool:
        path = self._resolve_record_path(record_id)
        if path is None:
            return False
        return safe_delete_store_record(path, root_dir=self._record_store_root())

    def _list_record_items(self) -> list[tuple[Path, dict[str, Any]]]:
        root = self._record_store_root()
        rows: list[tuple[Path, dict[str, Any]]] = []
        for path in _list_json_record_paths(root, self._read_errors, root_dir=root):
            loaded = self._read_path(path)
            if isinstance(loaded, dict):
                rows.append((path, loaded))
        return rows

    def _list_records(self) -> list[dict[str, Any]]:
        return [record for _path, record in self._list_record_items()]

    def _resolve_record_path(
        self,
        record_id: str,
        *,
        diagnose_read_errors: bool = False,
    ) -> Path | None:
        root = self._record_store_root()
        identifier = canonical_store_id(record_id)
        try:
            path = self._path_for_write(identifier)
        except (OSError, ValueError, RuntimeError, StorePathSecurityError) as exc:
            if not diagnose_read_errors:
                raise
            path = root / f"{hashed_store_filename(identifier)}.json"
            self._read_errors.append(build_read_error(path, exc, root_dir=root))
            return None
        if not diagnose_read_errors:
            if path.is_file():
                return path
            return None
        try:
            path_mode = path.stat(follow_symlinks=False).st_mode
        except (FileNotFoundError, NotADirectoryError):
            return None
        except (OSError, ValueError, RuntimeError) as exc:
            self._read_errors.append(build_read_error(path, exc, root_dir=root))
            return None
        if stat.S_ISREG(path_mode) or stat.S_ISLNK(path_mode):
            return path
        return None

    def _path_for_write(self, record_id: str) -> Path:
        return _record_file_path(self._record_store_root(), record_id)

    def _read_path(self, path: Path) -> dict[str, Any] | None:
        record = read_json_record(path, self._read_errors, root_dir=self._record_store_root())
        if record is not None:
            # Old files can retain an untrimmed ID while their filename already
            # uses the canonical ID. Normalize the detached result, not the file.
            record[self._record_id_field] = canonical_store_id(record.get(self._record_id_field))
            try:
                self._path_for_write(record[self._record_id_field])
            except (OSError, ValueError, RuntimeError, StorePathSecurityError) as exc:
                self._read_errors.append(build_read_error(path, exc, root_dir=self._record_store_root()))
                return None
        return record


class _JsonCollectionFileStoreMixin(StoreReadDiagnosticsMixin):
    _collection_store_dir_attr = "root_dir"

    def _collection_store_root(self) -> Path:
        return Path(str(getattr(self, self._collection_store_dir_attr)))

    def _save_collection_record(self, subdir: str, id_key: str, record: dict[str, Any]) -> str:
        object_id = canonical_store_id(record.get(id_key))
        store_root = self._collection_store_root()
        target_dir = store_root / subdir
        path = _record_file_path(target_dir, object_id)
        atomic_write_json_record(path, {**record, id_key: object_id}, root_dir=store_root)
        return str(path)

    def _list_collection_records(self, subdir: str, *, id_key: str = "", **filters: Any) -> list[dict[str, Any]]:
        store_root = self._collection_store_root()
        target_dir = store_root / subdir
        try:
            safe_store_write_path(target_dir, root_dir=store_root)
        except (FileNotFoundError, NotADirectoryError):
            return []
        except StorePathSecurityError as exc:
            self._read_errors.append(build_read_error(target_dir, exc, root_dir=store_root))
            return []
        except (OSError, ValueError, RuntimeError) as exc:
            self._read_errors.append(_directory_enumeration_read_error(target_dir, exc, root_dir=store_root))
            return []

        rows: list[dict[str, Any]] = []
        for path in _list_json_record_paths(target_dir, self._read_errors, root_dir=store_root):
            loaded = read_json_record(path, self._read_errors, root_dir=store_root)
            if loaded is None:
                continue
            if id_key:
                loaded[id_key] = canonical_store_id(loaded.get(id_key))
                try:
                    _record_file_path(target_dir, loaded[id_key])
                except (OSError, ValueError, RuntimeError, StorePathSecurityError) as exc:
                    self._read_errors.append(build_read_error(path, exc, root_dir=store_root))
                    continue
            if any(value and str(loaded.get(key) or "") != str(value) for key, value in filters.items()):
                continue
            rows.append(loaded)
        return rows


def read_json_record(
    path: Path,
    errors: MutableSequence[StoreReadError] | None = None,
    *,
    root_dir: Path | None = None,
) -> dict[str, Any] | None:
    rendered = read_text_record(path, errors, root_dir=root_dir)
    if rendered is None:
        return None
    try:
        loaded = strict_json_loads(rendered)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        if errors is not None:
            errors.append(build_read_error(path, exc, root_dir=root_dir))
        return None
    if not isinstance(loaded, dict):
        if errors is not None:
            errors.append(
                {
                    "path": _diagnostic_path(path, root_dir=root_dir),
                    "error_type": type(loaded).__name__,
                    "exception_type": type(loaded).__name__,
                    "message": "JSON store record must be an object",
                }
            )
        return None
    return loaded


def read_text_record(
    path: Path,
    errors: MutableSequence[StoreReadError] | None = None,
    *,
    root_dir: Path | None = None,
) -> str | None:
    expected_stat = _probe_safe_store_read_file(path, root_dir=root_dir, errors=errors)
    if expected_stat is None:
        return None
    try:
        return _read_validated_store_text(path, expected_stat)
    except (FileNotFoundError, NotADirectoryError):
        try:
            path.stat(follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except (OSError, ValueError, RuntimeError) as probe_exc:
            if errors is not None:
                errors.append(build_read_error(path, probe_exc, root_dir=root_dir))
            return None
        if errors is not None:
            errors.append(
                build_read_error(
                    path,
                    StorePathSecurityError(_STORE_RECORD_CHANGED_MESSAGE),
                    root_dir=root_dir,
                )
            )
        return None
    except (
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        StorePathSecurityError,
    ) as exc:
        if errors is not None:
            errors.append(build_read_error(path, exc, root_dir=root_dir))
        return None


def append_text_record(
    path: Path,
    text: str,
    *,
    root_dir: Path | None = None,
) -> Path:
    target = _resolve_safe_store_write_path(path, root_dir=root_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    expected_stat = _probe_safe_store_append_file(target)
    _append_validated_store_text(target, text, expected_stat)
    return target


def atomic_write_json_record(path: Path, value: dict[str, Any], *, root_dir: Path | None = None) -> Path:
    rendered = json.dumps(
        value,
        indent=2,
        ensure_ascii=False,
        default=str,
        allow_nan=False,
    )
    return atomic_write_text_record(path, rendered, root_dir=root_dir)


def atomic_write_text_record(path: Path, text: str, *, root_dir: Path | None = None) -> Path:
    target = _resolve_safe_store_write_path(path, root_dir=root_dir)
    target.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        # The temporary name needs its own budget: a valid final filename can
        # already occupy the filesystem's entire component length allowance.
        prefix=".radt-record-",
        suffix=".tmp",
        dir=str(target.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_path, target)
    except Exception as write_exc:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError as cleanup_exc:
            diagnostic_root = Path(root_dir) if root_dir is not None else tmp_path.parent
            temp_label = _diagnostic_path(tmp_path, root_dir=diagnostic_root)
            write_message = redact_text_local_paths(str(write_exc), repo_root=str(diagnostic_root))
            cleanup_message = redact_text_local_paths(str(cleanup_exc), repo_root=str(diagnostic_root))
            warnings.warn(
                "Best-effort store temp cleanup failed after "
                f"{type(write_exc).__name__}: {write_message}; "
                f"temp={temp_label}; cleanup failure: {type(cleanup_exc).__name__}: {cleanup_message}",
                RuntimeWarning,
                stacklevel=2,
            )
        raise
    return target


def safe_delete_store_record(path: Path, *, root_dir: Path | None = None) -> bool:
    target = _resolve_safe_store_write_path(path, root_dir=root_dir)
    try:
        target.unlink()
    except FileNotFoundError:
        return False
    return True


def safe_store_write_path(path: Path, *, root_dir: Path | None = None) -> Path:
    return _resolve_safe_store_write_path(path, root_dir=root_dir)


def canonical_store_id(value: Any) -> str:
    """Use the existing write identity policy for payloads and lookups alike."""
    return str(value or "").strip() or "default"


def json_roundtrip_copy(value: Any) -> Any:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        default=str,
        allow_nan=False,
    )
    return strict_json_loads(rendered)


def safe_store_filename(name: Any, *, default: str = "default") -> str:
    safe = "".join(ch for ch in str(name) if ch.isalnum() or ch in ("_", "-")).strip("_-")
    return safe or str(default or "default")


def _unbounded_hashed_store_filename(name: Any, *, default: str = "default", digest_len: int = 10) -> str:
    identifier = str(name)
    safe_id = safe_store_filename(identifier, default=default)
    digest = hashlib.sha1(identifier.encode("utf-8")).hexdigest()[: max(1, int(digest_len))]
    return f"{safe_id}-{digest}"


def hashed_store_filename(name: Any, *, default: str = "default", digest_len: int = 10) -> str:
    """Keep the full identifier's hash and bound the readable prefix for JSON files."""
    original = _unbounded_hashed_store_filename(name, default=default, digest_len=digest_len)
    prefix, _, digest = original.rpartition("-")
    prefix_bytes = _STORE_FILENAME_MAX_BYTES - len(".json") - len(digest) - 1
    # Encoding starts valid; ignore only a partial final code point at the cut.
    bounded_prefix = prefix.encode("utf-8")[:prefix_bytes].decode("utf-8", errors="ignore")
    return f"{bounded_prefix}-{digest}"


def _record_file_path(directory: Path, identifier: str) -> Path:
    """Reuse an exact existing legacy filename before choosing a bounded new one.

    NTFS can hold Unicode components whose UTF-8 representation exceeds 255
    bytes. A changed naming budget must not orphan or duplicate those records.
    This only selects a path; callers still enforce normal store path safety.
    """
    target = directory / f"{hashed_store_filename(identifier)}.json"
    legacy_name = f"{_unbounded_hashed_store_filename(identifier)}.json"
    if legacy_name == target.name:
        return target
    if os.name == "nt" and len(legacy_name.encode("utf-16-le")) > 510:
        # No prior NTFS component could have used this many UTF-16 code units.
        return target
    legacy = directory / legacy_name
    try:
        # Do not follow a link or silently replace an unsafe legacy record with
        # a second file. Returning it lets the existing safety boundary reject it.
        legacy.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return target
    except OSError as exc:
        if exc.errno == errno.ENAMETOOLONG or getattr(exc, "winerror", None) == 206:
            return target
        raise
    try:
        target.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return legacy
    raise StorePathSecurityError("ambiguous store record has both legacy and bounded filenames")


def sorted_store_ids(values: Iterable[Any], *, dedupe: bool = True) -> list[str]:
    rows = [str(value) for value in values if str(value).strip()]
    if dedupe:
        rows = list(set(rows))
    return sorted(rows, key=lambda name: str(name).lower())


def _read_error(path: Path, exc: Exception) -> StoreReadError:
    return build_read_error(path, exc)


def _probe_safe_store_read_file(
    path: Path,
    *,
    root_dir: Path | None,
    errors: MutableSequence[StoreReadError] | None,
) -> os.stat_result | None:
    try:
        _resolve_safe_store_write_path(path, root_dir=root_dir)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (OSError, ValueError, RuntimeError, StorePathSecurityError) as exc:
        if errors is not None:
            errors.append(build_read_error(path, exc, root_dir=root_dir))
        return None

    try:
        path_stat = path.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except (OSError, ValueError, RuntimeError) as exc:
        if errors is not None:
            errors.append(build_read_error(path, exc, root_dir=root_dir))
        return None

    if stat.S_ISLNK(path_stat.st_mode):
        exc = StorePathSecurityError("symlinked store record is not allowed")
        if errors is not None:
            errors.append(build_read_error(path, exc, root_dir=root_dir))
        return None
    if not stat.S_ISREG(path_stat.st_mode):
        return None
    if _is_single_link_regular_store_file(path_stat):
        return path_stat
    exc = StorePathSecurityError(_STORE_RECORD_UNSAFE_MESSAGE)
    if errors is not None:
        errors.append(build_read_error(path, exc, root_dir=root_dir))
    return None


def _probe_safe_store_append_file(path: Path) -> os.stat_result | None:
    try:
        path_stat = path.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError):
        return None
    _require_safe_store_append_file(path_stat)
    return path_stat


def _require_safe_store_append_file(file_stat: os.stat_result) -> None:
    if not _is_single_link_regular_store_file(file_stat):
        raise StorePathSecurityError(_STORE_RECORD_APPEND_UNSAFE_MESSAGE)


def _is_single_link_regular_store_file(file_stat: os.stat_result) -> bool:
    link_count = getattr(file_stat, "st_nlink", None)
    return (
        stat.S_ISREG(file_stat.st_mode)
        and _has_stable_store_file_identity(file_stat)
        and isinstance(link_count, int)
        and not isinstance(link_count, bool)
        and link_count == 1
    )


def _has_stable_store_file_identity(file_stat: os.stat_result) -> bool:
    inode = getattr(file_stat, "st_ino", None)
    device = getattr(file_stat, "st_dev", None)
    return (
        isinstance(inode, int)
        and not isinstance(inode, bool)
        and inode != 0
        and isinstance(device, int)
        and not isinstance(device, bool)
    )


def _same_stable_store_file_identity(
    expected_stat: os.stat_result,
    opened_stat: os.stat_result,
) -> bool:
    try:
        same_file = os.path.samestat(expected_stat, opened_stat)
    except (AttributeError, OSError, TypeError, ValueError):
        return False
    return (
        _has_stable_store_file_identity(expected_stat)
        and _has_stable_store_file_identity(opened_stat)
        and same_file
    )


def _read_validated_store_text(path: Path, expected_stat: os.stat_result) -> str:
    fd: int | None = None
    primary_error: BaseException | None = None
    chunks: list[bytes] = []
    try:
        try:
            fd = os.open(path, _STORE_RECORD_OPEN_FLAGS)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise StorePathSecurityError(_STORE_RECORD_CHANGED_MESSAGE) from exc
            raise

        opened_stat = os.fstat(fd)
        if (
            not _is_single_link_regular_store_file(opened_stat)
            or not _same_stable_store_file_identity(expected_stat, opened_stat)
        ):
            raise StorePathSecurityError(_STORE_RECORD_CHANGED_MESSAGE)

        while True:
            chunk = os.read(fd, _STORE_RECORD_READ_CHUNK_BYTES)
            if not chunk:
                break
            chunks.append(chunk)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if fd is not None:
            _close_store_record_descriptor(fd, primary_error)
    return b"".join(chunks).decode("utf-8")


def _append_validated_store_text(
    path: Path,
    text: str,
    expected_stat: os.stat_result | None,
) -> None:
    fd: int | None = None
    primary_error: BaseException | None = None
    try:
        try:
            if expected_stat is None:
                fd = os.open(path, _STORE_RECORD_CREATE_FLAGS, 0o666)
            else:
                fd = os.open(path, _STORE_RECORD_APPEND_FLAGS)
        except FileExistsError as exc:
            if expected_stat is None:
                raise StorePathSecurityError(
                    _STORE_RECORD_APPEND_CHANGED_MESSAGE
                ) from exc
            raise
        except (FileNotFoundError, NotADirectoryError) as exc:
            if expected_stat is not None:
                raise StorePathSecurityError(
                    _STORE_RECORD_APPEND_CHANGED_MESSAGE
                ) from exc
            raise
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise StorePathSecurityError(
                    _STORE_RECORD_APPEND_CHANGED_MESSAGE
                ) from exc
            raise

        opened_stat = os.fstat(fd)
        _require_safe_store_append_file(opened_stat)
        try:
            current_stat = path.stat(follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError) as exc:
            raise StorePathSecurityError(
                _STORE_RECORD_APPEND_CHANGED_MESSAGE
            ) from exc
        _require_safe_store_append_file(current_stat)
        if not _same_stable_store_file_identity(current_stat, opened_stat):
            raise StorePathSecurityError(_STORE_RECORD_APPEND_CHANGED_MESSAGE)
        if expected_stat is not None and not _same_stable_store_file_identity(
            expected_stat,
            opened_stat,
        ):
            raise StorePathSecurityError(_STORE_RECORD_APPEND_CHANGED_MESSAGE)

        payload = text.replace("\n", os.linesep).encode("utf-8")
        _write_all_store_bytes(fd, payload)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if fd is not None:
            _close_store_record_descriptor(fd, primary_error)


def _write_all_store_bytes(fd: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(fd, remaining)
        if not isinstance(written, int) or isinstance(written, bool) or written <= 0:
            raise OSError(errno.EIO, "store append made no write progress")
        remaining = remaining[written:]


def _close_store_record_descriptor(
    fd: int,
    primary_error: BaseException | None,
) -> None:
    try:
        os.close(fd)
    except OSError as close_exc:
        if primary_error is None:
            raise
        _LOGGER.warning(
            "Store record descriptor cleanup failed after %s: %s",
            type(primary_error).__name__,
            type(close_exc).__name__,
        )


def _resolve_safe_store_write_path(path: Path, *, root_dir: Path | None) -> Path:
    candidate = Path(path)
    if root_dir is None:
        return candidate

    resolved_root = Path(root_dir).resolve(strict=False)
    if candidate.is_symlink():
        raise StorePathSecurityError("symlinked store record is not allowed")

    resolved_path = candidate.resolve(strict=False)
    if not resolved_path.is_relative_to(resolved_root):
        raise StorePathSecurityError("store record path escapes configured root directory")
    return candidate


def build_read_error(path: Path, exc: Exception, *, message: str | None = None, root_dir: Path | None = None) -> StoreReadError:
    repo_root = Path(root_dir) if root_dir is not None else Path(path).parent
    rendered_message = redact_text_local_paths(
        str(message if message is not None else exc),
        repo_root=str(repo_root),
    )
    return {
        "path": _diagnostic_path(path, root_dir=repo_root),
        "error_type": type(exc).__name__,
        "exception_type": type(exc).__name__,
        "message": rendered_message,
    }


def _diagnostic_path(path: Path, *, root_dir: Path | None) -> str:
    repo_root = Path(root_dir) if root_dir is not None else Path(path).parent
    rendered = redact_diagnostic_path(path, repo_root=str(repo_root))
    if not rendered.isprintable():
        return "<invalid-store-path>"
    return rendered


__all__ = [
    "StorePathSecurityError",
    "StoreReadDiagnosticsMixin",
    "StoreReadError",
    "append_text_record",
    "atomic_write_json_record",
    "atomic_write_text_record",
    "build_read_error",
    "hashed_store_filename",
    "json_roundtrip_copy",
    "read_json_record",
    "read_text_record",
    "safe_delete_store_record",
    "safe_store_filename",
    "safe_store_write_path",
    "sorted_store_ids",
]
