from __future__ import annotations

from collections.abc import Callable, Mapping
import logging
import ntpath
import os
import re
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import unquote

_WINDOWS_PATH_PATTERN = re.compile(
    r"(?:"
    r"(?<![A-Za-z0-9\\/])[A-Za-z]:[\\/]+"
    r"(?:[^\\/:*?\"<>|()\[\]{},;=\r\n]+[\\/]+)*[^\s\\/:*?\"<>|()\[\]{},;=\r\n]+"
    r"|"
    r"(?<![:\\/])\\{2,}[^\\/:*?\"<>|()\[\]{},;=\r\n]+[\\/]+"
    r"(?:[^\\/:*?\"<>|()\[\]{},;=\r\n]+[\\/]+)*[^\s\\/:*?\"<>|()\[\]{},;=\r\n]+"
    r")"
)
_POSIX_PATH_PATTERN = re.compile(
    r"(?<![:/A-Za-z0-9\]])/(?!/)[^\s'\"<>|]*[A-Za-z_.~\-][^\s'\"<>|]*"
)
_QUOTED_ABSOLUTE_PATH_PATTERNS = (
    re.compile(
        r"(?P<quote>')(?P<path>"
        r"(?:[A-Za-z]:[\\/]+|\\{2,}[^'\\\r\n]+[\\/]+|/(?!/)(?=[^'\s]))"
        r"(?:\\.|[^'\\\r\n])*)(?P=quote)"
    ),
    re.compile(
        r'(?P<quote>")(?P<path>'
        r'(?:[A-Za-z]:[\\/]+|\\{2,}[^"\\\r\n]+[\\/]+|/(?!/)(?=[^"\s]))'
        r'(?:\\.|[^"\\\r\n])*)(?P=quote)'
    ),
)
_OSERROR_QUOTED_DOUBLE_ROOT_PATTERNS = (
    re.compile(
        r"(?P<prefix>(?:\[(?:Errno|WinError) [^\]\r\n]+\][^\r\n]*?:\s*|\s+->\s+))"
        r"(?P<quote>')(?P<path>//(?:\\.|[^'\\\r\n])*)(?P=quote)"
    ),
    re.compile(
        r'(?P<prefix>(?:\[(?:Errno|WinError) [^\]\r\n]+\][^\r\n]*?:\s*|\s+->\s+))'
        r'(?P<quote>")(?P<path>//(?:\\.|[^"\\\r\n])*)(?P=quote)'
    ),
)
_SCHEME_URL_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s,;|]+")
_URL_SCHEME_PREFIX_PATTERN = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*):")
_LEADING_WRAP = "\"'([{<"
_TRAILING_WRAP = "\"')]}>,.;:"
_LOGGER = logging.getLogger(__name__)
_RepoRootPath = Path | PureWindowsPath
_MappingValueTransform = Callable[[str, bool, Any], Any]
_FilesystemTextCache = dict[int, tuple[os.PathLike[Any], str | None]]


def _filesystem_text(
    value: os.PathLike[Any],
    *,
    cache: _FilesystemTextCache | None = None,
) -> str | None:
    cache_key = id(value)
    if cache is not None:
        cached = cache.get(cache_key)
        if cached is not None and cached[0] is value:
            return cached[1]
    try:
        decoded = os.fsdecode(os.fspath(value))
        if not isinstance(decoded, str):
            raise TypeError("filesystem path did not decode to text")
        text = str.__str__(decoded)
        if "\0" in text:
            raise ValueError("filesystem path contains a null character")
        text.encode("utf-8", errors="strict")
        result = text
    except Exception as exc:
        _LOGGER.warning(
            "Role-Aware Dashboard Toolkit path redaction could not read path-like value (%s).",
            type(exc).__name__,
        )
        result = None
    if cache is not None:
        cache[cache_key] = (value, result)
    return result


def redact_payload_local_paths(
    payload: Mapping[Any, Any],
    *,
    repo_root: str | os.PathLike[Any],
    include_local_paths: bool = False,
    _mapping_value_transform: _MappingValueTransform | None = None,
    _reserved_top_level_keys: frozenset[str] = frozenset(),
    _filesystem_text_cache: _FilesystemTextCache | None = None,
) -> dict[str, Any]:
    filesystem_text_cache = (
        _filesystem_text_cache
        if _filesystem_text_cache is not None
        else {}
    )
    repo_root_path = _resolved_repo_root(repo_root, cache=filesystem_text_cache)
    redacted = _redact_value(
        payload,
        repo_root_path=repo_root_path,
        include_local_paths=include_local_paths,
        key_hint="",
        mapping_value_transform=_mapping_value_transform,
        reserved_mapping_keys=_reserved_top_level_keys,
        filesystem_text_cache=filesystem_text_cache,
    )
    if isinstance(redacted, dict):
        return redacted
    return dict(payload or {})


def _mapping_key_text(
    key: Any,
    *,
    cache: _FilesystemTextCache,
) -> tuple[str, bool]:
    if isinstance(key, os.PathLike):
        rendered = _filesystem_text(key, cache=cache)
        return (
            (rendered, True)
            if rendered is not None
            else ("<redacted-local-path>", False)
        )
    if isinstance(key, str):
        return str.__str__(key), True
    return str(key), True


def _available_mapping_key(base: str, *, used: set[str], reserved: set[str]) -> str:
    if base not in used and base not in reserved:
        return base
    ordinal = 2
    while f"{base}#{ordinal}" in used or f"{base}#{ordinal}" in reserved:
        ordinal += 1
    return f"{base}#{ordinal}"


def _stable_collection_sort_key(value: Any) -> tuple[str, ...]:
    value_type = type(value)
    try:
        return ("repr", repr(value))
    except Exception as exc:
        _LOGGER.warning(
            "Role-Aware Dashboard Toolkit path redaction could not order normalized set value (%s).",
            type(exc).__name__,
        )
        return ("object", value_type.__module__, value_type.__qualname__)


def _redact_value(
    value: Any,
    *,
    repo_root_path: _RepoRootPath | None,
    include_local_paths: bool,
    key_hint: str,
    mapping_value_transform: _MappingValueTransform | None,
    reserved_mapping_keys: frozenset[str],
    filesystem_text_cache: _FilesystemTextCache,
) -> Any:
    if isinstance(value, Mapping):
        entries: list[tuple[str, str, bool, Any]] = []
        reserved = set(reserved_mapping_keys)
        for key, item in value.items():
            raw_key, key_readable = _mapping_key_text(key, cache=filesystem_text_cache)
            sanitized_key = (
                raw_key
                if include_local_paths
                else _redact_text_local_paths(raw_key, repo_root_path=repo_root_path)
            )
            canonical = (
                isinstance(key, str)
                and not isinstance(key, os.PathLike)
                and sanitized_key == raw_key
            )
            if canonical:
                reserved.add(sanitized_key)
            if mapping_value_transform is not None:
                item = mapping_value_transform(raw_key, key_readable, item)
            entries.append((raw_key, sanitized_key, canonical, item))

        output: dict[str, Any] = {}
        used: set[str] = set()
        for raw_key, sanitized_key, canonical, item in entries:
            output_key = (
                sanitized_key
                if canonical
                else _available_mapping_key(sanitized_key, used=used, reserved=reserved)
            )
            output[output_key] = _redact_value(
                item,
                repo_root_path=repo_root_path,
                include_local_paths=include_local_paths,
                key_hint=raw_key,
                mapping_value_transform=mapping_value_transform,
                reserved_mapping_keys=frozenset(),
                filesystem_text_cache=filesystem_text_cache,
            )
            used.add(output_key)
        return output
    if isinstance(value, (set, frozenset)):
        normalized = [
            _redact_value(
                item,
                repo_root_path=repo_root_path,
                filesystem_text_cache=filesystem_text_cache,
                include_local_paths=include_local_paths,
                key_hint=key_hint,
                mapping_value_transform=mapping_value_transform,
                reserved_mapping_keys=frozenset(),
            )
            for item in value
        ]
        return sorted(normalized, key=_stable_collection_sort_key)
    if isinstance(value, (list, tuple)):
        return [
            _redact_value(
                item,
                repo_root_path=repo_root_path,
                include_local_paths=include_local_paths,
                key_hint=key_hint,
                mapping_value_transform=mapping_value_transform,
                filesystem_text_cache=filesystem_text_cache,
                reserved_mapping_keys=frozenset(),
            )
            for item in value
        ]
    if isinstance(value, os.PathLike):
        rendered = _filesystem_text(value, cache=filesystem_text_cache)
        if rendered is None:
            if key_hint == "repo_root" and not include_local_paths:
                return "."
            return "<redacted-local-path>"
    elif isinstance(value, str):
        rendered = str.__str__(value)
    else:
        return value
    if key_hint == "repo_root":
        return rendered if include_local_paths else "."
    if include_local_paths:
        return rendered
    return _redact_text_local_paths(rendered, repo_root_path=repo_root_path)


def redact_text_local_paths(
    text: str,
    *,
    repo_root: str | os.PathLike[Any] = "",
) -> str:
    rendered = str.__str__(text) if isinstance(text, str) else str(text or "")
    return _redact_text_local_paths(
        rendered,
        repo_root_path=_resolved_repo_root(repo_root),
    )


def redact_diagnostic_path(path: str | Path, *, repo_root: str = "") -> str:
    value = str(path or "")
    lexical_relative = _lexical_repo_relative_path(value, repo_root=repo_root)
    if lexical_relative and lexical_relative != ".":
        return lexical_relative
    redacted = redact_text_local_paths(value, repo_root=repo_root)
    if redacted in {"", "."}:
        return Path(value).name or redacted
    return redacted


def _lexical_repo_relative_path(value: str, *, repo_root: str) -> str:
    if not value or not str(repo_root or "").strip():
        return ""
    candidate = Path(value)
    if not candidate.is_absolute():
        return ""
    try:
        lexical_root = Path(os.path.abspath(repo_root))
        lexical_candidate = Path(os.path.abspath(candidate))
    except OSError as exc:
        _log_resolve_failure("diagnostic path", exc)
        return ""
    try:
        relative = lexical_candidate.relative_to(lexical_root)
    except ValueError:
        return ""
    return relative.as_posix() or "."


def _redact_quoted_match_path(match, *, repo_root_path: _RepoRootPath | None) -> str:
    candidate = match.group("path")
    if f"\\{match.group('quote')}" in candidate:
        return "<redacted-local-path>"
    return _redact_absolute_path(candidate, repo_root_path=repo_root_path)


def _replace_oserror_double_root_paths(text: str, *, repo_root_path: _RepoRootPath | None) -> str:
    if not re.match(r"^\[(?:Errno|WinError) ", text):
        return text
    value = text
    for pattern in _OSERROR_QUOTED_DOUBLE_ROOT_PATTERNS:
        value = pattern.sub(
            lambda match: (
                f"{match.group('prefix')}"
                f"{match.group('quote')}"
                f"{_redact_quoted_match_path(match, repo_root_path=repo_root_path)}"
                f"{match.group('quote')}"
            ),
            value,
        )
    return value


def _replace_quoted_absolute_paths(text: str, *, repo_root_path: _RepoRootPath | None) -> str:
    value = text
    for pattern in _QUOTED_ABSOLUTE_PATH_PATTERNS:
        value = pattern.sub(
            lambda match: (
                f"{match.group('quote')}"
                f"{_redact_quoted_match_path(match, repo_root_path=repo_root_path)}"
                f"{match.group('quote')}"
            ),
            value,
        )
    return value


def _redact_text_local_paths(text: str, *, repo_root_path: _RepoRootPath | None) -> str:
    value = str(text or "")
    if _looks_absolute_path(value):
        return _redact_absolute_path(value, repo_root_path=repo_root_path)
    if not value:
        return value
    value = _replace_oserror_double_root_paths(value, repo_root_path=repo_root_path)
    value = _replace_quoted_absolute_paths(value, repo_root_path=repo_root_path)
    value = _replace_windows_path_substrings(value, repo_root_path=repo_root_path)
    return re.sub(r"\S+", lambda match: _redact_token(match.group(0), repo_root_path=repo_root_path), value)


def _decode_url_field(value: str) -> str:
    decoded = value
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _redact_url_parameter_text(
    value: str,
    *,
    repo_root_path: _RepoRootPath | None,
) -> str:
    output: list[str] = []
    for field in re.split(r"([&;=])", value):
        if field in {"&", ";", "="}:
            output.append(field)
            continue
        decoded = _decode_url_field(field)
        redacted = _redact_text_local_paths(
            decoded,
            repo_root_path=repo_root_path,
        )
        output.append(field if redacted == decoded else redacted)
    return "".join(output)


def _redact_scheme_url(
    value: str,
    *,
    repo_root_path: _RepoRootPath | None,
) -> str:
    scheme_match = _URL_SCHEME_PREFIX_PATTERN.match(value)
    if scheme_match is None:
        return value
    if scheme_match.group("scheme").casefold() == "file":
        return "<redacted-local-path>"

    before_fragment, fragment_separator, fragment = value.partition("#")
    base, query_separator, query = before_fragment.partition("?")
    if not query_separator and not fragment_separator:
        return value
    redacted_query = _redact_url_parameter_text(
        query,
        repo_root_path=repo_root_path,
    )
    redacted_fragment = _redact_url_parameter_text(
        fragment,
        repo_root_path=repo_root_path,
    )
    return (
        f"{base}{query_separator}{redacted_query}"
        f"{fragment_separator}{redacted_fragment}"
    )


def _redact_token(token: str, *, repo_root_path: _RepoRootPath | None) -> str:
    leading = ""
    trailing = ""
    core = token
    while core and core[0] in _LEADING_WRAP:
        leading += core[0]
        core = core[1:]
    while core and core[-1] in _TRAILING_WRAP:
        trailing = core[-1] + trailing
        core = core[:-1]
    if not core:
        return token
    with_redacted_urls = _SCHEME_URL_PATTERN.sub(
        lambda match: _redact_scheme_url(
            match.group(0),
            repo_root_path=repo_root_path,
        ),
        core,
    )
    redacted_core = _replace_absolute_substrings(with_redacted_urls, repo_root_path=repo_root_path)
    return f"{leading}{redacted_core}{trailing}"


def _match_starts_in_scheme_url(match, *, text: str) -> bool:
    return any(url.start() <= match.start() < url.end() for url in _SCHEME_URL_PATTERN.finditer(text))


def _replace_windows_path_substrings(text: str, *, repo_root_path: _RepoRootPath | None) -> str:
    return _WINDOWS_PATH_PATTERN.sub(
        lambda match: (
            match.group(0)
            if _match_starts_in_scheme_url(match, text=text)
            else _redact_windows_path_match(match.group(0), repo_root_path=repo_root_path)
        ),
        text,
    )


def _replace_posix_path_substrings(text: str, *, repo_root_path: _RepoRootPath | None) -> str:
    return _POSIX_PATH_PATTERN.sub(
        lambda match: (
            match.group(0)
            if _match_starts_in_scheme_url(match, text=text)
            else _redact_absolute_path(match.group(0), repo_root_path=repo_root_path)
        ),
        text,
    )


def _replace_absolute_substrings(value: str, *, repo_root_path: _RepoRootPath | None) -> str:
    text = str(value or "")
    text = _replace_windows_path_substrings(text, repo_root_path=repo_root_path)
    text = _replace_posix_path_substrings(text, repo_root_path=repo_root_path)
    return text


def _resolved_repo_root(
    repo_root: str | os.PathLike[Any],
    *,
    cache: _FilesystemTextCache | None = None,
) -> _RepoRootPath | None:
    if isinstance(repo_root, os.PathLike):
        rendered = _filesystem_text(repo_root, cache=cache)
        if rendered is None:
            return None
        text = rendered.strip()
    elif isinstance(repo_root, str):
        text = str.__str__(repo_root).strip()
    else:
        text = str(repo_root or "").strip()
    if not text:
        return None
    if "\0" in text:
        _log_resolve_failure("repo root", ValueError())
        return None
    if _looks_windows_rooted_path(text):
        return PureWindowsPath(_normalize_windows_path(text))
    try:
        return Path(text).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        _log_resolve_failure("repo root", exc)
        return None


def _looks_absolute_path(value: str) -> bool:
    text = str(value or "")
    if not text:
        return False
    if text.startswith(("/", "\\")):
        return True
    return len(text) >= 3 and text[1] == ":" and text[2] in {"/", "\\"}


def _looks_windows_rooted_path(value: str) -> bool:
    text = str(value or "")
    if re.match(r"^[A-Za-z]:[\\/]+|^[\\/]{2,}", text):
        return True
    return os.name != "nt" and text.startswith("\\")


def _normalize_windows_path(value: str) -> str:
    text = str(value or "")
    normalized = ntpath.normpath(text)
    if re.match(r"^[\\/]{2,}", text):
        return "\\\\" + normalized.lstrip("\\/")
    return normalized


def _redact_windows_path_match(value: str, *, repo_root_path: _RepoRootPath | None) -> str:
    candidate = value
    trailing = ""
    while candidate and candidate[-1] in _TRAILING_WRAP:
        trailing = candidate[-1] + trailing
        candidate = candidate[:-1]
    return f"{_redact_absolute_path(candidate, repo_root_path=repo_root_path)}{trailing}"


def _redact_absolute_path(value: str, *, repo_root_path: _RepoRootPath | None) -> str:
    if "\0" in value:
        _log_resolve_failure("absolute path", ValueError())
        return "<redacted-local-path>"
    if _looks_windows_rooted_path(value):
        path = PureWindowsPath(_normalize_windows_path(value))
        if isinstance(repo_root_path, PureWindowsPath):
            try:
                relative = path.relative_to(repo_root_path)
            except ValueError:
                return "<redacted-local-path>"
            return relative.as_posix() or "."
        return "<redacted-local-path>"
    try:
        path = Path(value).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        _log_resolve_failure("absolute path", exc)
        return "<redacted-local-path>"
    if (
        repo_root_path is not None
        and isinstance(repo_root_path, Path)
        and path.is_relative_to(repo_root_path)
    ):
        relative = path.relative_to(repo_root_path)
        return relative.as_posix() or "."
    return "<redacted-local-path>"


def _log_resolve_failure(context: str, exc: Exception) -> None:
    _LOGGER.warning(
        "Role-Aware Dashboard Toolkit path redaction could not resolve %s (%s).",
        context,
        type(exc).__name__,
    )


__all__ = ["redact_diagnostic_path", "redact_payload_local_paths", "redact_text_local_paths"]
