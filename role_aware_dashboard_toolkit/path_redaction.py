from __future__ import annotations

from bisect import bisect_left, bisect_right
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
# A POSIX path starts at a slash that is not part of a word, URL or double
# root, extends to the end of its token run, and needs one path character.
_POSIX_PATH_START_PATTERN = re.compile(r"(?<![:/A-Za-z0-9\]])/(?!/)")
# In the rest of a repository-relative result, a later path starts only after
# whitespace, a separator or an opening wrap: "pkg/__pycache__/m.pyc" holds no
# second path, while "a.pyc:/Users/x" and "a=/Users/x" do.
_POSIX_PATH_STRICT_START_PATTERN = re.compile(r"(?<![^\s,;|=:'\"(\[{<])/(?!/)")
_POSIX_PATH_RUN_END_PATTERN = re.compile(r"[\s'\"<>|]")
_POSIX_PATH_CHARACTER_PATTERN = re.compile(r"[A-Za-z_.~\-]")
_QUOTE_CHARACTERS = ("'", '"')
_OSERROR_MESSAGE_PATTERN = re.compile(r"\[(?:Errno|WinError) ")
_OSERROR_ARROW_PATTERN = re.compile(r"(?<!\s)\s+(?=->)")
_OSERROR_BRACKET_STOP_PATTERN = re.compile(r"[\]\r\n]")
_LINE_END_PATTERN = re.compile(r"[\r\n]")
_WHITESPACE_RUN_PATTERN = re.compile(r"\s*")
_SEPARATOR_RUN_PATTERN = re.compile(r"[\\/]*")
_BACKSLASH_RUN_PATTERN = re.compile(r"\\*")
_TOKEN_PATTERN = re.compile(r"\S+")
# A scheme starts at the first letter of its run of scheme characters. Anchoring
# the match at the run start keeps the search linear; ``url`` is the URL itself.
_SCHEME_URL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+.\-])[0-9+.\-]*(?P<url>[A-Za-z][A-Za-z0-9+.\-]*://[^\s,;|]+)"
)
_URL_SCHEME_PREFIX_PATTERN = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*):")
# A file URI without an authority (file:/x, file:C:/x, file:\\srv\x)
# names a local file just as a file:// URL does.
_FILE_URI_PATTERN = re.compile(
    r"(?<![A-Za-z0-9+.\-])file:(?=[\\/]|[A-Za-z]:[\\/])[^\s,;|]+",
    re.IGNORECASE,
)
# Editor links such as vscode://file/<path> (and forks) carry a local path.
_EDITOR_FILE_LINK_AUTHORITY = "//file/"
_LEADING_WRAP = "\"'([{<"
_TRAILING_WRAP = "\"')]}>,.;:"
# Redaction scans at most this many characters of one string, in time linear
# in its length. Measured on an Apple M2 (Python 3.12) over thirteen shapes of
# 1 MiB: at most 0.5 s without a repository root, and up to 5.4 s with one,
# because each candidate path under a POSIX root is resolved against the file
# system, one call per path component (a 1 MiB string of 2,000-component paths
# is the worst shape measured). Every path form ends at a
# line break, so an oversize string keeps only the whole lines before the
# limit: the line that crosses it and the rest are dropped, never emitted
# unscanned, and replaced by a marker that states how many characters were
# omitted. Cutting inside the line could split a quoted path or a Windows path
# with spaces, leaving a head that no longer reads as a path.
_MAX_SCAN_CHARACTERS = 1024 * 1024
# A URL query or fragment is scanned for paths, and may itself hold URLs.
# Past this many nested levels the rest is redacted unscanned, which bounds
# both the recursion and the rescanning of the remainder at each level.
_MAX_URL_NESTING = 8
# Longer than any supported platform's path limit: redacted without resolving.
_MAX_PATH_CHARACTERS = 4096
_REDACTED_LOCAL_PATH = "<redacted-local-path>"
_LOGGER = logging.getLogger(__name__)
_RepoRootPath = Path | PureWindowsPath
_MappingValueTransform = Callable[[str, bool, Any], Any]
_FilesystemTextCache = dict[int, tuple[os.PathLike[Any], str | None]]
_AbsolutePathCache = dict[str, str]


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
    if isinstance(value, (set, frozenset, list, tuple)):
        # A loop, not a comprehension: before Python 3.12 a comprehension adds
        # a frame per nesting level, halving the depth a packet can reach.
        items: list[Any] = []
        for item in value:
            items.append(_redact_value(
                item,
                repo_root_path=repo_root_path,
                include_local_paths=include_local_paths,
                key_hint=key_hint,
                mapping_value_transform=mapping_value_transform,
                filesystem_text_cache=filesystem_text_cache,
                reserved_mapping_keys=frozenset(),
            ))
        if isinstance(value, (set, frozenset)):
            return sorted(items, key=_stable_collection_sort_key)
        return items
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


class _QuotedBodyScanner:
    """Find where a quoted path body ends, scanning each character at most once.

    A body consumes escaped pairs and characters other than the quote, a
    backslash or a line break. Bodies that start at different positions merge
    once they reach a shared position, so the outcome is cached per position.
    """

    __slots__ = ("_quote", "_stops", "_text")

    def __init__(self, text: str, quote: str) -> None:
        self._text = text
        self._quote = quote
        self._stops: list[int] | None = None

    def closes_at(self, position: int) -> int | None:
        """Return the index of the closing quote for a body starting here."""
        text = self._text
        stop = self._stop(position)
        return stop if stop < len(text) and text[stop] == self._quote else None

    def _stop(self, position: int) -> int:
        text = self._text
        length = len(text)
        if self._stops is None:
            self._stops = [-1] * (length + 1)
        stops = self._stops
        quote = self._quote
        visited: list[int] = []
        while True:
            if position >= length:
                stop = length
                break
            known = stops[position]
            if known >= 0:
                stop = known
                break
            char = text[position]
            if char == quote or char == "\r" or char == "\n":
                stop = position
                break
            if char == "\\":
                if position + 1 < length and text[position + 1] != "\n":
                    visited.append(position)
                    position += 2
                    continue
                stop = position
                break
            visited.append(position)
            position += 1
        for item in visited:
            stops[item] = stop
        return stop


def _run_end(pattern: re.Pattern[str], text: str, position: int) -> int:
    match = pattern.match(text, position)
    return match.end() if match is not None else position


def _quoted_absolute_path_close(
    text: str, quote_index: int, scanner: _QuotedBodyScanner
) -> int | None:
    """Return the closing quote index of a quoted absolute path, or None.

    The path after the quote starts with a drive (``C:`` and separators), a UNC
    root (two or more backslashes, a name and separators) or one slash followed
    by a path character. The body then runs to the closing quote; a backslash
    escapes the next character. Where a drive or UNC root can end at several
    separators, the longest is tried first, matching the 0.1.0 pattern's
    leftmost-first result. Each body is scanned once, whatever the number of
    quotes in the text.
    """
    length = len(text)
    first = quote_index + 1
    if first >= length:
        return None
    quote = text[quote_index]
    char = text[first]
    if char.isascii() and char.isalpha():
        separators_start = first + 2
        if separators_start > length or text[first + 1] != ":":
            return None
        separators_end = _run_end(_SEPARATOR_RUN_PATTERN, text, separators_start)
        for body_start in range(separators_end, separators_start, -1):
            close = scanner.closes_at(body_start)
            if close is not None:
                return close
        return None
    if char == "\\":
        segment_start = _run_end(_BACKSLASH_RUN_PATTERN, text, first)
        if segment_start - first < 2:
            return None
        segment_end = segment_start
        while segment_end < length and text[segment_end] not in (quote, "\\", "\r", "\n"):
            segment_end += 1
        if segment_end == segment_start:
            return None
        # The segment may end in backslash separators: try each split there
        # first, longest first. A shorter split at a slash after the segment's
        # first character starts the body inside the segment, and every such
        # body reaches the segment end unchanged.
        if segment_end < length and text[segment_end] == "\\":
            separators_end = _run_end(_SEPARATOR_RUN_PATTERN, text, segment_end)
            for body_start in range(separators_end, segment_end, -1):
                close = scanner.closes_at(body_start)
                if close is not None:
                    return close
        if "/" in text[segment_start + 1:segment_end]:
            return scanner.closes_at(segment_end)
        return None
    if char == "/":
        body_start = first + 1
        if body_start >= length:
            return None
        following = text[body_start]
        if following == "/" or following == quote or following.isspace():
            return None
        return scanner.closes_at(body_start)
    return None


def _redact_quoted_path(
    candidate: str,
    quote: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
) -> str:
    if f"\\{quote}" in candidate:
        return _REDACTED_LOCAL_PATH
    return _redact_absolute_path(candidate, repo_root_path=repo_root_path, cache=cache)


def _replace_quoted_absolute_paths(
    text: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
) -> str:
    value = text
    for quote in _QUOTE_CHARACTERS:
        scanner = _QuotedBodyScanner(value, quote)
        output: list[str] = []
        emitted = 0
        search_from = 0
        while True:
            quote_index = value.find(quote, search_from)
            if quote_index < 0:
                break
            close = _quoted_absolute_path_close(value, quote_index, scanner)
            if close is None:
                search_from = quote_index + 1
                continue
            output.append(value[emitted:quote_index + 1])
            output.append(_redact_quoted_path(
                value[quote_index + 1:close], quote, repo_root_path=repo_root_path, cache=cache,
            ))
            emitted = close
            search_from = close + 1
        if output:
            output.append(value[emitted:])
            value = "".join(output)
    return value


class _OSErrorPathMatcher:
    """Match quoted double-root filenames in OSError text in linear time.

    A filename follows ``[Errno N] message:`` (the first colon after the bracket
    on that line whose quoted ``//`` filename closes) or `` -> `` for a second
    filename, as in the 0.1.0 pattern. A line is not rescanned once for every
    message prefix on it: a prefix that finds no filename rules out every later
    prefix on the same line.
    """

    __slots__ = ("_bracket", "_dead_line_end", "_line", "_quote", "_scanner", "_text")

    def __init__(self, text: str, quote: str) -> None:
        self._text = text
        self._quote = quote
        self._scanner = _QuotedBodyScanner(text, quote)
        self._bracket = (-1, -1)
        self._line = (-1, -1)
        self._dead_line_end = -1

    def _first_at_or_after(self, cache: tuple[int, int], pattern: re.Pattern[str], position: int) -> tuple[int, int]:
        query, found = cache
        if query <= position <= found:
            return cache
        match = pattern.search(self._text, position)
        return position, match.start() if match is not None else len(self._text)

    def _double_root_close(self, quote_index: int) -> int | None:
        text = self._text
        if not text.startswith(self._quote + "//", quote_index):
            return None
        return self._scanner.closes_at(quote_index + 3)

    def message_match(self, start: int, prefix_length: int) -> tuple[int, int] | None:
        """Return (quote index, closing quote index) for a message prefix."""
        if start < self._dead_line_end:
            return None
        text = self._text
        length = len(text)
        detail_start = start + prefix_length
        if detail_start >= length or text[detail_start] in "]\r\n":
            return None
        self._bracket = self._first_at_or_after(self._bracket, _OSERROR_BRACKET_STOP_PATTERN, detail_start)
        bracket = self._bracket[1]
        self._line = self._first_at_or_after(self._line, _LINE_END_PATTERN, detail_start)
        line_end = self._line[1]
        if bracket >= length or text[bracket] != "]":
            # No closing bracket on this line: every later prefix on it fails too.
            self._dead_line_end = line_end
            return None
        colon = text.find(":", bracket + 1, line_end)
        while colon >= 0:
            quote_index = _run_end(_WHITESPACE_RUN_PATTERN, text, colon + 1)
            close = self._double_root_close(quote_index) if quote_index < length else None
            if close is not None:
                return quote_index, close
            colon = text.find(":", colon + 1, line_end)
        # Later prefixes on this line reach no colon this one did not try.
        self._dead_line_end = line_end
        return None

    def arrow_match(self, start: int, arrow: int) -> tuple[int, int] | None:
        text = self._text
        after_arrow = arrow + 2
        quote_index = _run_end(_WHITESPACE_RUN_PATTERN, text, after_arrow)
        if quote_index == after_arrow or quote_index >= len(text):
            return None
        close = self._double_root_close(quote_index)
        return (quote_index, close) if close is not None else None


def _oserror_candidates(text: str) -> list[tuple[int, int, bool]]:
    candidates = [
        (match.start(), match.end() - match.start(), True)
        for match in _OSERROR_MESSAGE_PATTERN.finditer(text)
    ]
    candidates.extend(
        (match.start(), match.end(), False)
        for match in _OSERROR_ARROW_PATTERN.finditer(text)
    )
    candidates.sort()
    return candidates


def _replace_oserror_double_root_paths(
    text: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
) -> str:
    if not re.match(r"^\[(?:Errno|WinError) ", text):
        return text
    value = text
    for quote in _QUOTE_CHARACTERS:
        matcher = _OSErrorPathMatcher(value, quote)
        output: list[str] = []
        emitted = 0
        for start, detail, is_message in _oserror_candidates(value):
            if start < emitted:
                continue
            found = matcher.message_match(start, detail) if is_message else matcher.arrow_match(start, detail)
            if found is None:
                continue
            quote_index, close = found
            output.append(value[emitted:quote_index + 1])
            output.append(_redact_quoted_path(
                value[quote_index + 1:close], quote, repo_root_path=repo_root_path, cache=cache,
            ))
            emitted = close
        if output:
            output.append(value[emitted:])
            value = "".join(output)
    return value


def _redact_text_local_paths(
    text: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache | None = None,
    url_depth: int = 0,
    strict_starts: bool = False,
) -> str:
    value = str(text or "")
    if cache is None:
        cache = {}
    if len(value) > _MAX_SCAN_CHARACTERS:
        cut = _scan_cut(value, _MAX_SCAN_CHARACTERS)
        omitted = len(value) - cut
        scanned = _redact_text_local_paths(
            value[:cut],
            repo_root_path=repo_root_path,
            cache=cache,
            url_depth=url_depth,
        ) if cut else ""
        unit = "character" if omitted == 1 else "characters"
        return f"{scanned}<redacted-oversize-text: {omitted} {unit} omitted>"
    if _looks_absolute_path(value):
        # The whole text is read as one path, so a repository root containing
        # spaces stays whole; a later path in the relative remainder is
        # redacted by _repo_relative_text. A URL in the text is the exception:
        # path normalization would fold its "//", so scan path by path.
        whole = _redact_absolute_path(value, repo_root_path=repo_root_path, cache=cache)
        if whole == _REDACTED_LOCAL_PATH or "://" not in value:
            return whole
    elif not value:
        return value
    value = _replace_oserror_double_root_paths(value, repo_root_path=repo_root_path, cache=cache)
    value = _replace_quoted_absolute_paths(value, repo_root_path=repo_root_path, cache=cache)
    value = _replace_windows_path_substrings(value, repo_root_path=repo_root_path, cache=cache)
    return _TOKEN_PATTERN.sub(
        lambda match: _redact_token(
            match.group(0), repo_root_path=repo_root_path, cache=cache, url_depth=url_depth,
            strict_starts=strict_starts,
        ),
        value,
    )


def _scan_cut(value: str, limit: int) -> int:
    """Return where to cut an oversize string: the start of the line crossing ``limit``.

    A line that ends exactly at the limit is complete and is kept.
    """
    if value[limit] in "\r\n":
        return limit
    return max(value.rfind("\n", 0, limit), value.rfind("\r", 0, limit)) + 1


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
    cache: _AbsolutePathCache,
    url_depth: int,
) -> str:
    if url_depth >= _MAX_URL_NESTING:
        return _REDACTED_LOCAL_PATH if value else value
    output: list[str] = []
    for field in re.split(r"([&;=])", value):
        if field in {"&", ";", "="}:
            output.append(field)
            continue
        decoded = _decode_url_field(field)
        redacted = _redact_text_local_paths(
            decoded,
            repo_root_path=repo_root_path,
            cache=cache,
            url_depth=url_depth + 1,
        )
        output.append(field if redacted == decoded else redacted)
    return "".join(output)


def _redact_scheme_url(
    value: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
    url_depth: int,
) -> str:
    scheme_match = _URL_SCHEME_PREFIX_PATTERN.match(value)
    if scheme_match is None:
        return value
    if scheme_match.group("scheme").casefold() == "file":
        return _REDACTED_LOCAL_PATH
    after_scheme = value[scheme_match.end():scheme_match.end() + len(_EDITOR_FILE_LINK_AUTHORITY)]
    if after_scheme.casefold() == _EDITOR_FILE_LINK_AUTHORITY:
        return _REDACTED_LOCAL_PATH

    before_fragment, fragment_separator, fragment = value.partition("#")
    base, query_separator, query = before_fragment.partition("?")
    if not query_separator and not fragment_separator:
        return value
    redacted_query = _redact_url_parameter_text(
        query,
        repo_root_path=repo_root_path,
        cache=cache,
        url_depth=url_depth,
    )
    redacted_fragment = _redact_url_parameter_text(
        fragment,
        repo_root_path=repo_root_path,
        cache=cache,
        url_depth=url_depth,
    )
    return (
        f"{base}{query_separator}{redacted_query}"
        f"{fragment_separator}{redacted_fragment}"
    )


def _redact_token(
    token: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
    url_depth: int,
    strict_starts: bool = False,
) -> str:
    unwrapped = token.lstrip(_LEADING_WRAP)
    leading = token[:len(token) - len(unwrapped)]
    core = unwrapped.rstrip(_TRAILING_WRAP)
    trailing = unwrapped[len(core):]
    if not core:
        return token
    with_redacted_urls = _SCHEME_URL_PATTERN.sub(
        lambda match: (
            core[match.start():match.start("url")]
            + _redact_scheme_url(
                match.group("url"), repo_root_path=repo_root_path, cache=cache, url_depth=url_depth,
            )
        ),
        core,
    )
    with_redacted_urls = _replace_file_uris(with_redacted_urls)
    redacted_core = _replace_absolute_substrings(
        with_redacted_urls, repo_root_path=repo_root_path, cache=cache, strict_starts=strict_starts,
    )
    return f"{leading}{redacted_core}{trailing}"


def _replace_file_uris(text: str) -> str:
    if "file:" not in text.casefold():
        return text
    urls = _SchemeUrlSpans(text)
    return _FILE_URI_PATTERN.sub(
        lambda match: match.group(0) if match.start() in urls else _REDACTED_LOCAL_PATH,
        text,
    )


class _SchemeUrlSpans:
    """Answer whether a position lies inside a scheme URL, scanning once."""

    __slots__ = ("_ends", "_starts", "_text")

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts: list[int] | None = None
        self._ends: list[int] = []

    def __contains__(self, position: int) -> bool:
        if self._starts is None:
            spans = [match.span("url") for match in _SCHEME_URL_PATTERN.finditer(self._text)]
            self._starts = [start for start, _ in spans]
            self._ends = [end for _, end in spans]
        index = bisect_right(self._starts, position) - 1
        return index >= 0 and position < self._ends[index]

    def end_of_url_starting_inside(self, start: int, end: int) -> int | None:
        """Return the end of the last URL that starts inside (start, end), if any."""
        if self._starts is None:
            _ = start in self  # finds the spans once
        starts = self._starts or []
        first = bisect_right(starts, start)
        last = bisect_left(starts, end) - 1
        return self._ends[last] if last >= first else None


def _replace_windows_path_substrings(
    text: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
) -> str:
    urls = _SchemeUrlSpans(text)
    output: list[str] = []
    emitted = 0
    for match in _WINDOWS_PATH_PATTERN.finditer(text):
        start, end = match.span()
        if start < emitted or start in urls:
            continue
        output.append(text[emitted:start])
        glued_url_end = urls.end_of_url_starting_inside(start, end)
        if glued_url_end is not None:
            # A path glued to a URL (\\srv\share\vscode://file/...) takes the
            # URL's scheme, and the rest no longer reads as a URL or a path:
            # redact the URL with the path.
            output.append(_REDACTED_LOCAL_PATH)
            emitted = max(end, glued_url_end)
        else:
            output.append(_redact_windows_path_match(match.group(0), repo_root_path=repo_root_path, cache=cache))
            emitted = end
    if not output:
        return text
    output.append(text[emitted:])
    return "".join(output)


def _posix_path_spans(
    text: str, start_pattern: re.Pattern[str] = _POSIX_PATH_START_PATTERN,
) -> list[tuple[int, int]]:
    """Return the spans a POSIX path match covers, scanning each run once.

    A match runs from its start slash to the end of the token run. If the first
    eligible slash of a run has no path character after it, no later slash in
    that run has one either, so each run yields at most one span.
    """
    spans: list[tuple[int, int]] = []
    length = len(text)
    position = 0
    while True:
        slash = start_pattern.search(text, position)
        if slash is None:
            return spans
        start = slash.start()
        run_end = _POSIX_PATH_RUN_END_PATTERN.search(text, start)
        end = run_end.start() if run_end is not None else length
        if _POSIX_PATH_CHARACTER_PATTERN.search(text, start + 1, end) is not None:
            spans.append((start, end))
        position = end


def _replace_posix_path_substrings(
    text: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
    strict_starts: bool = False,
) -> str:
    spans = _posix_path_spans(
        text, _POSIX_PATH_STRICT_START_PATTERN if strict_starts else _POSIX_PATH_START_PATTERN,
    )
    if not spans:
        return text
    urls = _SchemeUrlSpans(text)
    output: list[str] = []
    emitted = 0
    for start, end in spans:
        output.append(text[emitted:start])
        candidate = text[start:end]
        output.append(
            candidate
            if start in urls
            else _redact_absolute_path(candidate, repo_root_path=repo_root_path, cache=cache)
        )
        emitted = end
    output.append(text[emitted:])
    return "".join(output)


def _replace_absolute_substrings(
    value: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
    strict_starts: bool = False,
) -> str:
    text = str(value or "")
    text = _replace_windows_path_substrings(text, repo_root_path=repo_root_path, cache=cache)
    text = _replace_posix_path_substrings(
        text, repo_root_path=repo_root_path, cache=cache, strict_starts=strict_starts,
    )
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


def _redact_windows_path_match(
    value: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache,
) -> str:
    candidate = value.rstrip(_TRAILING_WRAP)
    trailing = value[len(candidate):]
    return f"{_redact_absolute_path(candidate, repo_root_path=repo_root_path, cache=cache)}{trailing}"


def _redact_absolute_path(
    value: str,
    *,
    repo_root_path: _RepoRootPath | None,
    cache: _AbsolutePathCache | None = None,
) -> str:
    if cache is None:
        return _redact_absolute_path_once(value, repo_root_path=repo_root_path)
    redacted = cache.get(value)
    if redacted is None:
        redacted = cache[value] = _redact_absolute_path_once(value, repo_root_path=repo_root_path)
    return redacted


def _redact_absolute_path_once(value: str, *, repo_root_path: _RepoRootPath | None) -> str:
    if "\0" in value:
        _log_resolve_failure("absolute path", ValueError())
        return _REDACTED_LOCAL_PATH
    if len(value) > _MAX_PATH_CHARACTERS:
        return _REDACTED_LOCAL_PATH
    if _looks_windows_rooted_path(value):
        path = PureWindowsPath(_normalize_windows_path(value))
        if isinstance(repo_root_path, PureWindowsPath):
            try:
                relative = path.relative_to(repo_root_path)
            except ValueError:
                return _REDACTED_LOCAL_PATH
            return _repo_relative_text(relative.as_posix() or ".", repo_root_path)
        return _REDACTED_LOCAL_PATH
    if repo_root_path is None or not isinstance(repo_root_path, Path):
        # Only a native repository root can keep a POSIX-style path: without
        # one it is redacted whatever it resolves to, so skip the file-system
        # calls resolving would make (one or two per path component).
        return _REDACTED_LOCAL_PATH
    try:
        path = Path(value).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        _log_resolve_failure("absolute path", exc)
        return _REDACTED_LOCAL_PATH
    if path.is_relative_to(repo_root_path):
        relative = path.relative_to(repo_root_path)
        return _repo_relative_text(relative.as_posix() or ".", repo_root_path)
    return _REDACTED_LOCAL_PATH


# Where a later path can start inside a repository-relative result: after
# whitespace, a list separator, a quote, or a PATH/assignment separator.
_RELATIVE_RESCAN_START = re.compile(r"[\s,;|'\":=]")


def _repo_relative_text(relative: str, repo_root_path: _RepoRootPath) -> str:
    """Redact any path a repository-relative result still carries.

    A candidate path can run on past a separator that is not a path boundary
    (``/repo/a.txt,/Users/alice/s``), so its relative remainder must not carry
    a later path through. The remainder is scanned from the first such
    separator, and there a path starts only after whitespace, a separator or
    an opening wrap, so a slash after "_", "-", "~", ")" or "+" inside a
    relative path (``pkg/__pycache__/m.pyc``, ``My Folder (copy)/x``) is not
    taken for a path start. It is
    scanned once, without the root: a later path is redacted whole, even one
    inside the repository, so the scan never recurses again and stays linear
    however many paths are joined.
    """
    del repo_root_path  # deliberately not used: see above
    match = _RELATIVE_RESCAN_START.search(relative)
    if match is None:
        return relative
    start = match.start()
    return relative[:start] + _redact_text_local_paths(
        relative[start:], repo_root_path=None, strict_starts=True,
    )


def _log_resolve_failure(context: str, exc: Exception) -> None:
    _LOGGER.warning(
        "Role-Aware Dashboard Toolkit path redaction could not resolve %s (%s).",
        context,
        type(exc).__name__,
    )


__all__ = ["redact_diagnostic_path", "redact_payload_local_paths", "redact_text_local_paths"]
