from __future__ import annotations

import re
from threading import Lock
from typing import NamedTuple


REDACTED_SECRET = "<redacted-secret>"
# Names that mark a control or a nested field as secret. A name of four or more
# characters matches anywhere in another name, ignoring case; its words may be
# joined by "_", "-" or a space, or written together ("api key" matches
# "api_key", "x-api-key" and "apiKey"). A shorter one-word name matches only a
# whole word of another name, split at separators and case changes, so "dsn"
# matches "SENTRY_DSN" and "sentryDsn" but not "kidsName".
BUILTIN_SENSITIVE_NAMES: tuple[str, ...] = (
    "token",
    "secret",
    "password",
    "passphrase",
    "passwd",
    "pwd",
    "api key",
    "private key",
    "access key",
    "authorization",
    "credential",
    "cookie",
    "jwt",
    "dsn",
    "connection string",
)
_SHORT_NAME_LENGTH = 4
_WORD_BOUNDARY_PATTERN = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])"
)
_WORD_SEPARATOR_PATTERN = re.compile(r"[\W_]+")


class _NameRules(NamedTuple):
    fragments: tuple[str, ...]
    short_words: frozenset[str]
    pattern: re.Pattern[str]


def _name_words(name: str) -> list[str]:
    spaced = _WORD_BOUNDARY_PATTERN.sub(" ", name)
    return [word.casefold() for word in _WORD_SEPARATOR_PATTERN.split(spaced) if word]


def _build_rules(names: tuple[str, ...], base: _NameRules | None = None) -> _NameRules:
    fragments = list(base.fragments) if base is not None else []
    short_words = set(base.short_words) if base is not None else set()
    for name in names:
        if not isinstance(name, str):
            raise TypeError("Sensitive names must be strings.")
        words = _name_words(name)
        if not words:
            raise ValueError("A sensitive name needs at least one letter or digit.")
        if len(words) == 1 and len(words[0]) < _SHORT_NAME_LENGTH:
            short_words.add(words[0])
            continue
        fragment = r"[_\-\s]?".join(re.escape(word) for word in words)
        if fragment not in fragments:
            fragments.append(fragment)
    return _NameRules(
        fragments=tuple(fragments),
        short_words=frozenset(short_words),
        pattern=re.compile("|".join(f"(?:{item})" for item in fragments) or r"(?!)", re.IGNORECASE),
    )


_RULES = _build_rules(BUILTIN_SENSITIVE_NAMES)
_RULES_LOCK = Lock()


def is_sensitive_name(name: str) -> bool:
    text = str(name or "")
    rules = _RULES
    if rules.pattern.search(text):
        return True
    return bool(rules.short_words) and not rules.short_words.isdisjoint(_name_words(text))


def register_sensitive_names(*names: str) -> None:
    """Treat more control and field names as secret, for this whole process.

    Names follow the built-in rules in ``BUILTIN_SENSITIVE_NAMES``. Built-in
    names cannot be removed. Register names before registering controls:
    a control's sensitivity is decided when it is registered, while audit,
    API, profile and export filters check names each time they run.
    """
    global _RULES
    with _RULES_LOCK:
        _RULES = _build_rules(tuple(names), _RULES)


__all__ = ["BUILTIN_SENSITIVE_NAMES", "REDACTED_SECRET", "is_sensitive_name", "register_sensitive_names"]
