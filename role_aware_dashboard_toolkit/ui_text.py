from __future__ import annotations

from html import escape
from typing import Any

from .path_redaction import redact_text_local_paths


def sanitize_caption_text(value: Any, *, repo_root: str = "") -> str:
    text = str(value or "")
    if _has_local_path_hint(text):
        text = redact_text_local_paths(text, repo_root=repo_root)
    return escape(text)


def _has_local_path_hint(value: str) -> bool:
    normalized = str(value or "").replace("\\", "/")
    if ":/" in normalized:
        return True
    for token in (
        normalized.replace('"', " ")
        .replace("'", " ")
        .replace("<", " ")
        .replace(">", " ")
        .replace("(", " ")
        .replace(")", " ")
        .split()
    ):
        if token.startswith("/") and "/" in token[1:]:
            return True
    return False


__all__ = ["sanitize_caption_text"]
