from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from ._json_safety import sanitize_non_finite_numbers
from .path_redaction import redact_payload_local_paths


def with_redacted_json(
    st: Any,
    *,
    repo_root: str | os.PathLike[Any] = "",
) -> Any:
    return _RedactedJsonStreamlit(st, repo_root=repo_root)


def redact_ui_json_payload(
    payload: Any, *, repo_root: str | os.PathLike[Any] = ""
) -> Any:
    if isinstance(payload, Mapping):
        redacted = redact_payload_local_paths(payload, repo_root=repo_root)
    else:
        redacted = redact_payload_local_paths(
            {"value": payload},
            repo_root=repo_root,
        )["value"]
    return sanitize_non_finite_numbers(redacted)


class _RedactedJsonStreamlit:
    def __init__(
        self,
        st: Any,
        *,
        repo_root: str | os.PathLike[Any] = "",
    ) -> None:
        self._st = st
        self._repo_root = repo_root

    def __getattr__(self, name: str) -> Any:
        return getattr(self._st, name)

    def json(self, payload: Any) -> None:
        self._st.json(redact_ui_json_payload(payload, repo_root=self._repo_root))


__all__ = ["redact_ui_json_payload", "with_redacted_json"]
