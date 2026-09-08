from __future__ import annotations

from typing import Any


def load_optional_pandas(
    cached_module: Any,
    available: bool | None,
    *,
    checked: bool | None = None,
) -> tuple[Any, bool, bool]:
    if checked is not None and checked:
        return cached_module, cached_module is not None, True
    if checked is None:
        if available is False:
            return None, False, True
        if cached_module is not None:
            return cached_module, True, True

    try:
        import pandas as pandas_module
    except ModuleNotFoundError as exc:
        if exc.name != "pandas":
            raise
        return None, False, True
    return pandas_module, True, True


__all__ = ["load_optional_pandas"]
