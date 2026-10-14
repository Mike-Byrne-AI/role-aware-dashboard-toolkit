from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Any


def strict_json_loads(raw: str | bytes | bytearray) -> Any:
    """Load standards-compliant JSON while preserving normal numeric types.

    Python's default decoder accepts the non-standard constants ``NaN`` and
    ``Infinity``. It can also turn a syntactically valid, very large exponent
    into an infinite float. Both cases are rejected here so imported and
    persisted values cannot acquire non-finite numbers through JSON decoding.
    """
    return json.loads(
        raw,
        parse_constant=_reject_non_finite_json_constant,
        parse_float=_parse_finite_json_float,
    )


def _reject_non_finite_json_constant(value: str) -> None:
    raise ValueError(f"JSON contains non-finite numeric constant {value!r}")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"JSON number is outside the finite float range: {value!r}")
    return parsed


def sanitize_non_finite_numbers(value: Any) -> Any:
    """Replace non-finite floats with ``None`` in nested JSON-like values.

    Containers are walked with plain loops, one stack frame per nesting level:
    a comprehension adds a frame per level before Python 3.12, and a
    generator does on every version, which halved the depth a packet could
    reach.
    """
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        mapping: dict[Any, Any] = {}
        for key, item in value.items():
            mapping[key] = sanitize_non_finite_numbers(item)
        return mapping
    if isinstance(value, (list, tuple)):
        items: list[Any] = []
        for item in value:
            items.append(sanitize_non_finite_numbers(item))
        return items if isinstance(value, list) else tuple(items)
    return value


__all__ = ["sanitize_non_finite_numbers", "strict_json_loads"]
