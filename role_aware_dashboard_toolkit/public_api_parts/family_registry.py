from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .family_definitions import build_family_definitions as _build_family_definitions


@dataclass(frozen=True)
class PublicAPIFamily:
    family_id: str
    display_name: str
    symbols: tuple[str, ...]
    classification: str = "stable"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["symbols"] = list(self.symbols)
        payload["symbol_count"] = len(self.symbols)
        payload["symbol_classification"] = {
            symbol: self.classification for symbol in self.symbols
        }
        return payload


def build_public_api_families() -> dict[str, PublicAPIFamily]:
    return _build_family_definitions(PublicAPIFamily)


__all__ = ["PublicAPIFamily", "build_public_api_families"]
