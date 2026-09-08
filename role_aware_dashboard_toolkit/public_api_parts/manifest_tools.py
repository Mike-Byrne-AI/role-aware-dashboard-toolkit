from __future__ import annotations

from typing import Any
from collections.abc import Iterable, Mapping, Sequence


def assert_no_conflicting_symbol_classifications(families: Iterable[Mapping[str, Any]]) -> None:
    seen: dict[str, tuple[str, str]] = {}
    conflicts: dict[str, list[tuple[str, str]]] = {}
    for family in families:
        family_id = str(family.get("family_id") or "").strip()
        classification = str(family.get("classification") or "stable").strip() or "stable"
        for raw_symbol in family.get("symbols", []):
            symbol = str(raw_symbol or "").strip()
            if not symbol:
                continue
            first_seen = seen.get(symbol)
            if first_seen is None:
                seen[symbol] = (family_id, classification)
                continue
            if first_seen[1] == classification:
                continue
            entries = conflicts.setdefault(symbol, [first_seen])
            current = (family_id, classification)
            if current not in entries:
                entries.append(current)
    if not conflicts:
        return
    parts = []
    for symbol in sorted(conflicts):
        entries = ", ".join(f"{family_id} ({classification})" for family_id, classification in conflicts[symbol])
        parts.append(f"{symbol}: {entries}")
    raise AssertionError("Public API family classification conflicts detected: " + "; ".join(parts))


def build_export_classification_map(
    *,
    families: Sequence[Mapping[str, Any]],
    exports: Sequence[str],
) -> dict[str, str]:
    assert_no_conflicting_symbol_classifications(families)
    export_set = {str(symbol) for symbol in exports}
    mapping: dict[str, str] = {}
    for family in families:
        classification = str(family.get("classification") or "stable")
        for symbol in family.get("symbols", []):
            rendered = str(symbol)
            if rendered in export_set:
                mapping[rendered] = classification
    missing = sorted(export_set - set(mapping))
    if missing:
        rendered = ", ".join(missing)
        raise AssertionError(f"Public exports missing a documented API family: {rendered}")
    return mapping


def build_module_only_symbols(*, documented_symbols: Iterable[str], exports: Sequence[str]) -> list[str]:
    export_set = {str(symbol) for symbol in exports}
    return sorted({str(symbol) for symbol in documented_symbols} - export_set)


def build_public_api_manifest(
    *,
    exports: Sequence[str],
    families: Sequence[Mapping[str, Any]],
    documented_symbols: Iterable[str],
    root_export_budget_total: int,
) -> dict[str, Any]:
    normalized_exports = [str(symbol) for symbol in exports]
    documented = [str(symbol) for symbol in documented_symbols]
    classifications = build_export_classification_map(
        families=families,
        exports=normalized_exports,
    )
    undocumented = sorted(set(normalized_exports) - set(documented))
    module_only = build_module_only_symbols(documented_symbols=documented, exports=normalized_exports)
    classification_counts: dict[str, int] = {
        "stable": 0,
        "experimental": 0,
    }
    for symbol in normalized_exports:
        key = classifications[symbol]
        classification_counts[key] = int(classification_counts.get(key, 0)) + 1
    return {
        "export_count": len(normalized_exports),
        "exports": normalized_exports,
        "families": list(families),
        "export_classification": classifications,
        "classification_counts": classification_counts,
        "root_export_budget": {
            "total": int(root_export_budget_total),
        },
        "module_only_symbols": module_only,
        "module_only_symbol_count": len(module_only),
        "undocumented_exports": undocumented,
        "undocumented_export_count": len(undocumented),
    }

