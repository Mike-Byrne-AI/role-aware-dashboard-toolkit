from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from ._exports import PUBLIC_EXPORTS
from .public_api_parts.family_registry import (
    PublicAPIFamily,
    build_public_api_families,
)
from .public_api_parts.manifest_tools import (
    assert_no_conflicting_symbol_classifications,
    build_export_classification_map,
    build_module_only_symbols,
    build_public_api_manifest,
)
from .public_api_parts.reference_markdown import (
    build_public_api_reference_markdown as _build_reference_markdown,
)
from .public_api_parts.usage_recipes import build_public_api_usage_recipe_lines

_ROOT_EXPORT_BUDGET_TOTAL = 60
_PUBLIC_API_FAMILIES = build_public_api_families()


def get_public_api_family(family_id: str) -> dict[str, Any]:
    return _PUBLIC_API_FAMILIES[str(family_id or "")].to_dict()


def list_public_api_families() -> list[dict[str, Any]]:
    return [
        family.to_dict()
        for family in sorted(
            _PUBLIC_API_FAMILIES.values(),
            key=lambda item: item.family_id,
        )
    ]


def public_api_family_map() -> dict[str, dict[str, Any]]:
    return {
        family["family_id"]: family
        for family in list_public_api_families()
    }


def iter_documented_public_symbols() -> Iterable[str]:
    for family in _PUBLIC_API_FAMILIES.values():
        yield from family.symbols


def list_public_exports() -> list[str]:
    return list(PUBLIC_EXPORTS)


def _assert_no_conflicting_symbol_classifications(
    families: Iterable[Mapping[str, Any]],
) -> None:
    assert_no_conflicting_symbol_classifications(families)


def _export_classification_map() -> dict[str, str]:
    return build_export_classification_map(
        families=list_public_api_families(),
        exports=list_public_exports(),
    )


def _module_only_public_symbols() -> list[str]:
    return build_module_only_symbols(
        documented_symbols=iter_documented_public_symbols(),
        exports=list_public_exports(),
    )


def public_api_manifest() -> dict[str, Any]:
    manifest = build_public_api_manifest(
        exports=list_public_exports(),
        families=list_public_api_families(),
        documented_symbols=iter_documented_public_symbols(),
        root_export_budget_total=_ROOT_EXPORT_BUDGET_TOTAL,
    )
    manifest["count_contract"] = {
        "policy": "oss-standard-generated-manifest",
        "export_count": manifest["export_count"],
        "classification_counts": dict(manifest["classification_counts"]),
        "root_export_budget": dict(manifest["root_export_budget"]),
        "module_only_symbol_count": manifest["module_only_symbol_count"],
        "undocumented_export_count": manifest["undocumented_export_count"],
    }
    return manifest


def build_public_api_reference_markdown() -> str:
    return _build_reference_markdown(
        manifest=public_api_manifest(),
        families=list_public_api_families(),
        usage_recipe_lines=build_public_api_usage_recipe_lines(),
    )


__all__ = [
    "PublicAPIFamily",
    "build_public_api_reference_markdown",
    "get_public_api_family",
    "iter_documented_public_symbols",
    "list_public_api_families",
    "list_public_exports",
    "public_api_family_map",
    "public_api_manifest",
]
