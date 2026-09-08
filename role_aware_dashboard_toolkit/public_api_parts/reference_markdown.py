from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def build_public_api_reference_markdown(
    *,
    manifest: Mapping[str, Any],
    families: Sequence[Mapping[str, Any]],
    usage_recipe_lines: Sequence[str],
) -> str:
    counts = manifest["classification_counts"]
    lines = [
        "# Role-Aware Dashboard Toolkit public API families",
        "",
        "This reference is generated from the OSS-standard API manifest.",
        "",
        "## Root export boundary",
        "",
        f"- Total root exports: `{manifest['export_count']}`",
        f"- Stable exports: `{counts.get('stable', 0)}`",
        f"- Experimental exports: `{counts.get('experimental', 0)}`",
        f"- Undocumented exports: `{manifest['undocumented_export_count']}`",
        f"- Root export budget: `{manifest['root_export_budget']['total']}`",
        (
            "- Documented module-only public symbols: "
            f"`{manifest['module_only_symbol_count']}`"
        ),
        "",
        *list(usage_recipe_lines),
    ]
    export_set = set(manifest["exports"])
    for family in families:
        root_symbols = [
            symbol for symbol in family["symbols"] if symbol in export_set
        ]
        module_only_symbols = [
            symbol for symbol in family["symbols"] if symbol not in export_set
        ]
        lines.extend(
            [
                f"## {family['display_name']}",
                "",
                f"Classification: `{family['classification']}`",
                "",
                (
                    f"Root exports: `{len(root_symbols)}`; "
                    f"module-only symbols: `{len(module_only_symbols)}`."
                ),
                "",
            ]
        )
        for symbol in family["symbols"]:
            suffix = "" if symbol in export_set else " (module-only)"
            lines.append(f"- `{symbol}`{suffix}")
        lines.extend(["", family["description"], ""])
    return "\n".join(lines)


__all__ = ["build_public_api_reference_markdown"]
