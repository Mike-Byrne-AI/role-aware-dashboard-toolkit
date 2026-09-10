"""Validated appearance settings and official Streamlit theme configuration.

Global colors belong in Streamlit's startup config. Group fills are applied only
to documented keyed-container CSS classes; unstyled rendering needs no new API.
"""
from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from inspect import signature
import re
from typing import Any

_HEX_COLOR = re.compile(r"#[0-9a-fA-F]{6}\Z")


def _color(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _HEX_COLOR.fullmatch(value) is None:
        raise ValueError(f"{name} must be a six-digit #RRGGBB color or None.")
    return value.upper()


def validate_dashboard_colors(
    card_background_color: str | None,
    group_background_colors: Mapping[str, str] | None,
) -> tuple[str | None, dict[str, str]]:
    """Validate and detach color options without importing Streamlit."""
    default = _color(card_background_color, "card_background_color")
    if group_background_colors is None:
        return default, {}
    if not isinstance(group_background_colors, Mapping):
        raise TypeError("group_background_colors must map group names to #RRGGBB colors.")
    overrides: dict[str, str] = {}
    for name, value in group_background_colors.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("group_background_colors requires nonempty string group names.")
        color = _color(value, f"group_background_colors[{name!r}]")
        if color is None:
            raise ValueError("Group background overrides must be #RRGGBB colors; omit a group to inherit.")
        overrides[name] = color
    return default, overrides


def validate_dashboard_appearance(config: Any, *, st: Any | None = None) -> None:
    """Check names after plugin setup and optional runtime support before widgets."""
    default, overrides = validate_dashboard_colors(
        getattr(config, "card_background_color", None),
        getattr(config, "group_background_colors", None),
    )
    if overrides:
        known_groups = {ctrl.group for ctrl in config.registry.all()}
        unknown = sorted(set(overrides) - known_groups)
        if unknown:
            raise ValueError(
                "group_background_colors refers to unknown control groups: "
                + ", ".join(unknown)
                + ". Use registered group names or remove these overrides."
            )
    if st is not None and (default is not None or overrides):
        _require_styling_runtime(st)


def group_background_color(config: Any, group_name: str) -> str | None:
    default, overrides = validate_dashboard_colors(
        getattr(config, "card_background_color", None),
        getattr(config, "group_background_colors", None),
    )
    return overrides.get(group_name, default)


def _group_container_key(group_name: str) -> str:
    # Display names never enter CSS selectors. The digest stays stable across
    # changes in registry order and accepts arbitrary Unicode group names.
    return "radt-group-" + sha256(group_name.encode("utf-8")).hexdigest()


def styled_group_container(st: Any, group_name: str, color: str, *, border: bool) -> Any:
    """Return a styled group container, requiring Streamlit's documented key API."""
    validated = _color(color, "group background")
    if validated is None:
        raise ValueError("A styled group container requires a #RRGGBB background color.")
    _require_styling_runtime(st)
    key = _group_container_key(group_name)
    st.html(f"<style>.st-key-{key} {{ background-color: {validated}; }}</style>")
    return st.container(key=key, border=border)


def _require_styling_runtime(st: Any) -> None:
    try:
        supports_key = "key" in signature(st.container).parameters
    except (AttributeError, TypeError, ValueError):
        supports_key = False
    if not supports_key or not callable(getattr(st, "html", None)):
        raise RuntimeError(
            "Dashboard group background colors require Streamlit >=1.39 "
            "with st.container(key=...) and st.html(). Upgrade Streamlit or "
            "remove card_background_color and group_background_colors."
        )


def build_streamlit_theme_toml(
    *,
    background_color: str | None = None,
    secondary_background_color: str | None = None,
    text_color: str | None = None,
    primary_color: str | None = None,
    sidebar_background_color: str | None = None,
    sidebar_secondary_background_color: str | None = None,
    sidebar_text_color: str | None = None,
    base: str = "light",
) -> str:
    """Return an official Streamlit theme snippet; do not write or apply it.

    Merge this text into the host project's .streamlit/config.toml before
    launching its app. Existing theme sections must be edited, not duplicated.
    Global options work with Streamlit >=1.30; sidebar overrides require >=1.44.
    Every color must be a six-digit hex string. Unset colors inherit Streamlit's
    selected base theme. This helper has no Streamlit dependency.
    """
    if base not in ("light", "dark"):
        raise ValueError("base must be 'light' or 'dark'.")
    main = {
        "backgroundColor": _color(background_color, "background_color"),
        "secondaryBackgroundColor": _color(secondary_background_color, "secondary_background_color"),
        "textColor": _color(text_color, "text_color"),
        "primaryColor": _color(primary_color, "primary_color"),
    }
    sidebar = {
        "backgroundColor": _color(sidebar_background_color, "sidebar_background_color"),
        "secondaryBackgroundColor": _color(sidebar_secondary_background_color, "sidebar_secondary_background_color"),
        "textColor": _color(sidebar_text_color, "sidebar_text_color"),
    }
    lines = [
        "# Merge into .streamlit/config.toml before starting the app.",
        "# Edit an existing [theme] section rather than adding a duplicate.",
        "# Global colors require Streamlit >=1.30.",
    ]
    if any(value is not None for value in sidebar.values()):
        lines.append("# Sidebar overrides require Streamlit >=1.44.")
    lines.extend(["[theme]", f'base = "{base}"'])
    lines.extend(f'{key} = "{value}"' for key, value in main.items() if value is not None)
    if any(value is not None for value in sidebar.values()):
        lines.extend(["", "[theme.sidebar]"])
        lines.extend(f'{key} = "{value}"' for key, value in sidebar.items() if value is not None)
    return "\n".join(lines) + "\n"


__all__ = ["build_streamlit_theme_toml"]
