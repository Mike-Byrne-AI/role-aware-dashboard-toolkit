"""Dependency-free presentation resources for host-owned web applications.

These helpers render no private data and confer no authority. Hosts enforce
authentication, permissions, transactions and record-level access themselves.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from importlib import resources
import json
import re

from .appearance import build_streamlit_theme_toml


@dataclass(frozen=True)
class WebTheme:
    """Validated semantic colors shared by CSS components and Streamlit hosts."""

    ink: str = "#203D3A"
    muted: str = "#596C68"
    canvas: str = "#F4F5F0"
    surface: str = "#FFFFFF"
    accent: str = "#236354"
    accent_soft: str = "#E8F1E9"
    line: str = "#D9E2DB"
    dark: str = "#163B35"

    def __post_init__(self):
        for item in fields(self):
            value = getattr(self, item.name)
            if not isinstance(value, str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
                raise ValueError(f"{item.name} must be a six-digit hex color")

    def css(self) -> str:
        """Return a fixed-selector stylesheet; arbitrary CSS is never accepted."""
        return ":root {\n" + "".join(
            f"  --radt-{item.name.replace('_', '-')}: {getattr(self, item.name)};\n"
            for item in fields(self)
        ) + "}\n"

    def streamlit_toml(self) -> str:
        """Return compatible color configuration, without modifying any files."""
        return build_streamlit_theme_toml(
            background_color=self.canvas, secondary_background_color=self.surface,
            text_color=self.ink, primary_color=self.accent,
            sidebar_background_color=self.dark, sidebar_text_color=self.surface,
        )


_PRESETS = {
    "field": ("Fieldwork", "A good day starts with a plan.",
              WebTheme(accent="#315C83", dark="#18364F", accent_soft="#E8EFF7")),
    "studio": ("Northline Studio", "Make room for your best work.", WebTheme()),
}


def _contrast(first: str, second: str) -> float:
    def luminance(color):
        channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        values = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4
                  for value in channels]
        return sum(value * weight for value, weight in zip(values, (.2126, .7152, .0722)))
    values = sorted((luminance(first), luminance(second)))
    return (values[1] + .05) / (values[0] + .05)


@dataclass(frozen=True)
class WebPresentation:
    """Versioned, plain-data branding for a repeatable fictional web demo."""

    preset: str = "field"
    brand: str | None = None
    headline: str | None = None
    theme: WebTheme | None = None

    def __post_init__(self):
        if not isinstance(self.preset, str) or self.preset not in _PRESETS:
            raise ValueError("Choose the field or studio preset")
        brand, headline, theme = _PRESETS[self.preset]
        for name, default, limit in (("brand", brand, 80), ("headline", headline, 160)):
            value = getattr(self, name)
            value = default if value is None else value
            if not isinstance(value, str) or not value.strip() or len(value) > limit or not value.isprintable():
                raise ValueError(f"{name} must be printable text of 1 to {limit} characters")
            object.__setattr__(self, name, value.strip())
        theme = theme if self.theme is None else self.theme
        if not isinstance(theme, WebTheme):
            raise ValueError("theme must be a WebTheme")
        for foreground, background in (("ink", "canvas"), ("ink", "surface"), ("ink", "accent_soft"),
                                      ("muted", "canvas"), ("muted", "surface"),
                                      ("muted", "accent_soft"), ("accent", "surface"), ("accent", "canvas"),
                                      ("accent", "accent_soft"), ("surface", "dark")):
            if _contrast(getattr(theme, foreground), getattr(theme, background)) < 4.5:
                raise ValueError(f"Theme contrast below 4.5:1 for {foreground} on {background}")
        object.__setattr__(self, "theme", theme)

    def to_json(self) -> str:
        """Export reproducible configuration, without reading or writing files."""
        return json.dumps({"schema_version": 1, **asdict(self)}, indent=2, ensure_ascii=True) + "\n"

    @classmethod
    def from_json(cls, text: str) -> WebPresentation:
        """Validate a bounded configuration; reject unknown or duplicate keys."""
        if not isinstance(text, str) or len(text.encode("utf-8")) > 65536:
            raise ValueError("Web configuration must be at most 64 KiB")

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate web configuration key")
                result[key] = value
            return result

        try:
            data = json.loads(text, object_pairs_hook=unique)
        except (json.JSONDecodeError, RecursionError):
            raise ValueError("Web configuration must be valid JSON") from None
        if not isinstance(data, dict) or set(data) - {"schema_version", "preset", "brand", "headline", "theme"}:
            raise ValueError("Unknown web configuration fields")
        if isinstance(data.get("schema_version"), bool) or data.get("schema_version") != 1:
            raise ValueError("Web configuration requires schema_version 1")
        data.pop("schema_version")
        if "theme" in data:
            if not isinstance(data["theme"], dict) or set(data["theme"]) != {field.name for field in fields(WebTheme)}:
                raise ValueError("theme must contain exactly the eight WebTheme colors")
            data["theme"] = WebTheme(**data["theme"])
        return cls(**data)


def read_web_asset(name: str) -> str:
    """Read one fixed, version-matched component asset from the installed wheel."""
    if name not in {"components.js", "components.css", "tour.js", "presentation.js"}:
        raise ValueError("Choose components.js, components.css, tour.js or presentation.js")
    return resources.files(__package__).joinpath("resources", "web", name).read_text(encoding="utf-8")


def read_web_starter(presentation: WebPresentation | None = None) -> dict[str, str]:
    """Return a portable component gallery with two fictional brand presets."""
    presentation = presentation if presentation is not None else WebPresentation()
    if not isinstance(presentation, WebPresentation):
        raise ValueError("presentation must be a WebPresentation")
    root = resources.files(__package__).joinpath("resources", "web_starter")
    result = {name: root.joinpath(name).read_text(encoding="utf-8")
              for name in ("index.html", "gallery.js", "gallery.css", "README.md")}
    result.update({name: read_web_asset(name) for name in ("components.css", "components.js", "tour.js", "presentation.js")})
    result["theme.css"] = presentation.theme.css()
    result["web-presentation.json"] = presentation.to_json()
    result["web-config.js"] = "window.RADTWebConfig = " + presentation.to_json().rstrip().replace("<", "\\u003c") + ";\n"
    return result


def read_web_host_starter(presentation: WebPresentation | None = None) -> dict[str, str]:
    """Read an editable FastAPI application without importing or starting a host.

    The generated application's authentication, storage and workflows are consumer
    source, not library APIs. Runtime data and credentials are provisioned later.
    """
    presentation = presentation if presentation is not None else WebPresentation()
    if not isinstance(presentation, WebPresentation):
        raise ValueError("presentation must be a WebPresentation")
    root = resources.files(__package__).joinpath("resources", "web_host_starter")
    names = (
        "app.py", "manage.py", "README.md", "AGENTS.md", "host/__init__.py",
        "host/actions.py", "host/service.py", "host/auth.py", "host/storage.py",
        "static/index.html", "static/app.js", "static/app.css",
    )
    result = {name: root.joinpath(*name.split("/")).read_text(encoding="utf-8") for name in names}
    result[".gitignore"] = root.joinpath("gitignore").read_text(encoding="utf-8")
    for name in ("components.css", "components.js"):
        result["static/" + name] = read_web_asset(name)
    result["static/theme.css"] = presentation.theme.css()
    result["web-presentation.json"] = presentation.to_json()
    result["static/web-config.js"] = (
        "window.RADTWebConfig = " + presentation.to_json().rstrip().replace("<", "\\u003c") + ";\n"
    )
    return result


__all__ = ["WebTheme", "WebPresentation", "read_web_asset", "read_web_starter", "read_web_host_starter"]
