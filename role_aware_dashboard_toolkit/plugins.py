from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata
import warnings
from typing import Any
from collections.abc import Callable

from .diagnostics import build_diagnostic, diagnostic_text
from .path_redaction import redact_text_local_paths


_PANEL_GROUP = "role_aware_dashboard_toolkit.panels"
_SIDEBAR_GROUP = "role_aware_dashboard_toolkit.sidebar"
_PLUGIN_CAPABILITIES = {"sidebar", "panel", "setup"}


@dataclass(frozen=True)
class PluginErrorRecord:
    plugin_name: str
    stage: str
    source: str
    exception_type: str
    message: str

    @property
    def diagnostic(self) -> dict[str, Any]:
        """Installed help and effect scope; never includes callback payloads."""
        return build_diagnostic("RADT-PLUGIN")

    def __str__(self) -> str:
        return (
            f"{_diagnostic_label(self.plugin_name)} ({_exception_label(self.exception_type)}): "
            + diagnostic_text("RADT-PLUGIN")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "stage": self.stage,
            "source": self.source,
            "exception_type": self.exception_type,
            "message": self.message,
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True)
class PluginSourceRecord:
    plugin_name: str
    source_type: str
    source_ref: str
    trusted: bool
    group: str = ""
    distribution: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_name": self.plugin_name,
            "source_type": self.source_type,
            "source_ref": self.source_ref,
            "trusted": self.trusted,
            "group": self.group,
            "distribution": self.distribution,
        }


@dataclass
class DashboardPlugin:
    """Role-Aware Dashboard Toolkit plugin contract.

    Plugins may add a main panel renderer and/or a sidebar renderer. Failures are
    returned to the caller so the host app can surface them clearly.
    """

    name: str
    version: str = "0.1.0"
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    setup: Callable[[Any], None] | None = None
    render_panel: Callable[[Any], None] | None = None
    render_sidebar: Callable[[Any], None] | None = None
    _initialized: bool = field(default=False, init=False, repr=False)

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": list(self.capabilities),
        }


class PluginRegistry:
    """Own plugin registrations, with setup once per registration in this registry."""

    def __init__(self) -> None:
        self._plugins: dict[str, DashboardPlugin] = {}
        self._initialized_names: set[str] = set()
        self._registration_tokens: dict[str, object] = {}
        self._sources: dict[str, PluginSourceRecord] = {}
        self._discovery_errors: list[PluginErrorRecord] = []

    def register(self, plugin: DashboardPlugin, *, source: PluginSourceRecord | None = None) -> DashboardPlugin:
        if not str(plugin.name).strip():
            raise ValueError("Plugin name must be non-empty")
        if plugin.name in self._plugins:
            raise KeyError(f"Plugin '{plugin.name}' already registered")
        invalid = [cap for cap in plugin.capabilities if cap not in _PLUGIN_CAPABILITIES]
        if invalid:
            raise ValueError(f"Plugin '{plugin.name}' has invalid capabilities: {invalid}")
        self._plugins[plugin.name] = plugin
        self._registration_tokens[plugin.name] = object()
        self._sources[plugin.name] = source or PluginSourceRecord(
            plugin_name=plugin.name,
            source_type="manual",
            source_ref="manual_registration",
            trusted=True,
        )
        return plugin

    def unregister(self, name: str) -> DashboardPlugin:
        """Remove and return a plugin by name; raise KeyError when absent.

        Future dispatches skip its callbacks. Prior setup effects and stored
        records remain. Registering the plugin again runs setup again in this
        registry, without changing initialization in any other registry.
        """
        plugin = self._plugins.pop(name)
        self._sources.pop(name, None)
        self._registration_tokens.pop(name, None)
        self._initialized_names.discard(name)
        return plugin

    def all(self) -> list[DashboardPlugin]:
        return [self._plugins[name] for name in sorted(self._plugins.keys())]

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                **plugin.metadata(),
                "source": self._sources.get(plugin.name, PluginSourceRecord(plugin.name, "unknown", "", False)).to_dict(),
            }
            for plugin in self.all()
        ]

    def describe_sources(self) -> list[dict[str, Any]]:
        return [self._sources[name].to_dict() for name in sorted(self._sources.keys())]

    def discovery_errors(self) -> list[PluginErrorRecord]:
        return list(self._discovery_errors)

    def clear_discovery_errors(self) -> None:
        self._discovery_errors.clear()

    def initialize(self, context: Any) -> list[PluginErrorRecord]:
        errors: list[PluginErrorRecord] = []
        for plugin in self.all():
            self._initialize_plugin(plugin, context, errors)
        return errors

    def render_sidebar(self, context: Any, *, initialize_plugins: bool = True) -> list[PluginErrorRecord]:
        return self._render("render_sidebar", context, initialize_plugins=initialize_plugins)

    def render_panels(self, context: Any, *, initialize_plugins: bool = True) -> list[PluginErrorRecord]:
        return self._render("render_panel", context, initialize_plugins=initialize_plugins)

    def discover(
        self,
        *,
        trusted_entry_points: list[str] | None = None,
        allow_untrusted: bool = False,
    ) -> list[str]:
        allowlist = {
            str(item).strip() for item in list(trusted_entry_points or []) if str(item).strip()
        }
        if not allow_untrusted and not allowlist:
            raise PermissionError(
                "Plugin discovery executes trusted in-process code. "
                "Pass trusted_entry_points=['group:name'] or allow_untrusted=True."
            )
        self.clear_discovery_errors()
        loaded: list[str] = []
        for group in (_PANEL_GROUP, _SIDEBAR_GROUP):
            for entry_point in _iter_entry_points(group):
                source_ref = f"{group}:{entry_point.name}"
                if not allow_untrusted and source_ref not in allowlist:
                    continue
                try:
                    obj = entry_point.load()
                    plugin = obj() if callable(obj) and not isinstance(obj, DashboardPlugin) else obj
                    if not isinstance(plugin, DashboardPlugin):
                        raise TypeError(
                            f"Entry point '{entry_point.name}' in group '{group}' did not produce a DashboardPlugin"
                        )
                    if plugin.name not in self._plugins:
                        self.register(
                            plugin,
                            source=_entry_point_source_record(
                                plugin_name=plugin.name,
                                group=group,
                                entry_point=entry_point,
                                trusted=allow_untrusted or source_ref in allowlist,
                            ),
                        )
                        loaded.append(plugin.name)
                except Exception as exc:
                    self._record_discovery_error(entry_point, group, exc)
        return loaded

    def _render(self, attr: str, context: Any, *, initialize_plugins: bool) -> list[PluginErrorRecord]:
        errors: list[PluginErrorRecord] = []
        for plugin in self.all():
            if self._plugins.get(plugin.name) is not plugin:
                continue
            if initialize_plugins and not self._initialize_plugin(plugin, context, errors):
                continue
            if not initialize_plugins and plugin.name not in self._initialized_names:
                continue
            fn = getattr(plugin, attr)
            if fn is None:
                continue
            try:
                fn(context)
            except Exception as exc:
                errors.append(_plugin_error(plugin, attr, exc))
        return errors

    def _initialize_plugin(self, plugin: DashboardPlugin, context: Any, errors: list[PluginErrorRecord]) -> bool:
        if self._plugins.get(plugin.name) is not plugin:
            return False
        if plugin.name in self._initialized_names:
            return True
        registration = self._registration_tokens[plugin.name]
        if plugin.setup is None:
            self._initialized_names.add(plugin.name)
            plugin._initialized = True
            return True
        try:
            plugin.setup(context)
        except Exception as exc:
            errors.append(_plugin_error(plugin, "setup", exc))
            return False
        # Setup may remove and re-register even the same plugin object.
        # Completion belongs only to the registration that invoked this setup.
        if self._registration_tokens.get(plugin.name) is not registration:
            return False
        self._initialized_names.add(plugin.name)
        # Retain the historical informational flag, but a registry's own
        # initialization state decides whether its setup has already run.
        plugin._initialized = True
        return True

    def _record_discovery_error(self, entry_point: Any, group: str, exc: Exception) -> None:
        error = _entry_point_error(entry_point=entry_point, group=group, exc=exc)
        self._discovery_errors.append(error)
        warnings.warn(
            (
                "Role-Aware Dashboard Toolkit plugin discovery skipped "
                f"{error.source}: {error}"
            ),
            RuntimeWarning,
            stacklevel=3,
        )


def _plugin_error(plugin: DashboardPlugin, stage: str, exc: Exception) -> PluginErrorRecord:
    return PluginErrorRecord(
        plugin_name=_diagnostic_label(plugin.name),
        stage=stage,
        source=_diagnostic_label(f"{plugin.name}.{stage}"),
        exception_type=_exception_label(type(exc).__name__),
        message=_diagnostic_message(exc),
    )


def _entry_point_error(*, entry_point: Any, group: str, exc: Exception) -> PluginErrorRecord:
    entry_name = str(getattr(entry_point, "name", "") or "entry_point")
    source_ref = f"{group}:{entry_name}"
    return PluginErrorRecord(
        plugin_name=_diagnostic_label(entry_name),
        stage="discover",
        source=_diagnostic_label(source_ref),
        exception_type=_exception_label(type(exc).__name__),
        message=_diagnostic_message(exc),
    )


def _diagnostic_label(value: str) -> str:
    # Names identify the failing integration, but need not expose local paths
    # or allow unbounded/control-character output in warnings and records.
    redacted = redact_text_local_paths(str(value))
    printable = "".join(char if char.isprintable() else " " for char in redacted)
    return " ".join(printable.split())[:160]


def _exception_label(value: str) -> str:
    return value if len(value) <= 80 and value.isidentifier() else "Exception"


def _diagnostic_message(exc: Exception) -> str:
    # A third-party exception can include credentials even after path redaction.
    # Do not inspect its message (or invoke its potentially broken __str__).
    return f"Plugin operation failed ({_exception_label(type(exc).__name__)})."


def _iter_entry_points(group: str):
    eps = metadata.entry_points()
    if hasattr(eps, "select"):
        return list(eps.select(group=group))
    return list(eps.get(group, []))


def _entry_point_source_record(
    *,
    plugin_name: str,
    group: str,
    entry_point: Any,
    trusted: bool,
) -> PluginSourceRecord:
    distribution = ""
    dist = getattr(entry_point, "dist", None)
    if dist is not None:
        metadata_obj = getattr(dist, "metadata", None)
        if metadata_obj is not None:
            distribution = str(metadata_obj.get("Name") or "")
        if not distribution:
            distribution = str(getattr(dist, "name", "") or "")
    return PluginSourceRecord(
        plugin_name=plugin_name,
        source_type="entry_point",
        source_ref=f"{group}:{getattr(entry_point, 'name', '')}",
        trusted=bool(trusted),
        group=str(group or ""),
        distribution=distribution,
    )


__all__ = ["DashboardPlugin", "PluginErrorRecord", "PluginRegistry", "PluginSourceRecord"]
