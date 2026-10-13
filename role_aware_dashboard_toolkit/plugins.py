from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata
import os
import re
from threading import Condition, local
import warnings
from typing import Any
from collections.abc import Callable

from .diagnostics import build_diagnostic, diagnostic_text
from .path_redaction import redact_text_local_paths


_PANEL_GROUP = "role_aware_dashboard_toolkit.panels"
_SIDEBAR_GROUP = "role_aware_dashboard_toolkit.sidebar"
_PLUGIN_GROUPS = (_PANEL_GROUP, _SIDEBAR_GROUP)
_PLUGIN_CAPABILITIES = {"sidebar", "panel", "setup"}
# A distribution (project) name as packaging writes it: letters and digits,
# with ".", "_" or "-" inside.
_DISTRIBUTION_NAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_ALLOWLIST_FORM = "distribution:group:name"
_SETUP_CONTEXT = local()


@dataclass(frozen=True)
class PluginErrorRecord:
    plugin_name: str
    stage: str
    source: str
    exception_type: str
    message: str
    # RADT-PLUGIN-TRUST marks an entry point refused before import.
    code: str = "RADT-PLUGIN"

    @property
    def diagnostic(self) -> dict[str, Any]:
        """Installed help and effect scope; never includes callback payloads."""
        return build_diagnostic(self.code)

    def __str__(self) -> str:
        return (
            f"{_diagnostic_label(self.plugin_name)} ({_exception_label(self.exception_type)}): "
            + diagnostic_text(self.code)
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


@dataclass
class _SetupAttempt:
    finished: bool = False
    succeeded: bool = False
    error: PluginErrorRecord | None = None


@dataclass
class _PluginRegistration:
    plugin: DashboardPlugin
    source: PluginSourceRecord
    initialized: bool = False
    attempt: _SetupAttempt | None = None


class PluginRegistry:
    """Own plugin registrations, with setup once per registration in this registry."""

    def __init__(self) -> None:
        self._registrations: dict[str, _PluginRegistration] = {}
        self._condition = Condition()
        self._discovery_errors: list[PluginErrorRecord] = []

    def register(self, plugin: DashboardPlugin, *, source: PluginSourceRecord | None = None) -> DashboardPlugin:
        with self._condition:
            if not str(plugin.name).strip():
                raise ValueError("Plugin name must be non-empty")
            if plugin.name in self._registrations:
                raise KeyError(f"Plugin '{plugin.name}' already registered")
            invalid = [cap for cap in plugin.capabilities if cap not in _PLUGIN_CAPABILITIES]
            if invalid:
                raise ValueError(f"Plugin '{plugin.name}' has invalid capabilities: {invalid}")
            self._registrations[plugin.name] = _PluginRegistration(
                plugin=plugin,
                source=source or PluginSourceRecord(
                    plugin_name=plugin.name,
                    source_type="manual",
                    source_ref="manual_registration",
                    trusted=True,
                ),
            )
        return plugin

    def unregister(self, name: str) -> DashboardPlugin:
        """Remove and return a plugin by name; raise KeyError when absent.

        Future dispatches skip its callbacks. Prior setup effects and stored
        records remain. Registering the plugin again runs setup again in this
        registry, without changing initialization in any other registry.
        """
        with self._condition:
            registration = self._registrations.pop(name)
            self._condition.notify_all()
            return registration.plugin

    def _snapshot(self) -> list[tuple[str, _PluginRegistration]]:
        with self._condition:
            return sorted(self._registrations.items())

    def all(self) -> list[DashboardPlugin]:
        return [registration.plugin for _, registration in self._snapshot()]

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                **registration.plugin.metadata(),
                "source": registration.source.to_dict(),
            }
            for _, registration in self._snapshot()
        ]

    def describe_sources(self) -> list[dict[str, Any]]:
        return [registration.source.to_dict() for _, registration in self._snapshot()]

    def discovery_errors(self) -> list[PluginErrorRecord]:
        with self._condition:
            return list(self._discovery_errors)

    def clear_discovery_errors(self) -> None:
        with self._condition:
            self._discovery_errors.clear()

    def initialize(self, context: Any) -> list[PluginErrorRecord]:
        errors: list[PluginErrorRecord] = []
        for name, registration in self._snapshot():
            self._initialize_plugin(name, registration, context, errors)
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
        """Load entry-point plugins from allowlisted distributions.

        Each ``trusted_entry_points`` entry names ``distribution:group:name``.
        An entry point loads only when its own installed distribution, group
        and name all match an entry, so a same-named entry point from another
        distribution is never imported; it is recorded as a discovery error
        with a RuntimeWarning instead. A ``group:name`` entry, or any other
        malformed entry, raises ValueError before anything is loaded.
        """
        allowlist = _parse_trusted_entry_points(trusted_entry_points)
        if not allow_untrusted and not allowlist:
            raise PermissionError(
                "Plugin discovery executes trusted in-process code. "
                f"Pass trusted_entry_points=['{_ALLOWLIST_FORM}'] or allow_untrusted=True."
            )
        allowlisted_names = {(group, name) for _distribution, group, name in allowlist}
        conflicts = _conflicting_entry_points(allowlist) if allowlist and not allow_untrusted else set()
        self.clear_discovery_errors()
        loaded: list[str] = []
        for group in _PLUGIN_GROUPS:
            for entry_point in _iter_entry_points(group):
                distribution = _entry_point_distribution(entry_point)
                allowlisted = bool(distribution) and (
                    _normalized_distribution(distribution), group, str(getattr(entry_point, "name", ""))
                ) in allowlist
                key = (_normalized_distribution(distribution), group, str(getattr(entry_point, "name", "")))
                if allowlisted and key in conflicts:
                    # A distribution's name is what its own metadata declares,
                    # so another installed distribution can claim it and point
                    # the entry point elsewhere. Neither can be told apart:
                    # load none, report each.
                    self._record_discovery_error(entry_point, group, PermissionError(
                        "Entry point not loaded: installed distributions named "
                        f"{_diagnostic_label(distribution)} point it at different code; remove the "
                        "copy you did not install."
                    ), trust=True)
                    continue
                if not allow_untrusted and not allowlisted:
                    if (group, str(getattr(entry_point, "name", ""))) in allowlisted_names:
                        # An allowlisted name from another (or an unknown)
                        # distribution: never imported, but reported.
                        self._record_discovery_error(entry_point, group, PermissionError(
                            "Entry point not loaded: its distribution is not allowlisted."
                        ), trust=True)
                    continue
                try:
                    obj = entry_point.load()
                    plugin = obj() if callable(obj) and not isinstance(obj, DashboardPlugin) else obj
                    if not isinstance(plugin, DashboardPlugin):
                        raise TypeError(
                            f"Entry point '{entry_point.name}' in group '{group}' did not produce a DashboardPlugin"
                        )
                    source = _entry_point_source_record(
                        plugin_name=plugin.name,
                        group=group,
                        entry_point=entry_point,
                        distribution=distribution,
                        trusted=allow_untrusted or allowlisted,
                    )
                    with self._condition:
                        if plugin.name not in self._registrations:
                            self.register(plugin, source=source)
                            loaded.append(plugin.name)
                except Exception as exc:
                    self._record_discovery_error(entry_point, group, exc)
        return loaded

    def _render(self, attr: str, context: Any, *, initialize_plugins: bool) -> list[PluginErrorRecord]:
        errors: list[PluginErrorRecord] = []
        for name, registration in self._snapshot():
            if initialize_plugins and not self._initialize_plugin(name, registration, context, errors):
                continue
            with self._condition:
                if self._registrations.get(name) is not registration or not registration.initialized:
                    continue
                # Dispatch is claimed here. Removal cannot cancel a callback
                # already selected, and host code must run outside the lock.
                fn = getattr(registration.plugin, attr)
            if fn is None:
                continue
            try:
                fn(context)
            except Exception as exc:
                errors.append(_plugin_error(registration.plugin, attr, exc))
        return errors

    def _initialize_plugin(
        self, name: str, registration: _PluginRegistration,
        context: Any, errors: list[PluginErrorRecord],
    ) -> bool:
        with self._condition:
            if self._registrations.get(name) is not registration:
                return False
            if registration.initialized:
                return True
            attempt = registration.attempt
            if attempt is not None and not attempt.finished:
                # A setup callback may re-enter this or another registry. Do
                # not wait from inside setup: reciprocal callbacks could wait
                # on each other's registrations even on different threads.
                if getattr(_SETUP_CONTEXT, "depth", 0):
                    return False
                self._condition.wait_for(
                    lambda: attempt.finished or self._registrations.get(name) is not registration,
                )
                if self._registrations.get(name) is not registration:
                    return False
                if attempt.error is not None:
                    errors.append(attempt.error)
                return attempt.succeeded
            plugin = registration.plugin
            setup = plugin.setup
            if setup is None:
                registration.initialized = True
                plugin._initialized = True
                return True
            attempt = _SetupAttempt()
            registration.attempt = attempt
        depth = getattr(_SETUP_CONTEXT, "depth", 0)
        error = None
        succeeded = False
        try:
            _SETUP_CONTEXT.depth = depth + 1
            setup(context)
            succeeded = True
        except Exception as exc:
            error = _plugin_error(plugin, "setup", exc)
            errors.append(error)
        finally:
            _SETUP_CONTEXT.depth = depth
            with self._condition:
                current = self._registrations.get(name) is registration
                attempt.error = error
                attempt.succeeded = succeeded and current
                attempt.finished = True
                if attempt.succeeded:
                    registration.initialized = True
                    # Historical informational flag; registry state owns setup.
                    plugin._initialized = True
                self._condition.notify_all()
        return attempt.succeeded

    def _record_discovery_error(
        self, entry_point: Any, group: str, exc: Exception, *, trust: bool = False,
    ) -> None:
        error = _entry_point_error(entry_point=entry_point, group=group, exc=exc, trust=trust)
        with self._condition:
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


def _entry_point_error(
    *, entry_point: Any, group: str, exc: Exception, trust: bool = False,
) -> PluginErrorRecord:
    entry_name = str(getattr(entry_point, "name", "") or "entry_point")
    source_ref = f"{group}:{entry_name}"
    return PluginErrorRecord(
        plugin_name=_diagnostic_label(entry_name),
        stage="discover",
        source=_diagnostic_label(source_ref),
        exception_type=_exception_label(type(exc).__name__),
        # A trust refusal's text is the toolkit's own, never a plugin's.
        message=_diagnostic_label(str(exc)) if trust else _diagnostic_message(exc),
        code="RADT-PLUGIN-TRUST" if trust else "RADT-PLUGIN",
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


def _normalized_distribution(name: str) -> str:
    # Distribution names compare like package installers compare them.
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_trusted_entry_points(entries: list[str] | None) -> set[tuple[str, str, str]]:
    allowlist: set[tuple[str, str, str]] = set()
    for item in list(entries or []):
        text = str(item).strip()
        if not text:
            continue
        parts = [part.strip() for part in text.split(":", 2)]
        if (
            len(parts) != 3
            or parts[0] in _PLUGIN_GROUPS
            or not _DISTRIBUTION_NAME_PATTERN.fullmatch(parts[0])
            or parts[1] not in _PLUGIN_GROUPS
            or not parts[2]
        ):
            raise ValueError(
                f"trusted_entry_points entry {text[:200]!r} must be '{_ALLOWLIST_FORM}': the installed "
                f"distribution (project) name, then {_PANEL_GROUP} or {_SIDEBAR_GROUP}, then the "
                "entry-point name. A 'group:name' entry is refused because it would also trust a "
                "same-named entry point from any other installed distribution."
            )
        allowlist.add((_normalized_distribution(parts[0]), parts[1], parts[2]))
    return allowlist


def _entry_point_distribution(entry_point: Any) -> str:
    """Return the entry point's own distribution name, or "" when unknown."""
    try:
        dist = getattr(entry_point, "dist", None)
        if dist is None:
            return ""
        metadata_obj = getattr(dist, "metadata", None)
        name = str(metadata_obj.get("Name") or "") if metadata_obj is not None else ""
        return name or str(getattr(dist, "name", "") or "")
    except Exception:
        # Unreadable metadata cannot establish trust.
        return ""


def _installed_entry_point_targets() -> list[tuple[str, str, str, str]]:
    """Return (distribution, group, name, target) for every installed plugin entry point.

    Every installed distribution is read, once per real location, including
    those that ``metadata.entry_points()`` hides behind a same-named one.
    """
    rows: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for dist in metadata.distributions():
        try:
            location = str(getattr(dist, "_path", "") or "")
            if location:
                location = os.path.realpath(location)
                if location in seen:  # one directory reached through two sys.path entries
                    continue
                seen.add(location)
            name = str(dist.metadata.get("Name") or "")
            if not name:
                continue
            for entry_point in dist.entry_points:
                if entry_point.group in _PLUGIN_GROUPS:
                    rows.append((name, entry_point.group, entry_point.name, str(entry_point.value)))
        except Exception:
            continue
    return rows


def _conflicting_entry_points(allowlist: set[tuple[str, str, str]]) -> set[tuple[str, str, str]]:
    """Return allowlisted entry points that same-named distributions point at different code.

    An editable install (``pip install -e .`` with setuptools) leaves
    ``<name>.egg-info`` on the path beside the installed ``.dist-info``: two
    distributions with one name and the same target, which count as one. A
    second distribution that claims the name with another target is the
    impostor case.
    """
    targets: dict[tuple[str, str, str], set[str]] = {}
    for name, group, entry_name, target in _installed_entry_point_targets():
        key = (_normalized_distribution(name), group, entry_name)
        if key in allowlist:
            targets.setdefault(key, set()).add("".join(target.split()))
    return {key for key, values in targets.items() if len(values) > 1}


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
    distribution: str,
    trusted: bool,
) -> PluginSourceRecord:
    return PluginSourceRecord(
        plugin_name=plugin_name,
        source_type="entry_point",
        source_ref=f"{group}:{getattr(entry_point, 'name', '')}",
        trusted=bool(trusted),
        group=str(group or ""),
        distribution=distribution,
    )


__all__ = ["DashboardPlugin", "PluginErrorRecord", "PluginRegistry", "PluginSourceRecord"]
