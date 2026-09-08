"""Role-Aware Dashboard Toolkit: reusable dashboard controls, profiles, audit, and operator tooling."""

from __future__ import annotations

from ._exports import PUBLIC_EXPORT_MAP, PUBLIC_EXPORTS
from .version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION

__version__ = ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION
__all__ = list(PUBLIC_EXPORTS)


def __getattr__(name: str):
    target = PUBLIC_EXPORT_MAP.get(name)
    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
    module_name, attr_name = target
    module = __import__(f"{__name__}.{module_name}", fromlist=[attr_name])
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *PUBLIC_EXPORTS})
