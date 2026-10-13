"""API startup warnings and request size limits."""
from __future__ import annotations

import logging

import pytest

from role_aware_dashboard_toolkit import ControlRegistry, InMemoryProfileStore
from role_aware_dashboard_toolkit.api import FASTAPI_AVAILABLE, create_app

pytestmark = pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not installed")
KEY_ENV = "ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY"


def _registry() -> ControlRegistry:
    registry = ControlRegistry()
    registry.register("Banner", kind="text", key="banner", default="ready")
    return registry


def _key_warnings(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records
            if record.name == "role_aware_dashboard_toolkit.api" and KEY_ENV in record.getMessage()]


def test_create_app_warns_when_every_protected_route_would_return_401(monkeypatch, caplog):
    monkeypatch.delenv(KEY_ENV, raising=False)
    monkeypatch.delenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS", raising=False)

    with caplog.at_level(logging.WARNING, logger="role_aware_dashboard_toolkit.api"):
        create_app(_registry())

    warnings = _key_warnings(caplog)
    assert len(warnings) == 1
    assert "401" in warnings[0]
    assert all(record.levelno == logging.WARNING for record in caplog.records
               if KEY_ENV in record.getMessage())


@pytest.mark.parametrize("configured", ["key", "anonymous"])
def test_create_app_is_quiet_when_requests_can_succeed(monkeypatch, caplog, configured):
    if configured == "key":
        monkeypatch.setenv(KEY_ENV, "synthetic-startup-key")
        kwargs = {}
    else:
        monkeypatch.delenv(KEY_ENV, raising=False)
        kwargs = {"allow_anonymous": True}

    with caplog.at_level(logging.WARNING, logger="role_aware_dashboard_toolkit.api"):
        create_app(_registry(), **kwargs)

    assert _key_warnings(caplog) == []
