"""Guard two security lines that a mutation test showed no test protected.

Each test fails when its guarded line is disabled: the sensitive=True
redaction in AuditLog.log_control_change, and the allowlist filter in
PluginRegistry.discover.
"""
from __future__ import annotations

import json

from role_aware_dashboard_toolkit import AuditLog
from role_aware_dashboard_toolkit.plugins import DashboardPlugin, PluginRegistry
from role_aware_dashboard_toolkit.sensitive_values import REDACTED_SECRET, is_sensitive_name


def test_sensitive_control_change_is_redacted_when_its_key_looks_ordinary():
    key = "feature_mode"
    # The secret-name rule must not already cover this key, or the test
    # would pass through audit-store redaction without the guarded line.
    assert is_sensitive_name(key) is False
    audit = AuditLog()

    audit.log_control_change(key, "OLD-SECRET-CANARY", "NEW-SECRET-CANARY", role="Operator", sensitive=True)

    event = audit.all_events()[-1]
    assert (event["key"], event["old"], event["new"]) == (key, REDACTED_SECRET, REDACTED_SECRET)
    assert "SECRET-CANARY" not in json.dumps(audit.all_events())
    assert "SECRET-CANARY" not in audit.export_jsonl()


def test_discovery_never_imports_an_entry_point_outside_the_allowlist(monkeypatch):
    imported = []

    class Dist:
        metadata = {"Name": "acme-panels"}

    def entry_point(name):
        class EntryPoint:
            dist = Dist()

            def load(self):
                imported.append(name)
                return DashboardPlugin(name=f"plugin-{name}", capabilities=["panel"])

        EntryPoint.name = name
        return EntryPoint()

    monkeypatch.setattr(
        "role_aware_dashboard_toolkit.plugins._iter_entry_points",
        lambda group: [entry_point("unlisted"), entry_point("listed")] if group.endswith(".panels") else [],
    )
    registry = PluginRegistry()

    loaded = registry.discover(trusted_entry_points=["acme-panels:role_aware_dashboard_toolkit.panels:listed"])

    assert loaded == ["plugin-listed"]
    assert imported == ["listed"]
    assert [source["source_ref"] for source in registry.describe_sources()] == [
        "role_aware_dashboard_toolkit.panels:listed"
    ]
