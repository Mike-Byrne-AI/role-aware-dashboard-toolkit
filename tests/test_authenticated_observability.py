"""Observability must not bypass the current audit-read permission."""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from role_aware_dashboard_toolkit import AuditLog
from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, InMemoryAccessStore
from role_aware_dashboard_toolkit.security import RoleDef


AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
AUDIT_MARKER = "synthetic-audit-only-value"


class _ReadTrackedAudit(AuditLog):
    def __init__(self):
        super().__init__()
        self.reads = 0

    def recent(self, limit=100):
        self.reads += 1
        return super().recent(limit)


def _consumer(host):
    from role_aware_dashboard_toolkit import DashboardConfig, DashboardSections, render
    from role_aware_dashboard_toolkit.observability import ObservabilityConfig

    def sample():
        if host.revoke_during_sample:
            host.store.replace_grants(host.principal, ())
        return {"metrics": {"throughput": 7}}

    render(DashboardConfig(
        access=host.policy, custom_roles=host.roles, audit=host.audit,
        observability=ObservabilityConfig(enabled=True, telemetry_hook=sample),
        sections=DashboardSections(
            controls=False, profiles=False, runbook=False, audit_writer=False,
            audit_log=False, plugin_details=False,
        ),
    ))


@pytest.mark.parametrize(
    "audit_allowed,revoke_during_sample,expect_audit",
    [(False, False, False), (True, True, False), (True, False, True)],
    ids=["audit-denied", "revoked-during-sample", "audit-authorized"],
)
def test_observability_checks_audit_permission_after_sampling(
    audit_allowed, revoke_during_sample, expect_audit,
):
    identity = Identity("synthetic-review", "synthetic-observer", time.time() + 3600)
    store = InMemoryAccessStore(allowed_roles=("Observer",))
    policy = AccessPolicy(lambda: identity, store, b"synthetic-observability-test-key-material")
    principal = policy.identify()
    store.replace_grants(principal, ("Observer",))
    audit = _ReadTrackedAudit()
    audit.log_control_change("audit_only_key", "before", AUDIT_MARKER)
    host = SimpleNamespace(
        policy=policy, principal=principal, store=store, audit=audit,
        revoke_during_sample=revoke_during_sample,
        roles={"Observer": RoleDef("Observer", {
            "can_view_metrics": True, "can_view_audit": audit_allowed,
        })},
    )

    app = AppTest.from_function(_consumer, args=(host,), default_timeout=15).run()

    assert not app.exception, [item.message for item in app.exception]
    assert any(item.label == "throughput" for item in app.metric)
    summaries = [json.loads(item.value) for item in app.json]
    summary = next(item for item in summaries if "recent_changes" in item)
    assert summary["latest"] == {"throughput": 7.0}
    if expect_audit:
        assert audit.reads > 0
        assert summary["recent_changes"][0]["new"] == AUDIT_MARKER
    else:
        assert audit.reads == 0
        assert summary["recent_control_changes"] == 0
        assert summary["recent_changes"] == []
        assert all(AUDIT_MARKER not in item.value for item in app.json)
