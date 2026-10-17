"""A successful evidence read is not authority to save a later checkpoint."""
from __future__ import annotations

import time

import pytest

from role_aware_dashboard_toolkit import AuditLog
from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, InMemoryAccessStore
from role_aware_dashboard_toolkit.access_audit import bind_audit_identity
from role_aware_dashboard_toolkit.security import BUILTIN_ROLES, RoleDef, SecurityContext
from tests.test_authenticated_mutations import _ActionStreamlit, _scenario, _snapshot


@pytest.mark.parametrize("change", ["unchanged", "revoked", "frozen", "account_changed", "approval_revoked"])
def test_checkpoint_rechecks_authority_after_reading_evidence(change):
    config, state, target, render = _scenario("run_checkpoint")
    current_identity = [Identity("synthetic-checkpoint-test", "first", time.time() + 3600)]
    store = InMemoryAccessStore()
    policy = AccessPolicy(lambda: current_identity[0], store, b"synthetic-checkpoint-key-material" * 2)
    principal = policy.identify()
    store.replace_grants(principal, ("Admin",))
    store.compare_and_set_freeze(False, 0, principal)
    roles = {"Admin": RoleDef("Admin", dict(BUILTIN_ROLES["Admin"].perms))}
    ctx = SecurityContext(
        role="Admin", perms=dict(roles["Admin"].perms), authenticated=True,
        user_id=principal, session_id="1" * 32,
        _authorize=lambda permission, writing: policy.authorize(
            principal, "Admin", permission, custom_roles=roles, write=writing,
        ),
    )
    reads = []

    class ChangingAudit(AuditLog):
        def recent(self, count=25):
            evidence = super().recent(count)
            reads.append(count)
            # An administrator/provider can change access while a store read
            # is in progress. The click and its initial check already passed.
            if change == "revoked":
                store.replace_grants(principal, ())
            elif change == "frozen":
                freeze = store.read_freeze()
                store.compare_and_set_freeze(True, freeze.revision, principal)
            elif change == "account_changed":
                current_identity[0] = Identity("synthetic-checkpoint-test", "second", time.time() + 3600)
                store.replace_grants(policy.identify(), ("Admin",))
            elif change == "approval_revoked":
                roles["Admin"].perms["can_approve_changes"] = False
            return evidence

    config.audit = bind_audit_identity(ChangingAudit(), principal, ctx.session_id)
    config.audit.log("evidence_marker", role="Admin")
    before = _snapshot(config)
    st = _ActionStreamlit(target, state)

    render(st, ctx)

    assert st.clicked and reads == [25], "Reach the authorized action and complete its evidence read."
    if change in {"revoked", "frozen", "account_changed"}:
        assert _snapshot(config) == before
        assert not any(event[0] in {"toast", "rerun"} for event in st.events)
        assert any(event[0] == "warning" and "Checkpoint" in event[1] for event in st.events)
    else:
        checkpoints = config.run_store.load("run_test")["checkpoints"]
        assert len(checkpoints) == 2
        expected_approval = "approved" if change == "unchanged" else "proposed"
        assert checkpoints[-1]["approval_state"] == expected_approval
        assert checkpoints[-1]["approval"]["state"] == expected_approval
        assert checkpoints[-1]["actor"] == principal
        assert checkpoints[-1]["audit_slice"] == before["audit"]
        assert [event["type"] for event in config.audit.all_events()] == ["evidence_marker", "checkpoint_create"]
