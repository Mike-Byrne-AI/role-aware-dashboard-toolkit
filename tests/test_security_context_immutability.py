"""Permission snapshots cannot be changed accidentally or detach live policy."""
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError, asdict, replace
import json
import operator
import pickle
import time
from types import MappingProxyType

import pytest

from role_aware_dashboard_toolkit.access import AccessPolicy, Identity, InMemoryAccessStore
from role_aware_dashboard_toolkit.security import (
    SecurityContext, can_mutate, can_write, has_perm, make_security_context,
)


@pytest.mark.parametrize("factory", [SecurityContext, make_security_context])
@pytest.mark.parametrize("readonly_input", [False, True])
def test_context_copies_permissions_from_the_host(factory, readonly_input):
    source = {"edit": False, "read": True}
    supplied = MappingProxyType(source) if readonly_input else source
    ctx = factory(role="Reader", perms=supplied)
    source["edit"] = True
    source["read"] = False

    assert has_perm(ctx, "edit") is False
    assert has_perm(ctx, "read") is True


@pytest.mark.parametrize("field,value", [
    ("role", "Admin"), ("perms", {"edit": True}), ("controls_writable", True),
    ("authenticated", False), ("user_id", "another-user"),
    ("session_id", "another-session"), ("_authorize", lambda *_: True),
])
def test_identity_and_authority_fields_cannot_be_assigned_or_deleted(field, value):
    ctx = SecurityContext(role="Reader", perms={"edit": False}, controls_writable=False,
                          authenticated=True, _authorize=lambda *_: False)
    with pytest.raises(FrozenInstanceError):
        setattr(ctx, field, value)
    with pytest.raises(FrozenInstanceError):
        delattr(ctx, field)
    assert has_perm(ctx, "edit") is False
    assert can_mutate(ctx, "edit") is False


@pytest.mark.parametrize("mutate", [
    lambda perms: operator.setitem(perms, "edit", True),
    lambda perms: operator.delitem(perms, "edit"),
    lambda perms: perms.update(edit=True),
    lambda perms: perms.clear(),
    lambda perms: perms.pop("edit"),
    lambda perms: perms.popitem(),
    lambda perms: perms.setdefault("new_permission", True),
    lambda perms: operator.ior(perms, {"edit": True}),
])
def test_permission_mutators_do_not_change_a_snapshot(mutate):
    ctx = SecurityContext(role="Reader", perms={"edit": False})
    with pytest.raises(TypeError, match="read-only"):
        mutate(ctx.perms)
    assert ctx.perms == {"edit": False}


def test_reinitializing_permissions_does_not_edit_the_existing_snapshot():
    ctx = SecurityContext(role="Reader", perms={"edit": False})
    ctx.perms.__init__({"edit": True})
    assert has_perm(ctx, "edit") is False


def test_copies_and_replacements_keep_live_revocation_and_freeze_checks():
    store = InMemoryAccessStore()
    identity = Identity("synthetic-issuer", "synthetic-user", time.time() + 60)
    policy = AccessPolicy(lambda: identity, store, b"synthetic-context-key" * 2)
    principal = policy.identify()
    store.replace_grants(principal, ("Admin",))
    store.compare_and_set_freeze(False, 0, principal)
    ctx = SecurityContext(
        role="Admin", perms={"can_edit_controls": True}, authenticated=True,
        user_id=principal,
        _authorize=lambda permission, write: policy.authorize(principal, "Admin", permission, write=write),
    )
    contexts = [ctx, copy(ctx), deepcopy(ctx), replace(ctx, session_id="replacement-session")]
    for snapshot in contexts:
        assert snapshot._authorize is ctx._authorize
        assert can_mutate(snapshot, "can_edit_controls") is True
        with pytest.raises(FrozenInstanceError):
            snapshot.authenticated = False
        with pytest.raises(TypeError):
            snapshot.perms["can_edit_controls"] = False

    store.compare_and_set_freeze(True, 1, principal)
    for snapshot in contexts:
        assert has_perm(snapshot, "can_edit_controls") is True
        assert can_write(snapshot, "can_edit_controls") is False
    store.replace_grants(principal, ())
    for snapshot in contexts:
        assert has_perm(snapshot, "can_edit_controls") is False
        assert can_mutate(snapshot, "can_edit_controls") is False


def test_dict_export_and_copy_roundtrips_preserve_values_without_mutating_the_context():
    ctx = SecurityContext(role="Reader", perms={"read": True, "edit": False})
    exported = asdict(ctx)
    assert json.loads(json.dumps(exported))["perms"] == {"read": True, "edit": False}
    assert json.loads(json.dumps(ctx.perms)) == dict(ctx.perms)
    for snapshot in [copy(ctx), deepcopy(ctx), pickle.loads(pickle.dumps(ctx))]:
        assert snapshot == ctx
        with pytest.raises(TypeError):
            snapshot.perms["edit"] = True

    editable = dict(ctx.perms)
    editable["edit"] = True
    replacement = replace(ctx, perms=editable)
    editable["edit"] = False
    assert has_perm(ctx, "edit") is False
    assert has_perm(replacement, "edit") is True
