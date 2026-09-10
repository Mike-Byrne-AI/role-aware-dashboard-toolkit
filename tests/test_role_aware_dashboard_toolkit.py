import builtins
import importlib
import json
import os
import queue
import pytest
import sys
import tempfile
import types

import role_aware_dashboard_toolkit.audit as audit_module
from role_aware_dashboard_toolkit import (
    AuditLog,
    ControlRegistry,
    DashboardConfig,
    ObservabilityConfig,
    PluginRegistry,
    RoleDef,
    can_write,
    get_role,
    get_role_names,
    has_perm,
    load_profile,
    load_profile_data,
    merge_profile_values,
    normalize_telemetry,
    profile_diff,
    safe_call,
    save_profile,
    summarize_telemetry,
)
from role_aware_dashboard_toolkit.audit_store import AUDIT_EVENT_SCHEMA_VERSION
from role_aware_dashboard_toolkit.diagnostics import build_diagnostic, diagnostic_text
from role_aware_dashboard_toolkit.observability import coerce_telemetry_sample, summarize_observability
from role_aware_dashboard_toolkit.plugins import DashboardPlugin
from role_aware_dashboard_toolkit.profile_store import InMemoryProfileStore
from role_aware_dashboard_toolkit.runtime import cleanup_runtime
from role_aware_dashboard_toolkit.security import (
    BUILTIN_ROLES,
    SecurityContext,
    apply_security_fields,
    make_security_context,
    read_security_context,
)
from role_aware_dashboard_toolkit.sidebar import render_sidebar


def _install_torch_import_failure(monkeypatch, error):
    real_import = builtins.__import__
    attempts = []

    def import_hook(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "torch":
            attempts.append(name)
            raise error
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_hook)
    return attempts


class TestControlRegistry:
    def test_register_defaults(self):
        reg = ControlRegistry()
        reg.register("s", kind="slider", key="s")
        reg.register("t", kind="toggle", key="t")
        reg.register("n", kind="number", key="n")
        reg.register("x", kind="select", key="x", options=["a", "b"])
        reg.register("tx", kind="text", key="tx")
        reg.register("c", kind="color", key="c")
        assert reg.get("s").default == 0.5
        assert reg.get("t").default is False
        assert reg.get("n").default == 0.0
        assert reg.get("x").default == "a"
        assert reg.get("tx").default == ""
        assert reg.get("c").default == "#3b82f6"

    def test_register_many(self):
        reg = ControlRegistry()
        defs = [
            {"name": "A", "kind": "slider", "key": "a"},
            {"name": "B", "kind": "toggle", "key": "b"},
        ]
        results = reg.register_many(defs)
        assert len(results) == 2
        assert len(reg) == 2

    @pytest.mark.parametrize(
        "value",
        [
            float("nan"),
            float("inf"),
            float("-inf"),
            "NaN",
            "Infinity",
            "-Infinity",
            "1e9999",
        ],
    )
    @pytest.mark.parametrize("kind", ["slider", "number"])
    def test_numeric_sanitization_replaces_nonfinite_values(self, kind, value):
        reg = ControlRegistry()
        reg.register(
            "Count",
            kind=kind,
            key="count",
            default=7,
            min_value=0,
            max_value=10,
            step=1,
        )

        sanitized = reg.sanitize_value("count", value)

        assert sanitized == 7
        assert isinstance(sanitized, int if kind == "number" else float)

    @pytest.mark.parametrize(
        ("default", "min_value", "max_value", "expected"),
        [
            (float("nan"), 2.0, 9.0, 2.0),
            (float("inf"), None, 9.0, 9.0),
            (float("-inf"), None, None, 0.0),
        ],
    )
    def test_register_normalizes_nonfinite_numeric_defaults(
        self,
        default,
        min_value,
        max_value,
        expected,
    ):
        reg = ControlRegistry()

        ctrl = reg.register(
            "Threshold",
            kind="number",
            key="threshold",
            default=default,
            min_value=min_value,
            max_value=max_value,
            step=0.5,
        )

        assert ctrl.default == expected
        assert isinstance(ctrl.default, float)

    @pytest.mark.parametrize(
        ("field_name", "configured"),
        [
            ("min_value", float("nan")),
            ("max_value", float("inf")),
            ("step", float("-inf")),
            ("step", "1e9999"),
        ],
    )
    @pytest.mark.parametrize("kind", ["slider", "number"])
    def test_register_rejects_nonfinite_numeric_configuration(
        self,
        kind,
        field_name,
        configured,
    ):
        reg = ControlRegistry()
        kwargs = {field_name: configured}

        with pytest.raises(ValueError, match=rf"threshold.*{field_name}.*finite"):
            reg.register(
                "Threshold",
                kind=kind,
                key="threshold",
                default=1.0,
                **kwargs,
            )

        assert "threshold" not in reg

    @pytest.mark.parametrize(
        ("configuration", "message"),
        [
            (
                {"min_value": 2.0, "max_value": 1.0},
                "min_value must be less than or equal to max_value",
            ),
            ({"step": 0.0}, "step must be greater than zero"),
            ({"step": -0.5}, "step must be greater than zero"),
        ],
    )
    @pytest.mark.parametrize("kind", ["slider", "number"])
    def test_register_rejects_widget_unsafe_numeric_ranges(
        self,
        kind,
        configuration,
        message,
    ):
        reg = ControlRegistry()

        with pytest.raises(ValueError, match=message):
            reg.register(
                "Threshold",
                kind=kind,
                key="threshold",
                default=1.0,
                **configuration,
            )

        assert "threshold" not in reg

    def test_numeric_sanitization_ignores_nonfinite_legacy_bounds(self):
        reg = ControlRegistry()
        ctrl = reg.register(
            "Threshold",
            kind="number",
            key="threshold",
            default=3.0,
            min_value=0.0,
            max_value=10.0,
            step=0.5,
        )
        ctrl.default = float("nan")
        ctrl.min_value = float("inf")
        ctrl.max_value = 9.0

        assert reg.sanitize_value("threshold", "Infinity") == 9.0

        ctrl.default = 3.0
        ctrl.max_value = float("inf")
        assert reg.sanitize_value("threshold", -100.0) == -100.0

    def test_iter_groups_respects_visibility(self):
        reg = ControlRegistry()
        reg.register("Visible", kind="slider", key="v", group="G1")
        reg.register("Hidden", kind="slider", key="h", group="G1", visible=False)
        groups = reg.iter_groups()
        assert len(groups) == 1
        assert len(groups[0][1]) == 1

    def test_snapshot_and_restore(self):
        reg = ControlRegistry()
        reg.register("A", kind="slider", key="a", default=0.5)
        reg.register("B", kind="toggle", key="b", default=False)
        session = {"a": 0.8, "b": True}
        snap = reg.snapshot(session)
        assert snap == {"a": 0.8, "b": True}
        new_session = {}
        reg.restore(new_session, snap)
        assert new_session["a"] == 0.8
        assert new_session["b"] is True

    def test_restore_ignores_unknown_keys(self):
        reg = ControlRegistry()
        reg.register("A", kind="slider", key="a")
        session = {}
        reg.restore(session, {"a": 1.0, "unknown": "junk"})
        assert session == {"a": 1.0}

    def test_export_metadata(self):
        reg = ControlRegistry()
        reg.register("Gain", kind="slider", key="gain", group="Audio", min_value=0.0, max_value=1.0, step=0.01)
        meta = reg.export_metadata()
        assert len(meta) == 1
        assert meta[0]["name"] == "Gain"
        assert meta[0]["kind"] == "slider"
        assert "callback" not in meta[0]

    def test_sensitive_controls_are_inferred_and_can_be_overridden(self):
        reg = ControlRegistry()
        inferred = reg.register("API Token", kind="text", key="api_token", default="token-default")
        opted_out = reg.register("Token Count", kind="number", key="token_count", default=3, sensitive=False)

        assert inferred.sensitive is True
        assert opted_out.sensitive is False

        session = {"api_token": "live-token", "token_count": 7}
        assert reg.snapshot(session) == session
        assert reg.persistable_snapshot(session) == {"token_count": 7}

        metadata = {item["key"]: item for item in reg.export_metadata()}
        assert metadata["api_token"]["default"] == "<redacted-secret>"
        assert metadata["api_token"]["sensitive"] is True
        assert metadata["token_count"]["default"] == 3
        assert metadata["token_count"]["sensitive"] is False


class TestSecurity:
    def test_make_security_context(self):
        ctx = make_security_context("Admin", {"can_edit": True})
        assert ctx.role == "Admin"
        assert ctx.perms["can_edit"] is True
        assert ctx.controls_writable is True

    def test_has_perm_true(self):
        ctx = make_security_context("Admin", {"can_edit_controls": True})
        assert has_perm(ctx, "can_edit_controls") is True

    def test_has_perm_false(self):
        ctx = make_security_context("Viewer", {"can_edit_controls": False})
        assert has_perm(ctx, "can_edit_controls") is False

    def test_has_perm_missing_key_uses_default(self):
        ctx = make_security_context("Admin", {})
        assert has_perm(ctx, "nonexistent", default=True) is True
        assert has_perm(ctx, "nonexistent", default=False) is False

    def test_has_perm_none_context(self):
        assert has_perm(None, "anything") is False
        assert has_perm(None, "anything", default=True) is True

    def test_has_perm_surfaces_malformed_permission_mapping(self):
        class BrokenPerms(dict):
            def get(self, *_args, **_kwargs):
                raise RuntimeError("bad permissions")

        ctx = SecurityContext(role="Broken", perms=BrokenPerms())
        try:
            has_perm(ctx, "can_edit_controls", default=True)
        except RuntimeError as exc:
            assert str(exc) == "bad permissions"
        else:
            raise AssertionError("has_perm should surface malformed permission mappings")

    def test_can_write_respects_freeze(self):
        ctx = make_security_context("Operator", {"can_edit_controls": True}, controls_writable=False)
        assert can_write(ctx, "can_edit_controls") is False

    def test_builtin_roles_exist(self):
        assert "Admin" in BUILTIN_ROLES
        assert "Operator" in BUILTIN_ROLES
        assert "Viewer" in BUILTIN_ROLES
        assert "Approver" in BUILTIN_ROLES
        assert "Auditor" in BUILTIN_ROLES

    def test_read_only_builtin_roles_have_no_mutation_permissions(self):
        mutation_permissions = {
            "can_edit_controls",
            "can_manage_audit",
            "can_save_profiles",
            "can_load_profiles",
            "can_manage_runs",
            "can_approve_changes",
            "can_replay_runs",
            "can_comment_runs",
            "can_assign_reviews",
            "can_signoff_runs",
            "can_manage_team_ops",
            "can_manage_decisions",
            "can_manage_governance",
        }

        for role_name in ("Auditor", "Viewer"):
            granted = {
                permission
                for permission in mutation_permissions
                if BUILTIN_ROLES[role_name].perms.get(permission, False)
            }
            assert granted == set(), f"{role_name} unexpectedly grants {sorted(granted)}"

    def test_only_admin_can_manage_audit_by_default(self):
        assert BUILTIN_ROLES["Admin"].perms["can_manage_audit"] is True
        for role_name in ("Operator", "Approver", "Auditor", "Viewer"):
            assert BUILTIN_ROLES[role_name].perms["can_manage_audit"] is False

    def test_approver_cannot_load_profiles_but_keeps_review_authority(self):
        perms = BUILTIN_ROLES["Approver"].perms
        assert perms["can_load_profiles"] is False
        assert perms["can_approve_changes"] is True
        assert perms["can_assign_reviews"] is True
        assert perms["can_signoff_runs"] is True

    def test_get_role_names_with_custom(self):
        custom = {"Safety Lead": RoleDef(name="Safety Lead")}
        names = get_role_names(custom)
        assert "Admin" in names
        assert "Safety Lead" in names

    def test_get_role_returns_none_for_unknown(self):
        assert get_role("Nonexistent") is None


class TestAuditLog:
    def test_log_and_recent(self):
        audit = AuditLog(max_events=10)
        audit.log_control_change("test_key", 1, 2, role="Admin")
        recent = audit.recent(5)
        assert len(recent) == 1
        assert recent[0]["key"] == "test_key"
        assert recent[0]["type"] == "control_change"

    def test_log_return_and_writer_queue_do_not_alias_stored_nested_values(self):
        audit = AuditLog()
        audit._writer_queue = queue.Queue()
        value = {"settings": {"retries": 3}}

        logged = audit.log("configuration", new_value=value)
        queued = audit._writer_queue.get_nowait()
        value["settings"]["retries"] = 4
        logged["new"]["settings"]["retries"] = 5
        queued["new"]["settings"]["retries"] = 6

        assert audit.all_events()[0]["new"] == {"settings": {"retries": 3}}

    def test_recent_returns_deeply_detached_events(self):
        audit = AuditLog()
        audit.log("configuration", new_value={"settings": {"retries": 3}})

        recent = audit.recent()
        recent[0]["new"]["settings"]["retries"] = 9

        assert audit.recent()[0]["new"] == {"settings": {"retries": 3}}

    def test_all_events_returns_deeply_detached_events(self):
        audit = AuditLog()
        audit.log("configuration", new_value={"settings": {"retries": 3}})

        events = audit.all_events()
        events[0]["new"]["settings"]["retries"] = 9

        assert audit.all_events()[0]["new"] == {"settings": {"retries": 3}}

    def test_ring_buffer_caps(self):
        audit = AuditLog(max_events=10)
        for i in range(25):
            audit.log("event", key=str(i))
        assert len(audit) == 10
        events = audit.all_events()
        assert events[0]["key"] == "15"

    def test_non_positive_limits_return_no_events(self):
        audit = AuditLog()
        audit.log_control_change("temperature", 0.7, 0.8, role="Admin")
        audit.log_profile_save("prod", role="Admin")

        assert audit.recent(0) == []
        assert audit.recent(-1) == []
        assert audit.filter_events(limit=0) == []
        assert audit.filter_events(limit=-1) == []
        assert audit.replay_plan(limit=0)["event_count"] == 0

    def test_filter_export_and_replay(self):
        audit = AuditLog()
        audit.log_control_change("temperature", 0.7, 0.8, role="Admin")
        audit.log_control_change("top_p", 0.9, 0.95, role="Admin")
        audit.log_profile_save("prod", role="Admin")
        filtered = audit.filter_events(event_types=["control_change"], key="temp")
        assert len(filtered) == 1
        assert filtered[0]["key"] == "temperature"
        replay = audit.replay_plan(limit=10)
        assert replay["event_count"] == 2
        assert replay["preview_state"]["temperature"] == 0.8
        assert "control_change" in audit.export_jsonl()

    def test_malformed_events_are_searchable_without_breaking_replay(self):
        audit = AuditLog()
        audit._events.extend(
            [
                "legacy raw event",
                {
                    "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
                    "ts": "legacy",
                    "type": "control_change",
                    "key": "unsafe",
                    "new": 99,
                },
            ]
        )
        audit.log_control_change("temperature", 0.7, 0.8, role="Admin")

        filtered = audit.filter_events(event_types=["malformed"], text="legacy")
        assert filtered == [
            {
                "type": "malformed",
                "detail": "legacy raw event",
                "source": "malformed_audit_event",
                "malformed": True,
            },
            {
                "ts": "legacy",
                "type": "malformed",
                "key": "unsafe",
                "new": 99,
                "original_type": "control_change",
                "source": "malformed_audit_event",
                "malformed": True,
            },
        ]
        assert all("schema_version" not in event for event in filtered)

        replay = audit.replay_plan(limit=10)
        assert replay["event_count"] == 1
        assert replay["preview_state"] == {"temperature": 0.8}

        exported = [json.loads(line) for line in audit.export_jsonl().splitlines()]
        assert exported[0] == "legacy raw event"
        assert exported[1] == {
            "schema_version": AUDIT_EVENT_SCHEMA_VERSION,
            "ts": "legacy",
            "type": "control_change",
            "key": "unsafe",
            "new": 99,
        }

    def test_writer_creates_file_and_flushes_on_stop(self):
        audit = AuditLog()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_audit.jsonl")
            audit.start_writer(path)
            for i in range(3):
                audit.log("test_event", key=f"k{i}", detail="hello")
            audit.stop_writer()
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            parsed = [json.loads(line) for line in lines]
            assert [event["key"] for event in parsed] == ["k0", "k1", "k2"]


class TestProfiles:
    def _make_registry(self):
        reg = ControlRegistry()
        reg.register("A", kind="slider", key="a", default=0.5)
        reg.register("B", kind="toggle", key="b", default=False)
        return reg

    def test_save_and_load(self):
        reg = self._make_registry()
        session = {"a": 0.9, "b": True}
        with tempfile.TemporaryDirectory() as tmpdir:
            save_profile("test", reg, session, role="Admin", profile_dir=tmpdir)
            assert "test" in load_profile_data("test", profile_dir=tmpdir)["profile_id"]
            new_session = {}
            result = load_profile("test", reg, new_session, profile_dir=tmpdir)
            assert result is not None
            assert new_session["a"] == 0.9
            assert new_session["b"] is True
            assert result["role"] == "Admin"

    def test_profile_lineage_and_diff(self):
        reg = self._make_registry()
        with tempfile.TemporaryDirectory() as tmpdir:
            base_session = {"a": 0.1, "b": False}
            save_profile("base", reg, base_session, profile_dir=tmpdir)
            child_session = {"a": 0.8, "b": False}
            save_profile(
                "child",
                reg,
                child_session,
                profile_dir=tmpdir,
                parent_profile_id="base",
                parent_values=base_session,
            )
            child = load_profile_data("child", profile_dir=tmpdir)
            assert child["parent_profile_id"] == "base"
            assert child["diff_from_parent"]["a"] == {"from": 0.1, "to": 0.8}

    def test_profile_diff_and_merge_helpers(self):
        assert profile_diff({"a": 1, "b": 2}, {"a": 1, "b": 3}) == {"b": {"from": 2, "to": 3}}
        assert merge_profile_values({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    def test_profiles_omit_sensitive_controls_and_ignore_legacy_values(self):
        reg = ControlRegistry()
        reg.register("API Token", kind="text", key="api_token", default="")
        reg.register("Mode", kind="select", key="mode", options=["safe", "fast"], default="safe")
        store = InMemoryProfileStore()

        save_profile(
            "secure",
            reg,
            {"api_token": "top-secret", "mode": "safe"},
            extra={"api_key": "extra-secret", "owner": "ops"},
            store=store,
        )

        saved = store.load("secure")
        assert saved["values"] == {"mode": "safe"}
        assert saved["extra"] == {"owner": "ops"}
        token_meta = next(item for item in saved["control_meta"] if item["key"] == "api_token")
        assert token_meta["default"] == "<redacted-secret>"

        legacy = dict(saved)
        legacy["profile_id"] = "legacy"
        legacy["values"] = {"api_token": "stored-secret", "mode": "fast"}
        legacy["control_meta"] = [{"key": "api_token", "default": "stored-secret"}]
        legacy["diff_from_parent"] = {"api_token": {"from": "old", "to": "stored-secret"}}
        store.save(legacy)

        session = {"api_token": "live-secret", "mode": "safe"}
        loaded = load_profile("legacy", reg, session, store=store)

        assert session["api_token"] == "live-secret"
        assert session["mode"] == "fast"
        assert loaded["values"] == {"mode": "fast"}
        assert "api_token" not in loaded["values"]
        assert loaded["diff_from_parent"] == {}
        loaded_token_meta = next(item for item in loaded["control_meta"] if item["key"] == "api_token")
        assert loaded_token_meta["default"] == "<redacted-secret>"

    def test_sidebar_profile_source_caption_redacts_local_paths(self, tmp_path):
        reg = self._make_registry()
        source_path = tmp_path / "private" / "profile-source.json"
        source_path.parent.mkdir()
        save_profile("leaky", reg, {"a": 0.3, "b": True}, profile_dir=str(tmp_path), source=str(source_path))
        config = DashboardConfig(registry=reg, profile_dir=str(tmp_path))
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_profile_choice"] = "leaky"

        render_sidebar(fake_st, config)

        assert f"Source: {source_path}" not in fake_st.messages["caption"]
        assert "Source: private/profile-source.json" in fake_st.messages["caption"]


class TestHardeningHelpers:
    def test_dashboard_config_preserves_empty_injected_objects(self):
        registry = ControlRegistry()
        audit = AuditLog()

        config = DashboardConfig(registry=registry, audit=audit)

        assert config.registry is registry
        assert config.audit is audit

    def test_sanitize_session_state_clamps_slider(self):
        reg = ControlRegistry()
        reg.register("Temp", kind="slider", key="temp", default=0.5, min_value=0.0, max_value=1.0, step=0.01)
        session = {"temp": 2.5}
        corrected = reg.sanitize_session_state(session)
        assert corrected == 1
        assert session["temp"] == 1.0

    def test_restore_validates_select_and_numeric(self):
        reg = ControlRegistry()
        reg.register("Mode", kind="select", key="mode", options=["fast", "safe"], default="safe")
        reg.register("Count", kind="number", key="count", default=5, min_value=0, max_value=10, step=1)
        session = {}
        corrected = reg.restore(session, {"mode": "broken", "count": 999})
        assert corrected == 2
        assert session == {"mode": "safe", "count": 10}

    def test_user_set_markers_round_trip(self):
        reg = ControlRegistry()
        reg.register("X", kind="slider", key="x")
        session = {}
        assert reg.is_user_set("x", session) is False
        reg.mark_user_set("x", session)
        assert reg.is_user_set("x", session) is True
        reg.clear_user_set("x", session)
        assert reg.is_user_set("x", session) is False

    def test_apply_and_read_security_context(self):
        class Dummy:
            pass

        obj = Dummy()
        ctx = apply_security_fields(obj, "Operator", {"can_view_audit": True}, controls_writable=False)
        assert ctx.role == "Operator"
        recovered = read_security_context(obj)
        assert recovered is not None
        assert recovered.role == "Operator"
        assert recovered.controls_writable is False
        assert has_perm(recovered, "can_view_audit") is True

    def test_safe_call_returns_default_and_calls_handler(self):
        seen = {}

        def boom():
            raise RuntimeError("nope")

        def on_error(exc):
            seen["msg"] = str(exc)
            seen["record"] = exc.role_aware_dashboard_toolkit_error_record.to_dict()

        result = safe_call(boom, default="fallback", on_error=on_error)
        assert result == "fallback"
        assert seen["msg"] == "nope"
        assert seen["record"]["stage"] == "safe_call"
        assert seen["record"]["source"].endswith("test_safe_call_returns_default_and_calls_handler.<locals>.boom")
        assert seen["record"]["exception_type"] == "RuntimeError"
        assert seen["record"]["message"] == "A callback failed."

    def test_safe_call_error_record_redacts_local_paths(self, tmp_path):
        seen = {}
        secret_path = tmp_path / "runtime" / "secret.txt"

        def boom():
            raise RuntimeError(f"failed reading {secret_path}")

        def on_error(exc):
            seen["record"] = exc.role_aware_dashboard_toolkit_error_record.to_dict()

        result = safe_call(boom, default="fallback", on_error=on_error)

        assert result == "fallback"
        assert seen["record"]["message"] == "A callback failed."
        assert str(secret_path) not in seen["record"]["message"]

    def test_safe_call_without_handler_warns_before_returning_default(self):
        def boom():
            raise ValueError("missing handler")

        with pytest.warns(RuntimeWarning, match="safe_call suppressed ValueError"):
            result = safe_call(boom, default="fallback")

        assert result == "fallback"

    def test_normalize_and_summarize_telemetry(self):
        payload = {
            "latency": 0.5,
            "nested": {"latency": 0.7, "risk": 0.2},
            "steps": [{"risk": 0.9}, {"risk": 0.3}],
            "ignored": True,
        }
        normalized = normalize_telemetry(payload)
        assert normalized["latency"] == 0.7
        assert normalized["nested.risk"] == 0.2
        assert normalized["risk"] == 0.9
        summary = summarize_telemetry(payload)
        assert summary["max_metric"] == "risk"
        assert summary["max_value"] == 0.9
        assert summary["metric_count"] >= 3

    def test_cleanup_runtime_stops_writer_and_clears_ref(self):
        class Dummy:
            cache = "x"

        audit = AuditLog()
        with tempfile.TemporaryDirectory() as tmpdir:
            audit.start_writer(os.path.join(tmpdir, "audit.jsonl"))
            obj = Dummy()
            report = cleanup_runtime(audit=audit, refs=[(obj, "cache")], try_torch_cuda_empty_cache=False)
            assert report["audit_writer_stopped"] is True
            assert obj.cache is None
            assert report["cleared_refs"] == ["cache"]
            assert report["error_records"] == []

    def test_cleanup_runtime_reports_structured_warning_records(self):
        class BadAudit:
            def stop_writer(self):
                raise RuntimeError("stop failed")

        report = cleanup_runtime(
            audit=BadAudit(),
            refs=[("value", "missing")],
            run_gc=False,
            try_torch_cuda_empty_cache=False,
        )

        assert report["warnings"][0] == f"audit.stop_writer failed: RuntimeError: {diagnostic_text('RADT-AUDIT-IO')}"
        assert report["error_records"][0] == {
            "stage": "audit.stop_writer",
            "source": "AuditLog.stop_writer",
            "exception_type": "RuntimeError",
            "error_type": "RuntimeError",
            "message": "Audit persistence could not be confirmed.",
            "diagnostic": build_diagnostic("RADT-AUDIT-IO"),
        }
        assert report["error_records"][1]["stage"] == "clear_ref"
        assert report["error_records"][1]["source"] == "str.missing"
        assert report["error_records"][1]["exception_type"] == "AttributeError"
        assert report["error_records"][1]["error_type"] == "AttributeError"

    def test_cleanup_runtime_reports_writer_shutdown_timeout(self, tmp_path):
        class _StuckThread:
            def is_alive(self):
                return True

            def join(self, timeout=None):
                return None

        audit = AuditLog()
        audit._writer_thread = _StuckThread()
        audit._writer_queue = queue.Queue()
        audit._writer_store = object()
        audit._writer_path = str(tmp_path / "audit.jsonl")

        report = cleanup_runtime(
            audit=audit,
            run_gc=False,
            try_torch_cuda_empty_cache=False,
        )

        status = audit.writer_status()
        assert report["audit_writer_stopped"] is False
        assert len(report["error_records"]) == 1
        assert report["error_records"][0] == {
            "stage": "audit.stop_writer",
            "source": "AuditLog.stop_writer",
            "exception_type": "TimeoutError",
            "error_type": "TimeoutError",
            "message": "Audit persistence could not be confirmed.",
            "diagnostic": build_diagnostic("RADT-AUDIT-IO"),
        }
        assert report["warnings"] == [
            f"audit.stop_writer failed: TimeoutError: {diagnostic_text('RADT-AUDIT-IO')}"
        ]
        assert status["writer_active"] is True
        assert audit._writer_path == str(tmp_path / "audit.jsonl")
        assert status["writer_error_count"] == 1
        assert status["last_writer_error"]["error_type"] == "TimeoutError"

    def test_cleanup_runtime_does_not_import_torch_when_cuda_cleanup_is_disabled(self, monkeypatch):
        attempts = _install_torch_import_failure(
            monkeypatch,
            AssertionError("torch import should be disabled"),
        )

        report = cleanup_runtime(run_gc=False, try_torch_cuda_empty_cache=False)

        assert attempts == []
        assert report["cuda_cache_cleared"] is False
        assert report["warnings"] == []
        assert report["error_records"] == []

    def test_cleanup_runtime_treats_missing_top_level_torch_as_optional(self, monkeypatch):
        attempts = _install_torch_import_failure(
            monkeypatch,
            ModuleNotFoundError("No module named 'torch'", name="torch"),
        )

        report = cleanup_runtime(run_gc=False)

        assert attempts == ["torch"]
        assert report == {
            "audit_writer_stopped": False,
            "cleared_refs": [],
            "gc_collected": None,
            "cuda_cache_cleared": False,
            "warnings": [],
            "error_records": [],
        }

    @pytest.mark.parametrize(
        ("import_error", "expected_type", "expected_message"),
        [
            (
                ModuleNotFoundError("broken Torch extension", name="torch._C"),
                "ModuleNotFoundError",
                "broken Torch extension",
            ),
            (ImportError("Torch DLL load failed"), "ImportError", "Torch DLL load failed"),
        ],
    )
    def test_cleanup_runtime_reports_broken_torch_imports(
        self,
        monkeypatch,
        import_error,
        expected_type,
        expected_message,
    ):
        _install_torch_import_failure(monkeypatch, import_error)

        report = cleanup_runtime(run_gc=False)

        assert report["cuda_cache_cleared"] is False
        assert report["error_records"] == [
            {
                "stage": "cuda_cleanup",
                "source": "import torch",
                "exception_type": expected_type,
                "error_type": expected_type,
                "message": "A callback failed.",
                "diagnostic": build_diagnostic("RADT-CALLBACK"),
            }
        ]
        assert report["warnings"] == [f"cuda cleanup skipped: {expected_type}: {diagnostic_text('RADT-CALLBACK')}"]

    def test_cleanup_runtime_treats_missing_cuda_namespace_as_expected(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace())

        report = cleanup_runtime(run_gc=False)

        assert report["cuda_cache_cleared"] is False
        assert report["warnings"] == []
        assert report["error_records"] == []

    def test_cleanup_runtime_reports_cuda_namespace_lookup_failures(self, monkeypatch):
        class BrokenTorch:
            @property
            def cuda(self):
                raise OSError("CUDA namespace lookup failed")

        monkeypatch.setitem(sys.modules, "torch", BrokenTorch())

        report = cleanup_runtime(run_gc=False)

        assert report["cuda_cache_cleared"] is False
        assert report["error_records"] == [
            {
                "stage": "cuda_cleanup",
                "source": "torch.cuda",
                "exception_type": "OSError",
                "error_type": "OSError",
                "message": "A callback failed.",
                "diagnostic": build_diagnostic("RADT-CALLBACK"),
            }
        ]
        assert report["warnings"] == [f"cuda cleanup skipped: OSError: {diagnostic_text('RADT-CALLBACK')}"]

    def test_cleanup_runtime_treats_falsey_cuda_namespace_as_expected(self, monkeypatch):
        class FalseyCuda:
            def __bool__(self):
                return False

            def is_available(self):
                pytest.fail("is_available must not run for a falsey CUDA namespace")

            def empty_cache(self):
                pytest.fail("empty_cache must not run for a falsey CUDA namespace")

        cuda = FalseyCuda()

        monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(cuda=cuda))

        report = cleanup_runtime(run_gc=False)

        assert report["cuda_cache_cleared"] is False
        assert report["warnings"] == []
        assert report["error_records"] == []

    def test_cleanup_runtime_reports_cuda_truthiness_failures(self, monkeypatch):
        class BrokenTruthinessCuda:
            def __bool__(self):
                raise RuntimeError("CUDA truthiness failed")

            def is_available(self):
                pytest.fail("is_available must not run after a truthiness failure")

        monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(cuda=BrokenTruthinessCuda()))

        report = cleanup_runtime(run_gc=False)

        assert report["cuda_cache_cleared"] is False
        assert report["error_records"] == [
            {
                "stage": "cuda_cleanup",
                "source": "torch.cuda",
                "exception_type": "RuntimeError",
                "error_type": "RuntimeError",
                "message": "A callback failed.",
                "diagnostic": build_diagnostic("RADT-CALLBACK"),
            }
        ]
        assert report["warnings"] == [f"cuda cleanup skipped: RuntimeError: {diagnostic_text('RADT-CALLBACK')}"]

    def test_cleanup_runtime_treats_unavailable_cuda_as_expected(self, monkeypatch):
        calls = []
        cuda = types.SimpleNamespace(
            is_available=lambda: calls.append("is_available") or False,
            empty_cache=lambda: pytest.fail("empty_cache must not run when CUDA is unavailable"),
        )
        monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(cuda=cuda))

        report = cleanup_runtime(run_gc=False)

        assert calls == ["is_available"]
        assert report["cuda_cache_cleared"] is False
        assert report["warnings"] == []
        assert report["error_records"] == []

    @pytest.mark.parametrize(
        ("failure_stage", "expected_source", "expected_type", "expected_message"),
        [
            (
                "is_available",
                "torch.cuda.is_available",
                "ModuleNotFoundError",
                "CUDA probe lost torch",
            ),
            (
                "empty_cache",
                "torch.cuda.empty_cache",
                "RuntimeError",
                "CUDA cache clear failed",
            ),
        ],
    )
    def test_cleanup_runtime_reports_cuda_failures(
        self,
        monkeypatch,
        failure_stage,
        expected_source,
        expected_type,
        expected_message,
    ):
        class FailingCuda:
            def is_available(self):
                if failure_stage == "is_available":
                    raise ModuleNotFoundError(expected_message, name="torch")
                return True

            def empty_cache(self):
                if failure_stage == "empty_cache":
                    raise RuntimeError(expected_message)

        monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(cuda=FailingCuda()))

        report = cleanup_runtime(run_gc=False)

        assert report["cuda_cache_cleared"] is False
        assert report["error_records"] == [
            {
                "stage": "cuda_cleanup",
                "source": expected_source,
                "exception_type": expected_type,
                "error_type": expected_type,
                "message": "A callback failed.",
                "diagnostic": build_diagnostic("RADT-CALLBACK"),
            }
        ]
        assert report["warnings"] == [f"cuda cleanup skipped: {expected_type}: {diagnostic_text('RADT-CALLBACK')}"]

    def test_cleanup_runtime_marks_successful_cuda_cache_clear(self, monkeypatch):
        calls = []
        cuda = types.SimpleNamespace(
            is_available=lambda: True,
            empty_cache=lambda: calls.append("empty_cache"),
        )
        monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(cuda=cuda))

        report = cleanup_runtime(run_gc=False)

        assert calls == ["empty_cache"]
        assert report["cuda_cache_cleared"] is True
        assert report["warnings"] == []
        assert report["error_records"] == []


class TestObservabilityAndPlugins:
    def test_coerce_and_summarize_observability(self):
        audit = AuditLog()
        audit.log_control_change("temperature", 0.7, 0.8)
        history = [
            coerce_telemetry_sample({"metrics": {"latency_ms": 100, "risk_score": 0.1}}),
            coerce_telemetry_sample({"metrics": {"latency_ms": 130, "risk_score": 0.3}}),
        ]
        summary = summarize_observability(history, audit)
        assert summary["sample_count"] == 2
        assert summary["latest"]["latency_ms"] == 130
        assert "latency_ms" in summary["drift"]

    def test_plugin_registry_collects_errors(self):
        registry = PluginRegistry()

        def boom(_context):
            raise RuntimeError("bad plugin")

        registry.register(DashboardPlugin(name="bad", render_panel=boom))
        errors = registry.render_panels({})
        assert [str(error) for error in errors] == ["bad (RuntimeError): " + diagnostic_text("RADT-PLUGIN")]
        assert errors[0].stage == "render_panel"
        assert errors[0].exception_type == "RuntimeError"


class _FakeContext:
    def __init__(self, root):
        self._root = root

    def __enter__(self):
        return self._root

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeStreamlit(_FakeContext):
    def __init__(self):
        super().__init__(self)
        self.session_state = {}
        self.sidebar = _FakeContext(self)
        self.messages = {"info": [], "warning": [], "error": [], "toast": [], "title": [], "caption": []}

    def header(self, *args, **kwargs):
        return None

    def title(self, message, *args, **kwargs):
        self.messages["title"].append(message)

    def caption(self, message, *args, **kwargs):
        self.messages["caption"].append(message)

    def info(self, message, *args, **kwargs):
        self.messages["info"].append(message)

    def warning(self, message, *args, **kwargs):
        self.messages["warning"].append(message)

    def error(self, message, *args, **kwargs):
        self.messages["error"].append(message)

    def toast(self, message, *args, **kwargs):
        self.messages["toast"].append(message)

    def divider(self, *args, **kwargs):
        return None

    def subheader(self, *args, **kwargs):
        return None

    def markdown(self, *args, **kwargs):
        return None

    def dataframe(self, *args, **kwargs):
        return None

    def json(self, *args, **kwargs):
        return None

    def download_button(self, *args, **kwargs):
        return False

    def rerun(self, *args, **kwargs):
        return None

    def expander(self, *args, **kwargs):
        return _FakeContext(self)

    def container(self, *args, **kwargs):
        return _FakeContext(self)

    def columns(self, spec, *args, **kwargs):
        count = spec if isinstance(spec, int) else len(spec)
        return [_FakeContext(self) for _ in range(count)]

    def selectbox(self, label, options, index=0, key=None, disabled=False, **kwargs):
        value = self.session_state.get(key, options[index] if options else None)
        if key is not None:
            self.session_state[key] = value
        return value

    def multiselect(self, label, options, default=None, key=None, **kwargs):
        value = self.session_state.get(key, list(default if default is not None else options))
        if key is not None:
            self.session_state[key] = value
        return value

    def text_input(self, label, value="", key=None, **kwargs):
        current = self.session_state.get(key, value)
        if key is not None:
            self.session_state[key] = current
        return current

    def toggle(self, label, value=False, key=None, disabled=False, **kwargs):
        current = bool(self.session_state.get(key, value))
        if key is not None:
            self.session_state[key] = current
        return current

    def slider(self, label, min_value=0.0, max_value=1.0, value=0.0, key=None, **kwargs):
        current = self.session_state.get(key, value)
        if key is not None:
            self.session_state[key] = current
        return current

    def number_input(self, label, value=0.0, key=None, **kwargs):
        current = self.session_state.get(key, value)
        if key is not None:
            self.session_state[key] = current
        return current

    def button(self, *args, **kwargs):
        return False

    def color_picker(self, label, value="#3b82f6", key=None, **kwargs):
        current = self.session_state.get(key, value)
        if key is not None:
            self.session_state[key] = current
        return current


class RecordingStreamlit(FakeStreamlit):
    def __init__(self, widget_values=None):
        super().__init__()
        self.widget_values = dict(widget_values or {})
        self.json_payloads = []
        self.dataframe_payloads = []
        self.slider_inputs = []
        self.number_inputs = []
        self.text_inputs = []

    def slider(self, label, *args, key=None, **kwargs):
        current = self.widget_values.get(key, kwargs.get("value", 0.0))
        self.slider_inputs.append({"label": label, **kwargs})
        if key is not None:
            self.session_state[key] = current
        return current

    def number_input(self, label, value=0.0, key=None, **kwargs):
        current = self.widget_values.get(key, value)
        self.number_inputs.append({"label": label, "value": value, **kwargs})
        if key is not None:
            self.session_state[key] = current
        return current

    def text_input(self, label, value="", key=None, **kwargs):
        current = self.widget_values.get(key, value)
        self.text_inputs.append({"label": label, "value": value, **kwargs})
        if key is not None:
            self.session_state[key] = current
        return current

    def json(self, payload, *args, **kwargs):
        self.json_payloads.append(payload)

    def dataframe(self, payload, *args, **kwargs):
        self.dataframe_payloads.append(payload)


class TestDashboardPanels:
    def test_render_groups_detects_changes_applied_before_rerun(self):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        callback_calls = []
        registry = ControlRegistry()
        registry.register(
            "Gain",
            kind="slider",
            key="gain",
            group="Main",
            min_value=0.0,
            max_value=1.0,
            step=0.1,
            default=0.5,
            callback=lambda key, value: callback_calls.append((key, value)),
        )
        config = types.SimpleNamespace(
            layout="stacked",
            columns_per_row=1,
            registry=registry,
            audit=audit,
            on_change=None,
        )
        ctx = make_security_context("Admin", {"can_edit_controls": True})
        fake_st = RecordingStreamlit(widget_values={"gain": 0.5})

        dashboard_panels.render_groups(fake_st, registry.iter_groups(), ctx, config)
        fake_st.session_state["gain"] = 0.8
        fake_st.widget_values["gain"] = 0.8
        dashboard_panels.render_groups(fake_st, registry.iter_groups(), ctx, config)

        assert callback_calls == [("gain", 0.8)]
        assert [event["type"] for event in audit.all_events()] == ["control_change"]
        assert audit.all_events()[0]["old"] == 0.5
        assert audit.all_events()[0]["new"] == 0.8

    def test_render_groups_rechecks_control_permission_before_processing_change(self):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        callback_calls = []
        global_calls = []
        registry = ControlRegistry()
        registry.register(
            "Governed Gain",
            kind="slider",
            key="gain",
            group="Main",
            permission="can_manage_governance",
            min_value=0.0,
            max_value=1.0,
            step=0.1,
            default=0.5,
            callback=lambda key, value: callback_calls.append((key, value)),
        )
        config = types.SimpleNamespace(
            layout="stacked",
            columns_per_row=1,
            registry=registry,
            audit=audit,
            on_change=lambda key, old, new: global_calls.append((key, old, new)),
        )
        denied_ctx = make_security_context(
            "Operator",
            {"can_edit_controls": True, "can_manage_governance": False},
        )
        fake_st = RecordingStreamlit(
            widget_values={"_radt_read_only_control__gain": 0.8}
        )
        fake_st.session_state["gain"] = 0.6

        dashboard_panels.render_groups(
            fake_st,
            registry.iter_groups(),
            denied_ctx,
            config,
        )

        assert callback_calls == []
        assert global_calls == []
        assert audit.all_events() == []
        assert registry.is_user_set("gain", fake_st.session_state) is False
        assert fake_st.session_state["gain"] == 0.6
        assert fake_st.slider_inputs[0]["disabled"] is True

        fake_st.session_state["gain"] = 0.9
        fake_st.widget_values["_radt_read_only_control__gain"] = 0.9
        dashboard_panels.render_groups(
            fake_st,
            registry.iter_groups(),
            denied_ctx,
            config,
        )

        assert fake_st.session_state["gain"] == 0.6
        assert callback_calls == []
        assert global_calls == []
        assert audit.all_events() == []

        allowed_ctx = make_security_context(
            "Admin",
            {"can_manage_governance": True},
        )
        fake_st.widget_values["gain"] = 0.8
        dashboard_panels.render_groups(
            fake_st,
            registry.iter_groups(),
            allowed_ctx,
            config,
        )

        assert callback_calls == [("gain", 0.8)]
        assert global_calls == [("gain", 0.6, 0.8)]
        assert [event["type"] for event in audit.all_events()] == ["control_change"]

    def test_sensitive_text_controls_use_password_input_and_redacted_audit(self):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        registry = ControlRegistry()
        registry.register(
            "Session Credential",
            kind="text",
            key="credential",
            default="first-secret",
            sensitive=True,
        )
        config = types.SimpleNamespace(
            layout="stacked",
            columns_per_row=1,
            registry=registry,
            audit=audit,
            on_change=None,
        )
        ctx = make_security_context("Admin", {"can_edit_controls": True})
        fake_st = RecordingStreamlit(widget_values={"credential": "first-secret"})

        dashboard_panels.render_groups(fake_st, registry.iter_groups(), ctx, config)
        fake_st.session_state["credential"] = "second-secret"
        fake_st.widget_values["credential"] = "second-secret"
        dashboard_panels.render_groups(fake_st, registry.iter_groups(), ctx, config)

        assert [item["type"] for item in fake_st.text_inputs] == ["password", "password"]
        events = audit.all_events()
        assert len(events) == 1
        assert events[0]["old"] == "<redacted-secret>"
        assert events[0]["new"] == "<redacted-secret>"

    def test_render_groups_surfaces_callback_errors_and_logs_audit(self, tmp_path):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        registry = ControlRegistry()
        control_path = tmp_path / "control-secret.txt"
        global_path = tmp_path / "global-secret.txt"

        def control_callback(_key, _value):
            raise RuntimeError(f"control exploded at {control_path}")

        def global_callback(_key, _old_value, _new_value):
            raise ValueError(f"global exploded at {global_path}")

        registry.register(
            "Gain",
            kind="slider",
            key="gain",
            group="Main",
            min_value=0.0,
            max_value=1.0,
            step=0.1,
            default=0.5,
            callback=control_callback,
        )
        config = types.SimpleNamespace(
            layout="stacked",
            columns_per_row=1,
            registry=registry,
            audit=audit,
            on_change=global_callback,
        )
        ctx = make_security_context("Admin", {"can_edit_controls": True})
        fake_st = RecordingStreamlit(widget_values={"gain": 0.8})

        dashboard_panels.render_groups(fake_st, registry.iter_groups(), ctx, config)

        events = audit.all_events()
        assert [event["type"] for event in events] == ["control_change", "callback_error", "callback_error"]
        assert events[0]["key"] == "gain"
        assert [event["detail"] for event in events[1:]] == [
            "RuntimeError. " + diagnostic_text("RADT-CALLBACK"),
            "ValueError. " + diagnostic_text("RADT-CALLBACK"),
        ]
        assert fake_st.messages["error"] == [
            "Callback error on gain: RuntimeError. " + diagnostic_text("RADT-CALLBACK"),
            "Global on_change error on gain: ValueError. " + diagnostic_text("RADT-CALLBACK"),
        ]
        assert str(tmp_path) not in "\n".join(fake_st.messages["error"])
        assert str(tmp_path) not in "\n".join(event["detail"] for event in events[1:])
        assert registry.is_user_set("gain", fake_st.session_state) is True

    def test_render_audit_panel_uses_json_when_pandas_absent(self, monkeypatch):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        audit.log_control_change("temperature", 0.7, 0.9, role="Admin")
        fake_st = RecordingStreamlit()
        monkeypatch.setattr(dashboard_panels, "PANDAS_AVAILABLE", False)

        dashboard_panels.render_audit_panel(fake_st, audit)

        assert any(
            isinstance(payload, list) and payload and payload[0]["type"] == "control_change"
            for payload in fake_st.json_payloads
        )
        assert fake_st.dataframe_payloads == []

    def test_render_audit_panel_keeps_malformed_events_visible(self, monkeypatch):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        audit._events.append({"key": "legacy", "detail": "missing event type"})
        audit._events.append("legacy raw event")
        audit.log_control_change("temperature", 0.7, 0.9, role="Admin")
        fake_st = RecordingStreamlit()
        monkeypatch.setattr(dashboard_panels, "PANDAS_AVAILABLE", False)

        dashboard_panels.render_audit_panel(fake_st, audit)

        assert "malformed" in fake_st.session_state["_radt_audit_types"]
        assert any(
            isinstance(payload, list)
            and any(
                isinstance(event, dict)
                and event.get("type") == "malformed"
                and event.get("detail") == "missing event type"
                and event.get("malformed") is True
                and "schema_version" not in event
                for event in payload
            )
            for payload in fake_st.json_payloads
        )
        assert any(
            isinstance(payload, list)
            and any(
                isinstance(event, dict)
                and event.get("type") == "malformed"
                and event.get("detail") == "legacy raw event"
                and event.get("malformed") is True
                and "schema_version" not in event
                for event in payload
            )
            for payload in fake_st.json_payloads
        )

    def test_render_audit_panel_rechecks_clear_permission_server_side(self, monkeypatch):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")

        class ForgedButtonStreamlit(RecordingStreamlit):
            def __init__(self):
                super().__init__()
                self.button_calls = []
                self.rerun_calls = 0

            def button(self, _label, *, key=None, disabled=False, **_kwargs):
                self.button_calls.append({"key": key, "disabled": disabled})
                return key == "_radt_audit_clear_btn"

            def rerun(self, *args, **kwargs):
                self.rerun_calls += 1

        audit = AuditLog()
        audit.log_control_change("temperature", 0.7, 0.9, role="Admin")
        fake_st = ForgedButtonStreamlit()
        monkeypatch.setattr(dashboard_panels, "PANDAS_AVAILABLE", False)

        denied_ctx = make_security_context(
            "Viewer",
            {"can_manage_audit": False, "can_view_audit": True},
        )
        dashboard_panels.render_audit_panel(fake_st, audit, denied_ctx)

        assert len(audit.all_events()) == 1
        assert fake_st.rerun_calls == 0
        assert fake_st.button_calls[-1] == {
            "key": "_radt_audit_clear_btn",
            "disabled": True,
        }

        allowed_ctx = make_security_context("Admin", {"can_manage_audit": True})
        dashboard_panels.render_audit_panel(fake_st, audit, allowed_ctx)

        assert audit.all_events() == []
        assert fake_st.rerun_calls == 1
        assert fake_st.button_calls[-1] == {
            "key": "_radt_audit_clear_btn",
            "disabled": False,
        }

    def test_render_groups_keeps_integer_number_controls_integer_typed(self):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        registry = ControlRegistry()
        registry.register(
            "Max Tokens",
            kind="number",
            key="max_tokens",
            group="Main",
            default=256,
            min_value=32,
            max_value=4096,
            step=1,
        )
        config = types.SimpleNamespace(
            layout="stacked",
            columns_per_row=1,
            registry=registry,
            audit=audit,
            on_change=None,
        )
        ctx = make_security_context("Admin", {"can_edit_controls": True})
        fake_st = RecordingStreamlit()

        dashboard_panels.render_groups(fake_st, registry.iter_groups(), ctx, config)

        assert fake_st.number_inputs == [
            {
                "label": "Max Tokens",
                "value": 256,
                "min_value": 32,
                "max_value": 4096,
                "step": 1,
                "disabled": False,
                "help": None,
            }
        ]

    def test_render_groups_avoids_slider_default_kwarg_when_session_value_exists(self):
        dashboard_panels = importlib.import_module("role_aware_dashboard_toolkit.dashboard_panels")
        audit = AuditLog()
        registry = ControlRegistry()
        registry.register(
            "Temperature",
            kind="slider",
            key="temperature",
            group="Main",
            default=0.7,
            min_value=0.0,
            max_value=2.0,
            step=0.05,
        )
        config = types.SimpleNamespace(
            layout="stacked",
            columns_per_row=1,
            registry=registry,
            audit=audit,
            on_change=None,
        )
        ctx = make_security_context("Admin", {"can_edit_controls": True})
        fake_st = RecordingStreamlit()
        fake_st.session_state["temperature"] = 0.7

        dashboard_panels.render_groups(fake_st, registry.iter_groups(), ctx, config)

        assert fake_st.slider_inputs == [
            {
                "label": "Temperature",
                "min_value": 0.0,
                "max_value": 2.0,
                "step": 0.05,
                "disabled": False,
                "help": None,
            }
        ]


class TestDashboardSmoke:
    def test_sidebar_detects_role_and_freeze_changes_applied_before_rerun(self):
        fake_st = FakeStreamlit()
        config = DashboardConfig()

        render_sidebar(fake_st, config)
        fake_st.session_state["_radt_role"] = "Viewer"
        fake_st.session_state["_radt_writable"] = False
        render_sidebar(fake_st, config)

        events = config.audit.all_events()
        assert [event["type"] for event in events] == ["role_switch", "freeze_toggle"]
        assert events[0]["old"] == "Admin"
        assert events[0]["new"] == "Viewer"
        assert events[1]["new"] is False

    @pytest.mark.parametrize(
        ("auth_value", "classification"),
        [
            ("", "EmptyRole"),
            ("   ", "EmptyRole"),
            ("Missing", "UnknownRole"),
            (None, "InvalidRoleType"),
            (42, "InvalidRoleType"),
        ],
    )
    def test_sidebar_auth_hook_invalid_results_fail_closed(
        self,
        auth_value,
        classification,
    ):
        class TrackingStreamlit(FakeStreamlit):
            def __init__(self):
                super().__init__()
                self.role_selectbox_calls = 0

            def selectbox(self, label, *args, **kwargs):
                if label == "Role":
                    self.role_selectbox_calls += 1
                return super().selectbox(label, *args, **kwargs)

        fake_st = TrackingStreamlit()
        fake_st.session_state["_radt_role"] = "Admin"
        fake_st.session_state["_radt_writable"] = True
        config = DashboardConfig(auth_hook=lambda value=auth_value: value)

        result = render_sidebar(fake_st, config)

        assert result.ctx.role == "Unauthenticated"
        assert result.ctx.perms == {}
        assert result.ctx.controls_writable is False
        assert result.plugin_errors == []
        assert fake_st.session_state["_radt_role"] == "Unauthenticated"
        assert fake_st.session_state["_radt_writable"] is False
        assert fake_st.role_selectbox_calls == 0
        assert fake_st.messages["error"] == [
            f"Authentication failed ({classification}): "
            + (
                "auth hook returned an empty role."
                if classification == "EmptyRole"
                else "auth hook returned an unrecognized role."
                if classification == "UnknownRole"
                else "auth hook must return a role name string."
            )
            + " " + diagnostic_text("RADT-AUTH")
        ]

    def test_sidebar_auth_hook_exception_fails_closed_without_leaking_details(self):
        def fail_auth():
            raise RuntimeError("secret identity-provider detail")

        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_role"] = "Admin"
        fake_st.session_state["_radt_writable"] = True
        config = DashboardConfig(auth_hook=fail_auth)

        result = render_sidebar(fake_st, config)

        assert result.ctx == SecurityContext(
            role="Unauthenticated",
            perms={},
            controls_writable=False,
        )
        assert fake_st.messages["error"] == [
            "Authentication failed (RuntimeError): auth hook raised an exception. "
            + diagnostic_text("RADT-AUTH")
        ]
        assert "secret identity-provider detail" not in fake_st.messages["error"][0]

    def test_sidebar_valid_auth_role_stays_locked(self):
        fake_st = FakeStreamlit()
        config = DashboardConfig(auth_hook=lambda: "Auditor")

        result = render_sidebar(fake_st, config)

        assert result.ctx.role == "Auditor"
        assert result.ctx.perms == BUILTIN_ROLES["Auditor"].perms
        assert fake_st.session_state["_radt_role"] == "Auditor"
        assert "Role locked by auth: Auditor" in fake_st.messages["caption"]

    def test_sidebar_rechecks_profile_permissions_after_forged_button_clicks(
        self,
        monkeypatch,
    ):
        sidebar_module = importlib.import_module("role_aware_dashboard_toolkit.sidebar")

        class ForgedButtonStreamlit(FakeStreamlit):
            def __init__(self):
                super().__init__()
                self.button_calls = []

            def button(self, _label, *, key=None, disabled=False, **_kwargs):
                self.button_calls.append({"key": key, "disabled": disabled})
                return key in {
                    "_radt_profile_save",
                    "_radt_profile_load",
                    "_radt_profile_delete",
                }

        mutation_calls = []
        monkeypatch.setattr(
            sidebar_module,
            "list_profiles",
            lambda *_args, **_kwargs: ["existing"],
        )
        monkeypatch.setattr(
            sidebar_module,
            "load_profile_data",
            lambda *_args, **_kwargs: {},
        )
        monkeypatch.setattr(
            sidebar_module,
            "save_profile",
            lambda *_args, **_kwargs: mutation_calls.append("save"),
        )
        monkeypatch.setattr(
            sidebar_module,
            "load_profile",
            lambda *_args, **_kwargs: mutation_calls.append("load"),
        )
        monkeypatch.setattr(
            sidebar_module,
            "delete_profile",
            lambda *_args, **_kwargs: mutation_calls.append("delete") or True,
        )
        fake_st = ForgedButtonStreamlit()
        fake_st.session_state.update(
            {
                "_radt_profile_choice": "existing",
                "_radt_profile_name": "forged",
            }
        )
        config = DashboardConfig()
        denied_ctx = make_security_context(
            "Viewer",
            {"can_save_profiles": False, "can_load_profiles": False},
        )

        sidebar_module._render_profiles(
            fake_st,
            config,
            denied_ctx,
            get_role_names(),
        )

        assert mutation_calls == []
        assert fake_st.button_calls == [
            {"key": "_radt_profile_save", "disabled": True},
            {"key": "_radt_profile_load", "disabled": True},
            {"key": "_radt_profile_delete", "disabled": True},
        ]
        assert config.audit.all_events() == []

    @pytest.mark.parametrize(
        ("writable", "can_manage_governance", "allowed"),
        [(False, True, False), (True, False, False), (True, True, True)],
    )
    def test_sidebar_profile_load_preflights_all_control_permissions(
        self, writable, can_manage_governance, allowed,
    ):
        class ProfileLoadStreamlit(FakeStreamlit):
            def button(self, _label, *, key=None, **_kwargs):
                # Return a click even when the UI marks the button disabled.
                return key == "_radt_profile_load"

        reg = ControlRegistry()
        reg.register("Mode", kind="text", key="mode", default="safe")
        reg.register(
            "Governance lock", kind="toggle", key="governance_lock",
            default=False, permission="can_manage_governance",
        )
        reg.register("API key", kind="text", key="api_key", default="live-secret")
        store = InMemoryProfileStore()
        store.save({
            "profile_id": "governed", "role": "Admin",
            "values": {
                "mode": "fast", "governance_lock": True,
                "api_key": "stored-secret", "obsolete": "ignored",
            },
        })
        config = DashboardConfig(registry=reg, profile_store=store)
        fake_st = ProfileLoadStreamlit()
        fake_st.session_state.update({
            "mode": "safe", "governance_lock": False, "api_key": "live-secret",
            "_radt_role": "Operator", "_radt_profile_choice": "governed",
        })
        ctx = make_security_context(
            "Operator",
            {
                "can_load_profiles": True, "can_edit_controls": True,
                "can_manage_governance": can_manage_governance,
            },
            controls_writable=writable,
        )

        importlib.import_module("role_aware_dashboard_toolkit.sidebar")._render_profiles(
            fake_st, config, ctx, get_role_names(),
        )

        assert fake_st.session_state["mode"] == ("fast" if allowed else "safe")
        assert fake_st.session_state["governance_lock"] is allowed
        assert fake_st.session_state["api_key"] == "live-secret"
        assert "obsolete" not in fake_st.session_state
        events = config.audit.all_events()
        if allowed:
            assert [event["type"] for event in events] == ["profile_load"]
        else:
            assert events == []
            assert fake_st.session_state["_radt_role"] == "Operator"
            assert fake_st.messages["toast"] == []

    def test_sidebar_rejects_audit_writer_path_outside_configured_root(self, tmp_path):
        audit_root = tmp_path / "audit"
        outside = tmp_path / "outside.jsonl"
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(outside)
        config = DashboardConfig(audit_dir=str(audit_root))

        render_sidebar(fake_st, config)

        assert config.audit.writer_status()["writer_active"] is False
        assert fake_st.messages["error"] == ["Audit file path must stay within configured audit directory. " + diagnostic_text("RADT-AUDIT-IO")]


    def test_sidebar_audit_writer_persists_inside_configured_root(self, tmp_path):
        audit_root = tmp_path / "audit"
        audit_path = audit_root / "events.jsonl"
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(audit_path)
        config = DashboardConfig(audit_dir=str(audit_root))

        render_sidebar(fake_st, config)
        config.audit.log("test_event", role="Admin")
        config.audit.stop_writer()

        events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        assert [event["type"] for event in events] == ["test_event"]


    def test_sidebar_surfaces_one_redacted_startup_error_and_retries(
        self, tmp_path, monkeypatch
    ):
        audit_root = tmp_path / "audit"
        audit_path = audit_root / "private" / "events.jsonl"
        audit = AuditLog()
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(audit_path)
        config = DashboardConfig(audit=audit, audit_dir=str(audit_root))
        startup_error = OSError(f"cannot open {audit_path}")

        def fail_store(_path):
            raise startup_error

        with monkeypatch.context() as patch:
            patch.setattr(audit_module, "FileAuditStore", fail_store)
            render_sidebar(fake_st, config)

        failed_status = audit.writer_status()
        assert failed_status["writer_active"] is False
        assert failed_status["writer_path"] == ""
        assert failed_status["writer_error_count"] == 1
        assert audit_module._get_writer_startup_error(startup_error) == failed_status[
            "last_writer_error"
        ]
        errors = fake_st.messages["error"]
        assert len(errors) == 1
        displayed_error = errors[0]
        assert displayed_error.startswith("Audit writer error (OSError): ")
        assert diagnostic_text("RADT-AUDIT-IO") in displayed_error
        assert str(audit_path) not in displayed_error

        audit.log("memory_only_after_sidebar_start_failure")
        assert [event["type"] for event in audit.all_events()] == [
            "memory_only_after_sidebar_start_failure"
        ]

        render_sidebar(fake_st, config)
        audit.log("retry_event")
        audit.stop_writer()

        persisted = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        assert [event["type"] for event in persisted] == ["retry_event"]
        assert fake_st.messages["error"] == [displayed_error]
        retry_status = audit.writer_status()
        assert retry_status["writer_error_count"] == 0
        assert retry_status["last_writer_error"] == {}

    def test_sidebar_handles_unknown_start_liveness_without_status_probe(
        self, tmp_path, monkeypatch, caplog
    ):
        audit_root = tmp_path / "audit"
        audit_path = audit_root / "private" / "events.jsonl"
        start_error = RuntimeError(f"thread start failed at {audit_path}")
        probe_error = OSError(f"liveness probe failed at {audit_path}")

        class _UnknownLivenessThread:
            def __init__(self):
                self.alive = True
                self.raise_liveness = True
                self.join_timeouts = []

            def start(self):
                raise start_error

            def is_alive(self):
                if self.raise_liveness:
                    raise probe_error
                return self.alive

            def join(self, timeout=None):
                self.join_timeouts.append(timeout)

        writer_thread = _UnknownLivenessThread()
        audit = AuditLog()
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(audit_path)
        config = DashboardConfig(audit=audit, audit_dir=str(audit_root))

        with monkeypatch.context() as patch:
            patch.setattr(
                audit_module.threading,
                "Thread",
                lambda **_kwargs: writer_thread,
            )
            with caplog.at_level("WARNING", logger=audit_module.__name__):
                render_sidebar(fake_st, config)

        assert audit._writer_thread is writer_thread
        assert audit._writer_queue is not None
        assert audit._writer_store is not None
        assert audit._writer_path == str(audit_path)
        assert audit._writer_stop.is_set()
        errors = fake_st.messages["error"]
        assert len(errors) == 1
        assert "Audit writer error (RuntimeError)" in errors[0]
        assert diagnostic_text("RADT-AUDIT-IO") in errors[0]
        assert str(audit_path) not in errors[0]
        audit.log("memory_only_while_start_state_is_unknown")
        assert audit._writer_queue.qsize() == 0
        assert str(audit_path) not in "\n".join(record.getMessage() for record in caplog.records)

        writer_thread.raise_liveness = False
        writer_thread.alive = False
        audit.stop_writer()



    def test_sidebar_read_only_role_cannot_start_audit_writer(self, tmp_path):
        audit_root = tmp_path / "audit"
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(audit_root / "events.jsonl")
        config = DashboardConfig(
            audit_dir=str(audit_root),
            custom_roles={
                "Locked": RoleDef(
                    name="Locked",
                    perms={"can_edit_controls": False, "can_view_audit": True},
                )
            },
            auth_hook=lambda: "Locked",
        )

        render_sidebar(fake_st, config)

        assert config.audit.writer_status()["writer_active"] is False

    def test_sidebar_read_only_role_does_not_stop_active_audit_writer(self, tmp_path):
        audit_root = tmp_path / "audit"
        audit_path = audit_root / "events.jsonl"
        audit = AuditLog()
        audit.start_writer(str(audit_path))
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = False
        config = DashboardConfig(
            audit=audit,
            audit_dir=str(audit_root),
            custom_roles={
                "Locked": RoleDef(
                    name="Locked",
                    perms={"can_edit_controls": False, "can_view_audit": True},
                )
            },
            auth_hook=lambda: "Locked",
        )

        try:
            render_sidebar(fake_st, config)
            assert audit.writer_status()["writer_active"] is True
            audit.log("writer_survived_read_only_render", role="Locked")
        finally:
            audit.stop_writer()

        events = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
        ]
        assert [event["type"] for event in events] == [
            "role_switch",
            "writer_survived_read_only_render",
        ]


    def test_sidebar_surfaces_background_audit_writer_errors(self):
        audit = AuditLog()
        audit._writer_error_count = 1
        audit._last_writer_error = {
            "error_type": "OSError",
            "exception_type": "OSError",
            "message": "cannot write <redacted-local-path>",
        }
        fake_st = FakeStreamlit()
        config = DashboardConfig(audit=audit)

        render_sidebar(fake_st, config)

        assert fake_st.messages["error"] == [
            "Audit writer error (OSError): " + diagnostic_text("RADT-AUDIT-IO")
        ]


    def test_sidebar_surfaces_classified_bounded_audit_writer_shutdown_timeout(
        self, tmp_path
    ):
        class _StuckThread:
            def __init__(self):
                self.alive = True
                self.join_timeouts = []

            def is_alive(self):
                return self.alive

            def join(self, timeout=None):
                self.join_timeouts.append(timeout)

        audit_root = tmp_path / "audit"
        writer_path = audit_root / "private" / "events.jsonl"
        audit = AuditLog()
        writer_thread = _StuckThread()
        audit._writer_thread = writer_thread
        audit._writer_queue = queue.Queue()
        audit._writer_store = object()
        audit._writer_path = str(writer_path)
        fake_st = FakeStreamlit()
        config = DashboardConfig(audit=audit, audit_dir=str(audit_root))

        render_sidebar(fake_st, config)

        errors = fake_st.messages["error"]
        assert errors == [
            "Audit writer error (TimeoutError): " + diagnostic_text("RADT-AUDIT-IO")
        ]
        assert str(writer_path) not in "\n".join(errors)
        status = audit.writer_status()
        assert status["writer_active"] is True
        assert status["writer_error_count"] == 1
        assert audit._writer_thread is writer_thread

        writer_thread.alive = False
        audit.stop_writer()

    @pytest.mark.parametrize("error_type", [RuntimeError, TimeoutError])
    def test_sidebar_does_not_swallow_unexpected_audit_writer_shutdown_errors(
        self, monkeypatch, error_type
    ):
        audit = AuditLog()

        def fail_shutdown():
            raise error_type("unexpected writer failure")

        monkeypatch.setattr(audit, "stop_writer", fail_shutdown)
        fake_st = FakeStreamlit()
        config = DashboardConfig(audit=audit)
        with pytest.raises(error_type, match="unexpected writer failure"):
            render_sidebar(fake_st, config)

    @pytest.mark.parametrize("error_type", [RuntimeError, TimeoutError])
    def test_sidebar_does_not_swallow_unmarked_start_writer_errors(
        self, tmp_path, monkeypatch, error_type
    ):
        audit_root = tmp_path / "audit"
        audit_path = audit_root / "events.jsonl"
        audit = AuditLog()

        def fail_start(_path):
            raise error_type("unexpected start_writer failure")

        monkeypatch.setattr(audit, "start_writer", fail_start)
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(audit_path)
        config = DashboardConfig(audit=audit, audit_dir=str(audit_root))

        with pytest.raises(error_type, match="unexpected start_writer failure"):
            render_sidebar(fake_st, config)

    def test_sidebar_does_not_trust_forged_startup_error_marker(
        self, tmp_path, monkeypatch
    ):
        audit_root = tmp_path / "audit"
        audit_path = audit_root / "events.jsonl"
        error = RuntimeError("forged startup classification")
        setattr(
            error,
            audit_module._WRITER_STARTUP_ERROR_ATTR,
            {
                "error_type": "RuntimeError",
                "exception_type": "RuntimeError",
                "message": "forged diagnostic",
            },
        )

        audit = AuditLog()

        def fail_start(_path):
            raise error

        monkeypatch.setattr(audit, "start_writer", fail_start)
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(audit_path)
        config = DashboardConfig(audit=audit, audit_dir=str(audit_root))

        with pytest.raises(RuntimeError) as caught:
            render_sidebar(fake_st, config)

        assert caught.value is error



    @pytest.mark.parametrize("error_type", [RuntimeError, TimeoutError])
    def test_sidebar_does_not_swallow_prior_writer_shutdown_errors_from_start(
        self, tmp_path, error_type
    ):
        class _JoinFailureThread:
            def is_alive(self):
                return False

            def join(self, timeout=None):
                raise error_type("unexpected prior writer shutdown failure")

        audit_root = tmp_path / "audit"
        audit = AuditLog()
        audit._writer_thread = _JoinFailureThread()
        audit._writer_queue = queue.Queue()
        audit._writer_store = object()
        audit._writer_path = str(audit_root / "old.jsonl")
        fake_st = FakeStreamlit()
        fake_st.session_state["_radt_audit_writer"] = True
        fake_st.session_state["_radt_audit_path"] = str(audit_root / "new.jsonl")
        config = DashboardConfig(audit=audit, audit_dir=str(audit_root))

        with pytest.raises(
            error_type, match="unexpected prior writer shutdown failure"
        ):
            render_sidebar(fake_st, config)


    def test_sidebar_does_not_swallow_writer_status_errors(self, monkeypatch):
        audit = AuditLog()

        def fail_status():
            raise RuntimeError("unexpected writer_status failure")

        monkeypatch.setattr(audit, "writer_status", fail_status)
        fake_st = FakeStreamlit()
        config = DashboardConfig(audit=audit)

        with pytest.raises(RuntimeError, match="unexpected writer_status failure"):
            render_sidebar(fake_st, config)




    def test_render_attempts_failed_plugin_setup_once_per_cycle(self, monkeypatch):
        calls = []

        def setup(_context):
            calls.append("setup")
            raise RuntimeError("setup failed")

        registry = PluginRegistry()
        registry.register(
            DashboardPlugin(
                name="setup-once",
                capabilities=["setup", "sidebar", "panel"],
                setup=setup,
                render_sidebar=lambda _context: calls.append("sidebar"),
                render_panel=lambda _context: calls.append("panel"),
            )
        )
        fake_st = FakeStreamlit()
        fake_streamlit_module = types.SimpleNamespace()
        monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit_module)
        dashboard_mod = importlib.import_module("role_aware_dashboard_toolkit.dashboard")
        config = dashboard_mod.DashboardConfig(
            title="Setup Failure Test",
            plugins=registry,
        )
        monkeypatch.setattr(dashboard_mod, "st", fake_st)

        dashboard_mod.render(config)

        assert calls == ["setup"]
        assert fake_st.messages["warning"] == [
            "Plugin setup error: setup-once (RuntimeError): " + diagnostic_text("RADT-PLUGIN")
        ]

    def test_render_surfaces_plugin_discovery_errors(self, monkeypatch):
        fake_st = FakeStreamlit()
        fake_streamlit_module = types.SimpleNamespace()
        monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit_module)
        dashboard_mod = importlib.import_module("role_aware_dashboard_toolkit.dashboard")
        DashboardConfig = dashboard_mod.DashboardConfig

        class BrokenEntryPoint:
            name = "broken_ep"

            def load(self):
                raise RuntimeError("entry point exploded")

        monkeypatch.setattr(
            "role_aware_dashboard_toolkit.plugins._iter_entry_points",
            lambda group: [BrokenEntryPoint()] if group == "role_aware_dashboard_toolkit.panels" else [],
        )
        registry = PluginRegistry()
        with pytest.warns(RuntimeWarning, match="Role-Aware Dashboard Toolkit plugin discovery skipped role_aware_dashboard_toolkit.panels:broken_ep"):
            assert registry.discover(trusted_entry_points=["role_aware_dashboard_toolkit.panels:broken_ep"]) == []

        config = DashboardConfig(title="Smoke Test", plugins=registry)
        monkeypatch.setattr(dashboard_mod, "st", fake_st)

        dashboard_mod.render(config)

        assert "Plugin discovery error: broken_ep (RuntimeError): " + diagnostic_text("RADT-PLUGIN") in fake_st.messages["warning"]

    def test_render_sanitizes_preexisting_session_values(self, monkeypatch):
        fake_st = FakeStreamlit()
        fake_streamlit_module = types.SimpleNamespace()
        monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit_module)
        dashboard_mod = importlib.import_module("role_aware_dashboard_toolkit.dashboard")
        DashboardConfig = dashboard_mod.DashboardConfig
        fake_st.session_state["gain"] = 999
        fake_st.session_state["mode"] = "broken"

        reg = ControlRegistry()
        reg.register("Gain", kind="slider", key="gain", min_value=0.0, max_value=1.0, default=0.5)
        reg.register("Mode", kind="select", key="mode", options=["fast", "safe"], default="safe")

        config = DashboardConfig(
            title="Smoke Test",
            registry=reg,
            custom_roles={
                "Locked": RoleDef(
                    name="Locked",
                    perms={
                        "can_edit_controls": False,
                        "can_view_audit": False,
                        "can_save_profiles": False,
                        "can_load_profiles": False,
                        "can_view_metrics": False,
                    },
                )
            },
            auth_hook=lambda: "Locked",
            observability=ObservabilityConfig(enabled=True, telemetry_hook=lambda: {"metrics": {"latency_ms": 10.0}}),
        )

        monkeypatch.setattr(dashboard_mod, "st", fake_st)
        ctx = dashboard_mod.render(config)
        assert ctx.role == "Locked"
        assert fake_st.session_state["gain"] == 1.0
        assert fake_st.session_state["mode"] == "safe"
        assert "_radt_observability_history" not in fake_st.session_state
        assert fake_st.messages["info"] == []


class TestPackageBoundary:
    def test_example_app_is_not_importable_package_content(self):
        import importlib.util
        spec = importlib.util.find_spec("role_aware_dashboard_toolkit.example_app")
        assert spec is None

    def test_examples_demo_exists_and_compiles(self, tmp_path):
        import py_compile
        from pathlib import Path
        demo = Path(__file__).resolve().parents[1] / "examples" / "core_library.py"
        assert demo.is_file()
        py_compile.compile(str(demo), cfile=str(tmp_path / "core_library.pyc"), doraise=True)
