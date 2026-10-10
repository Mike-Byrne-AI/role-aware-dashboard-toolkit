from pathlib import Path

import pytest

import role_aware_dashboard_toolkit as radt
import role_aware_dashboard_toolkit.decision_store as decision_store
import role_aware_dashboard_toolkit.decisions as decisions
import role_aware_dashboard_toolkit.store_diagnostics as store_diagnostics_module
import role_aware_dashboard_toolkit.team_ops as team_ops
import role_aware_dashboard_toolkit.team_store as team_store
from role_aware_dashboard_toolkit.decisions import sync_decision_case
from role_aware_dashboard_toolkit.security import make_security_context
from role_aware_dashboard_toolkit.validators import validate_decision_record


REPO_ROOT = Path(__file__).resolve().parents[1]



def test_decision_case_composes_review_and_handoff_state():
    run = radt.build_run({"temperature": 0.7, "mode": "safe"}, run_id="run_decide", role="Operator")
    run = radt.append_checkpoint(run, {"temperature": 0.9, "mode": "safe"}, label="cp1", approval_state="proposed")
    checkpoint = run["checkpoints"][-1]

    decision = decisions.build_decision_case(run, checkpoint=checkpoint, actor="mike", role="Operator")
    assert decision["state"] == "proposed"
    assert validate_decision_record(decision)["ok"] is True

    assignment = team_ops.build_review_assignment(
        run["run_id"],
        checkpoint_id=checkpoint["checkpoint_id"],
        title="Review cp1",
        assignee="jane",
        assignee_role="Approver",
        assigned_by="mike",
        assigned_role="Operator",
        status="in_review",
    )
    updated = sync_decision_case(
        decision,
        run=run,
        checkpoint=checkpoint,
        assignments=[assignment],
        actor="mike",
        role="Operator",
    )
    assert updated["state"] == "in_review"
    assert updated["last_event_type"] == "review_started"

    signoff = team_ops.build_signoff_record(
        run["run_id"],
        "approved",
        checkpoint_id=checkpoint["checkpoint_id"],
        assignment_id=assignment["assignment_id"],
        actor="jane",
        role="Approver",
    )
    approved = sync_decision_case(
        updated,
        run=run,
        checkpoint=checkpoint,
        assignments=[assignment],
        signoffs=[signoff],
        actor="jane",
        role="Approver",
    )
    assert approved["state"] == "approved"
    assert approved["latest_signoff_decision"] == "approved"
    assert "handoff" in approved["allowed_actions"]

    handoff = team_ops.build_handoff_summary(
        run,
        handoff_to="night",
        handoff_role="Auditor",
        actor="jane",
        role="Approver",
        status="pending",
    )
    pending = sync_decision_case(
        approved,
        run=run,
        checkpoint=checkpoint,
        assignments=[assignment],
        signoffs=[signoff],
        handoffs=[handoff],
        actor="jane",
        role="Approver",
    )
    assert pending["state"] == "handoff_pending"
    assert pending["blockers"][0]["kind"] in {"handoff_pending", "open_assignments"}



def test_decision_store_round_trip_and_summary():
    run = radt.build_run({"mode": "safe"}, run_id="run_store", role="Operator")
    run = radt.append_checkpoint(run, {"mode": "fast"}, label="cp1", approval_state="approved")
    checkpoint = run["checkpoints"][-1]
    decision = decisions.build_decision_case_from_run(run, checkpoint=checkpoint)

    store = decision_store.InMemoryDecisionStore()
    decision_id = store.save(decision)
    loaded = store.load(decision_id)

    assert loaded is not None
    assert loaded["checkpoint_id"] == checkpoint["checkpoint_id"]
    assert store.list_by_run("run_store")[0]["decision_id"] == decision_id
    assert decisions.decision_summary(loaded)["state"] == loaded["state"]


def test_file_decision_store_records_corrupt_json_read_errors(tmp_path):
    store_dir = tmp_path / "decisions"
    store_dir.mkdir()
    (store_dir / "broken.json").write_text("{not json", encoding="utf-8")
    store = decision_store.FileDecisionStore(str(store_dir))

    assert store.list_ids() == []
    assert store.read_errors
    assert store.read_errors[0]["path"].endswith("broken.json")
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"

    store.clear_read_errors()
    assert store.read_errors == []


def test_file_decision_store_direct_load_records_corrupt_json_read_errors(tmp_path):
    store = decision_store.FileDecisionStore(str(tmp_path / "decisions"))
    decision = decisions.build_decision_case({"run_id": "run_corrupt", "checkpoints": [], "latest_controls": {}, "status": "active"})
    path = store.save(decision)
    decision_id = decision["decision_id"]
    Path(path).write_text("{not json", encoding="utf-8")

    assert store.load(decision_id) is None
    assert store.read_errors
    assert store.read_errors[0]["path"].endswith(Path(path).name)
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"



def test_decision_record_validation_catches_bad_state():
    decision = decisions.build_decision_case({"run_id": "run_bad", "checkpoints": [], "latest_controls": {}, "status": "active"})
    decision["state"] = "not_real"
    result = validate_decision_record(decision)
    assert result["ok"] is False
    assert any("Invalid decision state" in error for error in result["errors"])


class _FakeExpander:
    def __init__(self, st):
        self._st = st

    def __enter__(self):
        return self._st

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeStreamlit:
    def __init__(self, *, save=False):
        self.session_state = {"_radt_user_id": "tester"}
        self._save = save
        self.events = []

    def subheader(self, text):
        self.events.append(("subheader", str(text)))

    def caption(self, text):
        self.events.append(("caption", str(text)))

    def json(self, payload):
        self.events.append(("json", payload))

    def expander(self, label, expanded=False):
        self.events.append(("expander", str(label)))
        return _FakeExpander(self)

    def button(self, label, key=None):
        self.events.append(("button", str(label)))
        return self._save and "Save decision snapshot" in str(label)

    def toast(self, text):
        self.events.append(("toast", str(text)))

    def dataframe(self, payload, **kwargs):
        self.events.append(("dataframe", payload))


class _SpyDecisionStore(decision_store.InMemoryDecisionStore):
    def __init__(self):
        super().__init__()
        self.save_calls = 0

    def save(self, record):
        self.save_calls += 1
        return super().save(record)


class _DecisionPanelConfig:
    def __init__(self):
        self.decision_store = _SpyDecisionStore()
        self.team_store = team_store.InMemoryTeamStore()
        self.decision_title = "Decision Layer"


def test_decision_panel_previews_without_persisting_until_save_clicked():
    from role_aware_dashboard_toolkit.runbook_panels import _render_decision_panel

    config = _DecisionPanelConfig()
    run = radt.build_run({"mode": "safe"}, run_id="run_preview", role="Operator")
    run = radt.append_checkpoint(run, {"mode": "fast"}, label="cp1", approval_state="proposed")
    checkpoint = run["checkpoints"][-1]
    ctx = make_security_context(
        "Auditor",
        {
            "can_view_decisions": True,
            "can_view_team_ops": True,
            "can_manage_runs": True,
        },
    )
    st = _FakeStreamlit(save=False)

    _render_decision_panel(st, config, ctx, run, checkpoint)

    assert config.decision_store.save_calls == 0
    assert config.decision_store.list_by_run("run_preview") == []
    assert any("Rendering the panel does not persist state." in text for kind, text in st.events if kind == "caption")


def test_decision_preview_builder_returns_checkpoint_scoped_preview():
    from role_aware_dashboard_toolkit.runbook_panels_parts import build_decision_panel_preview

    config = _DecisionPanelConfig()
    run = radt.build_run({"mode": "safe"}, run_id="run_preview_builder", role="Operator")
    run = radt.append_checkpoint(run, {"mode": "fast"}, label="cp1", approval_state="proposed")
    checkpoint = run["checkpoints"][-1]

    preview = build_decision_panel_preview(config, run, checkpoint, actor="tester", role="Operator")
    assert preview is not None
    assert preview["run_id"] == "run_preview_builder"
    assert preview["checkpoint_id"] == checkpoint["checkpoint_id"]
    assert validate_decision_record(preview["decision"])["ok"] is True


def test_decision_panel_persists_only_after_explicit_save_click():
    from role_aware_dashboard_toolkit.runbook_panels import _render_decision_panel

    config = _DecisionPanelConfig()
    run = radt.build_run({"mode": "safe"}, run_id="run_save", role="Operator")
    run = radt.append_checkpoint(run, {"mode": "fast"}, label="cp1", approval_state="proposed")
    checkpoint = run["checkpoints"][-1]
    ctx = make_security_context(
        "Operator",
        {
            "can_view_decisions": True,
            "can_manage_decisions": True,
            "can_view_team_ops": True,
        },
    )
    st = _FakeStreamlit(save=True)

    _render_decision_panel(st, config, ctx, run, checkpoint)

    assert config.decision_store.save_calls == 1
    saved = config.decision_store.list_by_run("run_save")
    assert len(saved) == 1
    assert validate_decision_record(saved[0])["ok"] is True


def test_run_management_does_not_imply_decision_management():
    from role_aware_dashboard_toolkit.runbook_panels import _render_decision_panel

    config = _DecisionPanelConfig()
    run = radt.build_run({"mode": "safe"}, run_id="run_denied", role="Operator")
    run = radt.append_checkpoint(
        run,
        {"mode": "fast"},
        label="cp1",
        approval_state="proposed",
    )
    checkpoint = run["checkpoints"][-1]
    ctx = make_security_context("Custom", {"can_manage_runs": True})

    _render_decision_panel(_FakeStreamlit(save=True), config, ctx, run, checkpoint)

    assert config.decision_store.save_calls == 0


def test_file_decision_store_rejects_symlink_escape_records(tmp_path):
    store_dir = tmp_path / "decisions"
    store_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"decision_id": "escape", "run_id": "run"}', encoding="utf-8")
    link = store_dir / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    store = decision_store.FileDecisionStore(str(store_dir))
    assert store.list_ids() == []
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"
    assert "symlinked store record" in store.read_errors[0]["message"]


def test_atomic_write_text_record_surfaces_best_effort_cleanup_warning(monkeypatch, tmp_path):
    original_unlink = Path.unlink
    target = tmp_path / "records" / "decision.json"

    def fail_replace(src, dst):
        raise OSError(f"replace failed for {src} -> {dst}")

    def fail_unlink(self, *args, **kwargs):
        if str(self).endswith(".tmp"):
            raise OSError("unlink failed")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(store_diagnostics_module.os, "replace", fail_replace)
    monkeypatch.setattr(Path, "unlink", fail_unlink)

    with pytest.warns(RuntimeWarning, match="Best-effort store temp cleanup failed") as warning_records:
        with pytest.raises(OSError, match="replace failed"):
            store_diagnostics_module.atomic_write_text_record(target, "{}", root_dir=tmp_path)

    warning_text = str(warning_records[0].message)
    assert "OSError: replace failed" in warning_text
    assert "cleanup failure: OSError: unlink failed" in warning_text
    assert "records/" in warning_text
    assert str(tmp_path) not in warning_text


def test_shared_store_patterns_docs_lock_behavior_matrix():
    docs = (REPO_ROOT / "docs" / "shared_store_patterns.md").read_text(encoding="utf-8")
    for marker in [
        "## Diagnostics",
        "File-backed stores expose `read_errors`",
        "## Filesystem safety",
        "reject symlink and resolved-path escapes",
        "use hashed filenames to avoid normalized-id collisions",
        "resolve direct record reads through hashed filenames only",
        "## Store families",
        "| Profiles |",
        "| Operator memory |",
        "| Audit | append-only JSONL |",
        "In-memory variants use JSON-roundtrip copy semantics",
        "## Host responsibilities",
    ]:
        assert marker in docs
