import json
from pathlib import Path

import role_aware_dashboard_toolkit as radt
import role_aware_dashboard_toolkit.case_store as case_store
import role_aware_dashboard_toolkit.caseboard as caseboard
import role_aware_dashboard_toolkit.decision_store as decision_store
import role_aware_dashboard_toolkit.decisions as decisions
import role_aware_dashboard_toolkit.governance as governance_model
import role_aware_dashboard_toolkit.governance_store as governance_store
import role_aware_dashboard_toolkit.operator_memory as operator_memory
import role_aware_dashboard_toolkit.operator_memory_store as operator_memory_store
import role_aware_dashboard_toolkit.team_ops as team_ops
import role_aware_dashboard_toolkit.team_store as team_store
from role_aware_dashboard_toolkit.security import make_security_context
from role_aware_dashboard_toolkit.validators import validate_governance_record
import pytest


class FakeExpander:
    def __init__(self, st):
        self._st = st

    def __enter__(self):
        return self._st

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeStreamlit:
    def __init__(self, *, save=False):
        self.session_state = {"_radt_selected_case_id": "case_a", "_radt_user_id": "tester"}
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
        return FakeExpander(self)

    def button(self, label, key=None):
        self.events.append(("button", str(label)))
        return self._save and "Save governance snapshot" in str(label)

    def toast(self, text):
        self.events.append(("toast", str(text)))


class Config:
    def __init__(self):
        self.governance_store = governance_store.InMemoryGovernanceStore()
        self.case_store = case_store.InMemoryCaseStore()
        self.decision_store = decision_store.InMemoryDecisionStore()
        self.operator_memory_store = operator_memory_store.InMemoryOperatorMemoryStore()
        self.team_store = team_store.InMemoryTeamStore()
        self.governance_title = "Governance"


def _seed_case(config: Config):
    case_record = caseboard.build_case_record("Case A", case_id="case_a", linked_run_ids=["run_a"])
    config.case_store.save(case_record)
    run = radt.build_run({"mode": "safe"}, run_id="run_a", actor="tester", role="Operator")
    decision = decisions.build_decision_case(run, actor="tester", role="Operator")
    config.decision_store.save(decision)
    signoff = team_ops.build_signoff_record("run_a", "approved", actor="approver", role="Approver")
    config.team_store.save_signoff(signoff)
    incident = operator_memory.build_incident_record("run_a", "Latency spike", incident_id="incident_a")
    config.operator_memory_store.save_incident(incident)


def test_governance_record_validates_and_summarizes():
    case_record = caseboard.build_case_record("Case", linked_run_ids=["run_a"], linked_incident_ids=["incident_a"])
    run = radt.build_run({"mode": "safe"}, run_id="run_a", actor="tester", role="Operator")
    decision = decisions.build_decision_case(run, actor="tester", role="Operator")
    signoff = team_ops.build_signoff_record("run_a", "approved", actor="approver", role="Approver")
    incident = operator_memory.build_incident_record("run_a", "Latency spike", incident_id="incident_a")
    governance = governance_model.build_governance_record(case_record, decisions=[decision], signoffs=[signoff], incidents=[incident], actor="tester", role="Auditor")

    assert validate_governance_record(governance)["ok"] is True
    summary = governance_model.governance_summary(governance)
    assert summary["case_id"] == governance["case_id"]
    assert summary["state"] == governance["state"]
    assert summary["allowed_next_actions"] == governance["allowed_next_actions"]
    assert summary["summary_text"] == governance["summary_text"]
    assert "allowed_actions" not in governance
    assert "summary" not in governance


def test_file_governance_store_direct_load_records_corrupt_json_read_errors(tmp_path):
    store = governance_store.FileGovernanceStore(str(tmp_path / "governance"))
    case_record = caseboard.build_case_record("Case", case_id="case_a")
    record = governance_model.build_governance_record(case_record, governance_id="broken")
    path = store.save(record)
    Path(path).write_text("{not json", encoding="utf-8")

    assert store.load("broken") is None
    assert store.read_errors
    assert store.read_errors[0]["path"].endswith(Path(path).name)
    assert store.read_errors[0]["error_type"] == "JSONDecodeError"


def test_governance_panel_previews_without_saving_until_button_press():
    from role_aware_dashboard_toolkit.runbook_panels import _render_governance_panel

    config = Config()
    _seed_case(config)
    ctx = make_security_context("Auditor", {"can_view_governance": True, "can_manage_governance": False})
    st = FakeStreamlit(save=False)

    _render_governance_panel(st, config, ctx, runs=[])
    assert config.governance_store.list_records() == []
    assert any(kind == "caption" for kind, _ in st.events)


def test_governance_preview_builder_tracks_selected_case_links():
    from role_aware_dashboard_toolkit.runbook_panels_parts import build_governance_panel_preview

    config = Config()
    _seed_case(config)
    selected_case = config.case_store.list_cases()[0]

    preview = build_governance_panel_preview(config, selected_case, actor="tester", role="Auditor")
    assert preview is not None
    assert preview["selected_case_id"] == "case_a"
    assert validate_governance_record(preview["governance"])["ok"] is True
    assert preview["governance"]["case_id"] == "case_a"


def test_governance_panel_saves_only_when_explicitly_requested():
    from role_aware_dashboard_toolkit.runbook_panels import _render_governance_panel

    config = Config()
    _seed_case(config)
    ctx = make_security_context("Approver", {"can_view_governance": True, "can_manage_governance": True})
    st = FakeStreamlit(save=True)

    _render_governance_panel(st, config, ctx, runs=[])
    saved = config.governance_store.list_records()
    assert len(saved) == 1
    assert validate_governance_record(saved[0])["ok"] is True


def test_file_governance_store_uses_hashed_writes_and_ignores_unhashed_lookup(tmp_path):
    store_dir = tmp_path / "governance"
    store = governance_store.FileGovernanceStore(str(store_dir))
    case_record = caseboard.build_case_record("Case", case_id="case_a")
    left_id = "gov/a"
    right_id = "gov:a"

    left_path = Path(store.save(governance_model.build_governance_record(case_record, governance_id=left_id)))
    right_path = Path(store.save(governance_model.build_governance_record(case_record, governance_id=right_id)))

    assert left_path != right_path
    assert left_path.name.startswith("gova-")
    assert right_path.name.startswith("gova-")
    assert store.load(left_id)["governance_id"] == left_id
    assert store.load(right_id)["governance_id"] == right_id

    legacy_id = "legacy/gov"
    legacy_path = store_dir / "legacygov.json"
    legacy_path.write_text(json.dumps({"governance_id": legacy_id, "case_id": "case_a"}), encoding="utf-8")
    assert store.load(legacy_id) is None


def test_file_governance_store_rejects_symlink_escape_records(tmp_path):
    store_dir = tmp_path / "governance"
    store_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"governance_id": "escape"}', encoding="utf-8")
    link = store_dir / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available in this environment")

    store = governance_store.FileGovernanceStore(str(store_dir))
    assert store.list_records() == []
    assert store.read_errors
    assert store.read_errors[0]["error_type"] == "StorePathSecurityError"


def test_inmemory_governance_store_returns_json_roundtrip_copies():
    store = governance_store.InMemoryGovernanceStore()
    source = {"governance_id": "gov_a", "case_id": "case_a", "linked_run_ids": ["run_a"]}
    store.save(source)
    source["linked_run_ids"].append("run_b")

    loaded_once = store.load("gov_a")
    assert loaded_once["linked_run_ids"] == ["run_a"]
    loaded_once["linked_run_ids"].append("run_c")

    loaded_twice = store.load("gov_a")
    assert loaded_twice["linked_run_ids"] == ["run_a"]


def test_governance_docs_call_out_explicit_persistence_boundary():
    docs = (Path(__file__).resolve().parents[1] / "docs" / "governance.md").read_text(encoding="utf-8")
    assert "Save the governance snapshot explicitly" in docs
    assert "audit logging of those events does not enqueue hidden governance execution" in docs
