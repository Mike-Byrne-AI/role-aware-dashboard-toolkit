"""Spreadsheet exports are a safe view; JSONL and stored audit retain evidence."""
from __future__ import annotations

import csv
from io import StringIO

import pytest

from role_aware_dashboard_toolkit import AuditLog, ControlRegistry, make_security_context
from role_aware_dashboard_toolkit.dashboard_panels import _spreadsheet_safe_audit_csv, render_audit_panel
from tests.test_role_aware_dashboard_toolkit import FakeStreamlit


@pytest.mark.parametrize("value", [
    "=1+1", "+1+1", "-1+1", "@SUM(1,2)", "\t=1+1", "\r=1+1", "\n=1+1",
    "  =1+1", "\ufeff=1+1", "\x00=1+1", "＝1+1", "＋1+1", "－1+1", "＠SUM(1,2)",
    '=1+1,"\n=2+2',
])
def test_formula_like_strings_are_explicit_text_without_breaking_field_boundaries(value):
    exported = _spreadsheet_safe_audit_csv([{"new": value, "detail": "unchanged"}])
    rows = list(csv.DictReader(StringIO(exported)))
    assert rows == [{"new": "'" + value, "detail": "unchanged"}]
    assert exported.startswith('"new","detail"')
    assert exported.splitlines()[1].startswith('"\'')


def test_formula_headers_are_safe_and_numbers_keep_their_numeric_representation():
    exported = _spreadsheet_safe_audit_csv([{"=header": -12, "ordinary": "hello, \"world\"\nnext"}])
    assert list(csv.reader(StringIO(exported))) == [
        ["'=header", "ordinary"], ["-12", 'hello, "world"\nnext'],
    ]


def test_actual_operator_api_change_has_safe_csv_and_faithful_jsonl(monkeypatch):
    TestClient = pytest.importorskip("fastapi.testclient").TestClient
    from role_aware_dashboard_toolkit.api import create_app

    class Downloads(FakeStreamlit):
        def __init__(self):
            super().__init__()
            self.downloads = {}

        def download_button(self, label, data, *args, **kwargs):
            self.downloads[label] = data
            return False

    monkeypatch.setenv("ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY", "synthetic-csv-test-key")
    registry = ControlRegistry()
    registry.register("Operator comment", kind="text", key="operator_comment", default="")
    audit = AuditLog()
    client = TestClient(create_app(registry, audit=audit, api_role="Operator"))
    response = client.patch(
        "/controls", headers={"X-API-Key": "synthetic-csv-test-key"},
        json={"values": {"operator_comment": "=1+1"}},
    )
    assert response.status_code == 200
    before = audit.all_events()
    original_jsonl = audit.export_jsonl()
    runtime = Downloads()
    render_audit_panel(runtime, audit, make_security_context("Viewer", {"can_view_audit": True}))
    rows = list(csv.DictReader(StringIO(runtime.downloads["Download audit.csv"])))
    assert rows[0]["new"] == "'=1+1"
    assert audit.all_events() == before
    assert audit.all_events()[0]["new"] == "=1+1"
    assert runtime.downloads["Download audit.jsonl"] == original_jsonl


def test_csv_is_available_without_optional_pandas(monkeypatch):
    import role_aware_dashboard_toolkit.dashboard_panels as panels

    class Downloads(FakeStreamlit):
        def download_button(self, label, data, *args, **kwargs):
            if label == "Download audit.csv":
                self.csv = data
            return False

    monkeypatch.setattr(panels, "_load_pandas", lambda: None)
    runtime = Downloads()
    audit = AuditLog()
    audit.log("example", detail="=1+1")
    render_audit_panel(runtime, audit)
    assert list(csv.DictReader(StringIO(runtime.csv)))[0]["detail"] == "'=1+1"
