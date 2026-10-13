"""The Timeline table's own CSV download gets the audit CSV's formula protection."""
from __future__ import annotations

import pytest

from role_aware_dashboard_toolkit import AuditLog, make_security_context
from role_aware_dashboard_toolkit import dashboard_panels
from tests.test_role_aware_dashboard_toolkit import RecordingStreamlit

pd = pytest.importorskip("pandas")


def _timeline(audit):
    st = RecordingStreamlit()
    ctx = make_security_context("Auditor", {"can_view_audit": True})
    dashboard_panels.render_audit_panel(st, audit, ctx)
    [frame] = [payload for payload in st.dataframe_payloads if isinstance(payload, pd.DataFrame)]
    return frame


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2+3", "@SUM(1,2)", "\t=1+1", " =1+1", "﻿=1"])
def test_formula_like_cells_are_explicit_text(value):
    audit = AuditLog()
    audit.log("note", detail=value, role=value)
    audit.log_control_change("comment", "plain", value, role="Operator")
    frame = _timeline(audit)
    for column in ("detail", "role", "new"):
        cells = [cell for cell in frame[column] if isinstance(cell, str) and cell.strip()]
        assert cells, column
        for cell in cells:
            if cell in {"plain", "Operator"}:
                continue
            assert cell.startswith("'"), (column, cell)


def test_ordinary_cells_and_the_stored_events_are_unchanged():
    audit = AuditLog()
    audit.log_control_change("workers", 8, 12, role="Operator")
    audit.log("note", detail="=1+1")
    before = audit.all_events()
    frame = _timeline(audit)
    assert list(frame["new"])[0] == "12"
    assert list(frame["role"])[0] == "Operator"
    assert audit.all_events() == before
    assert before[1]["detail"] == "=1+1"


@pytest.mark.parametrize(
    ("old", "new", "shown"),
    [(5, -5, ("5", "-5")), (0.5, -0.25, ("0.5", "-0.25")), (-1, [1, -2], ("-1", "[1, -2]"))],
)
def test_numbers_are_shown_as_numbers_not_quoted_text(old, new, shown):
    # A negative number is not a formula; only values that were text get the
    # apostrophe, so the table no longer shows '-5.
    audit = AuditLog()
    audit.log_control_change("offset", old, new, role="Operator")
    frame = _timeline(audit)
    assert (list(frame["old"])[0], list(frame["new"])[0]) == shown


def test_text_that_looks_like_a_negative_number_is_still_protected():
    audit = AuditLog()
    audit.log_control_change("comment", "plain", "-5+cmd", role="Operator")
    assert list(_timeline(audit)["new"])[0] == "'-5+cmd"
