"""Pressure regressions for corrupt persisted audit lines."""

from role_aware_dashboard_toolkit import FileAuditStore


def test_deep_audit_line_is_diagnosed_without_hiding_healthy_events(tmp_path):
    path = tmp_path / "audit.jsonl"
    # The native JSON decoder's recursion limit is not necessarily Python's
    # recursion limit (CPython 3.12 accepts 1,100 nested arrays with limit 1,000).
    # Use a bounded pressure input that exceeds the supported decoders' limits.
    depth = 10_000
    original = ('{"type":"before"}\n{"nested":' + "[" * depth + "0"
                + "]" * depth + '}\n{"type":"after"}\n')
    path.write_text(original, encoding="utf-8")
    store = FileAuditStore(str(path))

    assert store.read_all() == [{"type": "before"}, {"type": "after"}]

    assert path.read_text(encoding="utf-8") == original
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "RecursionError"
    assert "line 2" in store.read_errors[0]["message"]
