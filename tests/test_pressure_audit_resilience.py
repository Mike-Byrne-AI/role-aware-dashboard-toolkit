"""Pressure regressions for corrupt persisted audit lines."""

import pytest

from role_aware_dashboard_toolkit import FileAuditStore
from role_aware_dashboard_toolkit._json_safety import strict_json_loads


def test_deep_audit_line_is_diagnosed_without_hiding_healthy_events(tmp_path):
    path = tmp_path / "audit.jsonl"
    # Probe the actual decoder instead of assuming its nesting bound equals
    # Python's recursion limit. Keep the fixture and discovery work bounded.
    for depth in (256, 512, 1024, 2048, 4096, 8192, 16384):
        deep_line = '{"nested":' + "[" * depth + "0" + "]" * depth + "}"
        try:
            strict_json_loads(deep_line)
        except RecursionError:
            break
    else:
        pytest.fail("JSON decoder accepted every bounded nesting probe (up to 16384 arrays)")

    # Require the intended failure before testing the store's recovery behavior.
    with pytest.raises(RecursionError):
        strict_json_loads(deep_line)
    original = '{"type":"before"}\n' + deep_line + '\n{"type":"after"}\n'
    path.write_text(original, encoding="utf-8")
    store = FileAuditStore(str(path))

    assert store.read_all() == [{"type": "before"}, {"type": "after"}]

    assert path.read_text(encoding="utf-8") == original
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "RecursionError"
    assert "line 2" in store.read_errors[0]["message"]
