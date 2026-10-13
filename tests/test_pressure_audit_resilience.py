"""Pressure regressions for corrupt persisted audit lines."""

from role_aware_dashboard_toolkit import FileAuditStore
from role_aware_dashboard_toolkit import audit_store


def test_deep_audit_line_is_diagnosed_without_hiding_healthy_events(tmp_path):
    path = tmp_path / "audit.jsonl"
    # JSON nesting limits depend on the decoder and its native stack (notably
    # CPython 3.14). Keep real decoding pressure bounded without requiring a
    # particular limit: a valid deep record can be accepted or diagnosed.
    depth = 2048
    deep_line = '{"nested":' + "[" * depth + "0" + "]" * depth + "}"
    original = '{"type":"before"}\n' + deep_line + '\n{"type":"after"}\n'
    path.write_text(original, encoding="utf-8")
    store = FileAuditStore(str(path))

    rows = store.read_all()

    assert rows[0] == {"type": "before"}
    assert rows[-1] == {"type": "after"}
    assert path.read_text(encoding="utf-8") == original
    if store.read_errors:
        assert len(rows) == 2
        assert len(store.read_errors) == 1
        assert store.read_errors[0]["error_type"] == "RecursionError"
        assert "line 2" in store.read_errors[0]["message"]
    else:
        assert len(rows) == 3
        assert set(rows[1]) == {"nested"}
        nested = rows[1]["nested"]
        for _ in range(depth):
            assert isinstance(nested, list) and len(nested) == 1
            nested = nested[0]
        assert nested == 0


def test_decoder_recursion_error_preserves_other_events_and_diagnoses_line(
    tmp_path, monkeypatch
):
    path = tmp_path / "audit.jsonl"
    rejected_line = '{"type":"decoder-limit"}'
    original = '{"type":"before"}\n' + rejected_line + '\n{"type":"after"}\n'
    path.write_text(original, encoding="utf-8")
    real_decoder = audit_store.strict_json_loads
    rejected = []

    def decoder_with_limit(line):
        if line.rstrip("\r") == rejected_line:
            rejected.append(line.rstrip("\r"))
            raise RecursionError("JSON decoder recursion limit reached")
        return real_decoder(line)

    # Exercise the recovery branch on every interpreter while healthy lines
    # still pass through the real strict JSON decoder.
    monkeypatch.setattr(audit_store, "strict_json_loads", decoder_with_limit)
    store = FileAuditStore(str(path))

    assert store.read_all() == [{"type": "before"}, {"type": "after"}]
    assert rejected == [rejected_line]
    assert path.read_text(encoding="utf-8") == original
    assert len(store.read_errors) == 1
    assert store.read_errors[0]["error_type"] == "RecursionError"
    assert "line 2" in store.read_errors[0]["message"]
    assert "JSON decoder recursion limit reached" in store.read_errors[0]["message"]
