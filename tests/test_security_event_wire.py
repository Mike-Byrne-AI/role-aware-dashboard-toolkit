"""Pure wire conformance and trusted sibling imports, without network services."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "examples/security_event_wire"
wire = runpy.run_path(str(SHARED / "bootstrap.py"))["load_wire"]()
SOURCE, COLLECTOR, DESTINATION = "1" * 32, "2" * 32, "3" * 32
EVENT, RECEIPT, ALERT, INBOX, NOTIFICATION = (char * 32 for char in "45678")
CHANNEL = {"collector_id": COLLECTOR, "destination_id": DESTINATION, "source_id": SOURCE}
INBOX_CHANNEL = {"inbox_id": INBOX, "destination_id": NOTIFICATION, "collector_id": COLLECTOR}
EVENT_BYTES = (
    b'{"event":{"actor":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    b'"code":"login_succeeded","id":"44444444444444444444444444444444","method":"totp",'
    b'"occurred_at":1700000000.0,"outcome":"succeeded","reason":"completed","sequence":7,'
    b'"target":null},"source_id":"11111111111111111111111111111111","v":1}'
)
GOLDEN_HASHES = {
    "event_payload": "3d520e5de2a2313ab385f2f6b0848fd8a576daf21cbebf7f82a96b85a91bc6b3",
    "event_request": "2ea3f742474c4a50a22489d6683fc27eda3bde4b59a817ce230d9836dafcfd1d",
    "event_receipt": "499f76402e2477448035cac5fa2c5eab0172620d863c5b3ed18e451879cb0d15",
    "heartbeat": "bcddf8479cfbad0193a43a36c4a9988bfec0b9452ecd00f618805981b3c7c53e",
    "heartbeat_ack": "eb6ad86fe3b946121149847c0252bb2382d8c37a270ca56f43ea65b694dcd7c9",
    "alert_payload": "b1a9a21d6518d48572501a2583a726a59ffe93dd7b22e978e3c26e4819be46dd",
    "alert_request": "a2e361b05a3d4f595fcc84a1c0a483ee6e68b2ad1e923d099c121f0370358619",
    "inbox_receipt": "3a98d4012ce7d49ad6d85ac7018216cddfeb6b3d800c3f36247b796f24dbc332",
}


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def event():
    return json.loads(EVENT_BYTES)["event"]


def heartbeat():
    return {"v": 1, **CHANNEL, "sequence": 9, "pending_events": 1, "oldest_pending_at": 1700000090.0,
            "retained_events": 4, "employee_session_reserve": 2, "delivery_error": None}


def alert():
    return {"v": 1, "collector_id": COLLECTOR, "alert_id": ALERT, "source_id": SOURCE,
            "number": 1, "at": 1700000200.0, "rule": "source_missing", "severity": "critical",
            "state": "opened", "details": {"last_seen_at": 1700000101.0, "deadline_at": 1700000191.0}}


def vectors():
    frozen = wire.freeze_event(SOURCE, event())
    beat = wire.heartbeat_request(heartbeat())
    notice = wire.freeze_alert(alert())
    return {
        "event_payload": frozen.data,
        "event_request": wire.event_request(COLLECTOR, DESTINATION, "retained_backfill", frozen),
        "event_receipt": wire.event_receipt({"v": 1, **CHANNEL, "event_id": EVENT, "sha256": frozen.sha256,
                                              "receipt_id": RECEIPT, "received_at": 1700000100.0}),
        "heartbeat": beat.data,
        "heartbeat_ack": wire.heartbeat_receipt({"v": 1, **CHANNEL, "sequence": 9,
                                                  "sha256": beat.sha256, "received_at": 1700000101.0}),
        "alert_payload": notice.data,
        "alert_request": wire.alert_request(INBOX, NOTIFICATION, notice),
        "inbox_receipt": wire.inbox_receipt({"v": 1, **INBOX_CHANNEL, "alert_id": ALERT,
                                              "number": 1, "sha256": notice.sha256,
                                              "receipt_id": "9" * 32, "received_at": 1700000201.0}),
    }


def expected_receipt(name, value):
    omitted = {"v", "receipt_id", "received_at"}
    return {key: item for key, item in value.items() if key not in omitted}


@pytest.mark.parametrize("name", tuple(GOLDEN_HASHES))
def test_all_wire_shapes_match_independently_frozen_golden_hashes(name):
    body = vectors()[name]
    assert digest(body) == GOLDEN_HASHES[name]
    if name == "event_payload":
        assert body == EVENT_BYTES


def test_event_receipts_and_payloads_are_detached_and_bound_to_expected_channel():
    payload = wire.freeze_event(SOURCE, event())
    body = wire.event_request(COLLECTOR, DESTINATION, "live", payload)
    parsed = wire.parse_event_request(body, CHANNEL)
    assert parsed.payload == payload
    assert parsed.payload_fields == {"v": 1, "source_id": SOURCE, "event": event()}
    parsed.fields["destination_id"] = "f" * 32
    parsed.payload_fields["event"]["actor"] = None
    assert wire.parse_event_request(body, CHANNEL).payload_fields["event"]["actor"] == "a" * 64
    assert parsed.payload.data == EVENT_BYTES
    for key in CHANNEL:
        with pytest.raises(wire.ProtocolError, match="Security wire message is invalid") as caught:
            wire.parse_event_request(body, {**CHANNEL, key: "f" * 32})
        assert caught.value.code == "identity_mismatch"


def test_persisted_payload_retries_do_not_call_the_new_event_factory(monkeypatch):
    stored = wire.freeze_event(SOURCE, event())
    original = wire.event_request(COLLECTOR, DESTINATION, "retained_backfill", stored)

    def future_factory(*args):
        pytest.fail("A queued event must not be reserialized by a newer producer")

    monkeypatch.setattr(wire, "freeze_event", future_factory)
    restored = wire.from_stored(stored.data, stored.sha256)
    assert wire.event_request(COLLECTOR, DESTINATION, "retained_backfill", restored) == original
    new_channel = wire.event_request(COLLECTOR, "d" * 32, "retained_backfill", restored)
    parsed = wire.parse_event_request(new_channel, {**CHANNEL, "destination_id": "d" * 32})
    assert parsed.payload.data == stored.data and parsed.payload.sha256 == stored.sha256


@pytest.mark.parametrize("name,parser", [
    ("event_receipt", "parse_event_receipt"), ("heartbeat_ack", "parse_heartbeat_receipt"),
    ("inbox_receipt", "parse_inbox_receipt"),
])
def test_success_receipts_bind_every_expected_identity_and_hash(name, parser):
    body = vectors()[name]
    fields = json.loads(body)
    expected = expected_receipt(name, fields)
    parsed = getattr(wire, parser)(body, expected)
    assert parsed.data == body and parsed.fields == fields
    for key, value in expected.items():
        changed = value + 1 if type(value) is int else ("f" * len(value))
        with pytest.raises(wire.ProtocolError) as caught:
            getattr(wire, parser)(body, {**expected, key: changed})
        assert caught.value.code == "identity_mismatch"
    for key in fields:
        missing = dict(fields)
        del missing[key]
        with pytest.raises(wire.ProtocolError):
            getattr(wire, parser)(canon(missing), expected)
    with pytest.raises(wire.ProtocolError):
        getattr(wire, parser)(body, {**expected, "untrusted": "canary"})


def test_duplicate_receipt_bytes_can_be_validated_without_reencoding(monkeypatch):
    body = vectors()["event_receipt"]
    expected = expected_receipt("event_receipt", json.loads(body))
    monkeypatch.setattr(wire, "event_receipt", lambda fields: pytest.fail("Reencoded persisted receipt"))
    assert wire.parse_event_receipt(body, expected).data == body


@pytest.mark.parametrize("field,value", [
    ("id", "A" * 32), ("id", "x" * 31), ("sequence", True), ("sequence", 0),
    ("sequence", 2**63), ("sequence", 1.0), ("occurred_at", -1.0),
    ("occurred_at", float("nan")), ("occurred_at", float("inf")), ("occurred_at", -0.0),
    ("occurred_at", True), ("occurred_at", 253402300800.0), ("code", "new_unreviewed_event"),
    ("code", []), ("actor", "a" * 63), ("target", {"secret": "canary"}),
    ("method", "sms"), ("reason", "forbidden"), ("outcome", "denied"),
])
def test_event_factory_rejects_malformed_or_unreviewed_values(field, value):
    candidate = event()
    candidate[field] = value
    with pytest.raises(wire.ProtocolError) as caught:
        wire.freeze_event(SOURCE, candidate)
    assert str(caught.value) == "Security wire message is invalid."


def test_event_factory_copies_fields_and_only_normalizes_timestamp_at_creation():
    original = event()
    original["occurred_at"] = 1700000000
    frozen = wire.freeze_event(SOURCE, original)
    original["actor"] = None
    assert frozen.data == EVENT_BYTES
    parsed = json.loads(EVENT_BYTES)
    parsed["event"]["occurred_at"] = 1700000000
    changed = canon(parsed)
    with pytest.raises(wire.ProtocolError):
        wire.from_stored(changed, digest(changed))


@pytest.mark.parametrize("body", [
    b"", b"{} " , b"[]", b"null", b'"canary"', b'{}{}', b'\xef\xbb\xbf{}', b'\xff',
    b'{"v":1,"v":1}', b'{"v":1,"\\u0076":1}', b'{"a":NaN}', b'{"a":Infinity}',
    b'{"a":-Infinity}', b'{"a":1e999}', b'{"a":-0.0}', b'{"a":-0}',
    b'{"a":' + b"9" * 33 + b'}', b'{"a":' * 5 + b'1' + b'}' * 5,
    b'{"a":[]}', b'{' + b" " * 4096 + b'}',
])
def test_hostile_json_is_rejected_before_schema_work(body):
    with pytest.raises(wire.ProtocolError):
        wire.parse_event_request(body, CHANNEL)


@pytest.mark.parametrize("mutation", ["extra", "version", "version_bool", "kind", "hash", "payload_hash",
                                         "base64_space", "base64_padding", "base64_unicode", "oversized_payload"])
def test_envelope_and_base64_are_exact_and_integrity_checked(mutation):
    value = json.loads(vectors()["event_request"])
    if mutation == "extra":
        value["secret"] = "DISPOSABLE_SECRET_CANARY"
    elif mutation == "version":
        value["v"] = 2
    elif mutation == "version_bool":
        value["v"] = True
    elif mutation == "kind":
        value["kind"] = "skip_alerts"
    elif mutation == "hash":
        value["sha256"] = value["sha256"].upper()
    elif mutation == "payload_hash":
        value["sha256"] = "f" * 64
    elif mutation == "base64_space":
        value["payload"] += " "
    elif mutation == "base64_padding":
        value["payload"] += "="
    elif mutation == "base64_unicode":
        value["payload"] = "\u00ff"
    else:
        value["payload"] = base64.b64encode(b"x" * 2049).decode()
    with pytest.raises(wire.ProtocolError) as caught:
        wire.parse_event_request(canon(value), CHANNEL)
    assert "DISPOSABLE_SECRET_CANARY" not in str(caught.value)


@pytest.mark.parametrize("data,sha", [(b"{}", digest(b"{}")), (bytearray(EVENT_BYTES), digest(EVENT_BYTES)),
                                      (EVENT_BYTES, "f" * 64), (EVENT_BYTES, digest(EVENT_BYTES).upper())])
def test_public_frozen_constructor_cannot_bypass_validation(data, sha):
    with pytest.raises(wire.ProtocolError):
        wire.FrozenPayload(data, sha)


def test_payload_kinds_cannot_be_substituted_and_repr_hides_bytes():
    frozen = wire.freeze_alert(alert())
    with pytest.raises(wire.ProtocolError):
        wire.from_stored(frozen.data, frozen.sha256)
    with pytest.raises(wire.ProtocolError):
        wire.event_request(COLLECTOR, DESTINATION, "live", frozen)
    assert "source_missing" not in repr(frozen)


@pytest.mark.parametrize("field,value", [("sequence", False), ("sequence", 0), ("pending_events", -1),
    ("pending_events", 0), ("oldest_pending_at", None), ("employee_session_reserve", 1.0),
    ("retained_events", 2**63), ("delivery_error", "secret-provider-body")])
def test_heartbeat_bounds_and_pending_relation(field, value):
    fields = heartbeat()
    fields[field] = value
    with pytest.raises(wire.ProtocolError):
        wire.heartbeat_request(fields)


def test_heartbeat_fields_are_detached_and_future_queue_time_is_not_hidden_by_codec():
    fields = heartbeat()
    fields["oldest_pending_at"] = 1700000300.0
    frozen = wire.heartbeat_request(fields)
    fields["pending_events"] = 99
    parsed = wire.parse_heartbeat(frozen.data, CHANNEL)
    assert parsed.fields["pending_events"] == 1
    assert parsed.fields["oldest_pending_at"] == 1700000300.0
    assert parsed.sha256 == frozen.sha256
    empty = {**heartbeat(), "pending_events": 0, "oldest_pending_at": None}
    assert wire.parse_heartbeat(wire.heartbeat_request(empty).data, CHANNEL).fields["pending_events"] == 0


@pytest.mark.parametrize("rule,details", [
    ("source_missing", {"last_seen_at": None, "deadline_at": 1700000300.0}),
    ("source_backlog", {"pending_events": 1, "oldest_pending_at": 1700000000.0, "threshold_seconds": 300, "basis": "source_age"}),
    ("source_backlog", {"pending_events": 1, "oldest_pending_at": 1700000300.0, "threshold_seconds": 0, "basis": "clock_untrusted"}),
    ("collector_capacity", {"resource": "bytes", "used": 100, "limit": 100}),
    ("event_conflict", {"event_id": EVENT, "accepted_sha256": "a" * 64, "rejected_sha256": "b" * 64}),
])
def test_all_alert_variants_round_trip_to_inbox(rule, details):
    fields = {**alert(), "rule": rule, "details": details}
    frozen = wire.freeze_alert(fields)
    request = wire.alert_request(INBOX, NOTIFICATION, frozen)
    parsed = wire.parse_alert_request(request, INBOX_CHANNEL)
    assert parsed.payload == frozen and parsed.payload_fields == fields
    details.clear()
    assert wire.parse_alert_request(request, INBOX_CHANNEL).payload_fields["details"]
    for key in INBOX_CHANNEL:
        with pytest.raises(wire.ProtocolError):
            wire.parse_alert_request(request, {**INBOX_CHANNEL, key: "f" * 32})


@pytest.mark.parametrize("mutation", ["unknown_rule", "extra_detail", "extra_field", "bad_counter",
                                       "bad_state", "bad_severity", "same_hash", "clock_threshold", "missing_detail"])
def test_alert_details_are_a_fixed_variant_not_free_form(mutation):
    fields = deepcopy(alert())
    if mutation == "unknown_rule":
        fields["rule"] = "user_supplied"
    elif mutation == "extra_detail":
        fields["details"]["operator_url"] = "https://untrusted.invalid"
    elif mutation == "extra_field":
        fields["html"] = "<script>canary</script>"
    elif mutation == "bad_counter":
        fields["number"] = True
    elif mutation == "bad_state":
        fields["state"] = "deleted"
    elif mutation == "bad_severity":
        fields["severity"] = []
    elif mutation == "same_hash":
        fields.update(rule="event_conflict", details={"event_id": EVENT, "accepted_sha256": "a" * 64, "rejected_sha256": "a" * 64})
    elif mutation == "clock_threshold":
        fields.update(rule="source_backlog", details={"pending_events": 1, "oldest_pending_at": 1700000300.0,
                                                     "threshold_seconds": 1, "basis": "clock_untrusted"})
    else:
        fields["details"].pop("deadline_at")
    with pytest.raises(wire.ProtocolError):
        wire.freeze_alert(fields)


def copy_example_layout(tmp_path):
    root = tmp_path / "extracted"
    shared = root / "examples/security_event_wire"
    shared.mkdir(parents=True)
    for name in ("__init__.py", "bootstrap.py", "protocol.py"):
        shutil.copyfile(SHARED / name, shared / name)
    for relative in ("examples/business_dashboard/business/event_wire.py", "examples/security_event_collector/collector/event_wire.py"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    return root, shared


def isolated(tmp_path, script, *args):
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script, *(str(arg) for arg in args)],
                            cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


def test_both_extracted_example_bridges_share_reviewed_stdlib_core_from_arbitrary_cwd(tmp_path):
    root, shared = copy_example_layout(tmp_path)
    isolated(tmp_path, """
from pathlib import Path
import runpy,sys,types
root=Path(sys.argv[1]); before=list(sys.path)
fake=types.ModuleType('security_event_wire');fake.__file__='/unrelated/installed.py'
sys.modules['security_event_wire']=fake
one=runpy.run_path(str(root/'examples/business_dashboard/business/event_wire.py'))['wire']
two=runpy.run_path(str(root/'examples/security_event_collector/collector/event_wire.py'))['wire']
assert one is two
assert Path(one.__file__).resolve()==root/'examples/security_event_wire/protocol.py'
assert sys.path==before
assert not {'httpx','fastapi','uvicorn'}.intersection(sys.modules)
assert sys.modules['security_event_wire'] is fake
""", root)


def test_concurrent_bridge_loads_publish_one_complete_package(tmp_path):
    root, shared = copy_example_layout(tmp_path)
    original = (shared / "protocol.py").read_text()
    (shared / "protocol.py").write_text("import builtins,time\nbuiltins.wire_loads=getattr(builtins,'wire_loads',0)+1\ntime.sleep(.02)\n" + original)
    isolated(tmp_path, """
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import builtins,runpy,sys
path=Path(sys.argv[1])/'examples/business_dashboard/business/event_wire.py'
with ThreadPoolExecutor(max_workers=8) as pool:
    modules=list(pool.map(lambda _:runpy.run_path(str(path))['wire'],range(16)))
assert len({id(module) for module in modules})==1
assert all(hasattr(module,'from_stored') for module in modules)
assert builtins.wire_loads==1
""", root)


def test_failed_import_cleans_owned_partial_modules_and_retry_can_succeed(tmp_path):
    root, shared = copy_example_layout(tmp_path)
    original = tmp_path / "original.py"
    shutil.copyfile(shared / "protocol.py", original)
    (shared / "child.py").write_text("value=1\n")
    (shared / "protocol.py").write_text("from . import child\nraise RuntimeError('synthetic failure')\n")
    isolated(tmp_path, """
from pathlib import Path
import runpy,sys,types
shared=Path(sys.argv[1]);original=Path(sys.argv[2])
load=runpy.run_path(str(shared/'bootstrap.py'))['load_wire']
unrelated=types.ModuleType('unrelated_fixture');sys.modules['unrelated_fixture']=unrelated
try:load()
except RuntimeError:pass
else:raise AssertionError('Failed source was accepted')
assert not any(name.startswith('_westbridge_security_event_wire') for name in sys.modules)
assert sys.modules['unrelated_fixture'] is unrelated
(shared/'protocol.py').write_bytes(original.read_bytes())
assert hasattr(load(),'freeze_event')
""", shared, original)


@pytest.mark.parametrize("mode", ["wrong_origin", "partial", "wrong_submodule", "missing_shared"])
def test_loader_refuses_wrong_or_incomplete_authority(tmp_path, mode):
    root, shared = copy_example_layout(tmp_path)
    if mode == "missing_shared":
        (shared / "__init__.py").unlink()
    isolated(tmp_path, """
from pathlib import Path
import runpy,sys,types
shared=Path(sys.argv[1]);mode=sys.argv[2];name='_westbridge_security_event_wire'
load=runpy.run_path(str(shared/'bootstrap.py'))['load_wire']
if mode!='missing_shared':
    package=types.ModuleType(name);package.__file__=str(shared/'__init__.py')
    if mode=='wrong_origin':package.__file__='/unrelated/package.py'
    if mode=='wrong_submodule':
        package._WIRE_READY=True;package.protocol=object()
        child=types.ModuleType(name+'.protocol');child.__file__='/unrelated/protocol.py'
        sys.modules[child.__name__]=child
    sys.modules[name]=package
try:load()
except ImportError:pass
else:raise AssertionError('Invalid cached or absent package was accepted')
if mode!='missing_shared':assert sys.modules[name] is package
""", shared, mode)


def test_optional_transport_is_explicit_origin_checked_and_failed_import_is_recoverable(tmp_path):
    root, shared = copy_example_layout(tmp_path)
    (shared / "transport.py").write_text("raise RuntimeError('synthetic adapter failure')\n")
    isolated(tmp_path, """
from pathlib import Path
import runpy,sys
shared=Path(sys.argv[1]);loader=runpy.run_path(str(shared/'bootstrap.py'))
core=loader['load_wire']()
assert '_westbridge_security_event_wire.transport' not in sys.modules
try:loader['load_transport']()
except RuntimeError:pass
else:raise AssertionError('Failed adapter accepted')
assert '_westbridge_security_event_wire.transport' not in sys.modules
assert loader['load_wire']() is core
(shared/'transport.py').write_text('marker=42\\n')
assert loader['load_transport']().marker==42
""", shared)
