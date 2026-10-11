"""Published JSON contracts agree with runtime rules, apart from named exceptions."""

from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

import role_aware_dashboard_toolkit as radt
from role_aware_dashboard_toolkit import validators
from role_aware_dashboard_toolkit.packet_core import VALID_PACKET_TYPES
from role_aware_dashboard_toolkit.protocol.catalog import RECORD_SCHEMA_VERSIONS
from role_aware_dashboard_toolkit.validators_parts import common
from tests.test_record_shape_boundaries import _records


SCHEMA_RECORDS = {
    "case": "case", "checkpoint": "checkpoint", "decision": "decision",
    "governance": "governance", "incident": "incident",
    "incident_timeline": "incident_timeline", "ledger": "ledger",
    "narrative_handoff": "narrative_handoff", "operator_note": "operator_note",
    "packet": "packet", "replay": "replay_packet", "run": "run",
}
PACKET_RECORDS = {name: {"compare": "diff_packet", "replay": "replay_packet"}.get(name, name)
                  for name in VALID_PACKET_TYPES}
SHAPE_TABLES = (
    (common._MAPPING_FIELDS, "object"),
    (common._RECORD_LIST_FIELDS, "array"),
    (common._STRING_LIST_FIELDS, "array"),
    (common._STRING_FIELDS, "string"),
    (common._INTEGER_FIELDS, "integer"),
    (common._BOOLEAN_FIELDS, "boolean"),
)
ENUM_FIELDS = {
    "run": {"status": validators.VALID_RUN_STATUSES},
    "checkpoint": {"approval_state": validators.VALID_APPROVAL_STATES},
    "approval": {"state": validators.VALID_APPROVAL_STATES},
    "decision": {"state": validators.VALID_DECISION_STATES},
    "case": {"state": validators.VALID_CASE_STATES, "priority": validators.VALID_CASE_PRIORITIES},
    "governance": {"state": validators.VALID_GOVERNANCE_STATES,
                   "escalation_level": validators.VALID_ESCALATION_LEVELS},
    "governance_policy_check": {"result": validators.VALID_POLICY_CHECK_RESULTS},
    "operator_note": {"event_type": validators.VALID_NOTE_EVENT_TYPES},
    "incident": {"event_type": ("incident",), "status": validators.VALID_INCIDENT_STATUSES,
                 "severity": validators.VALID_INCIDENT_SEVERITIES},
    "incident_timeline": {"event_type": ("incident_timeline",)},
    "narrative_handoff": {"event_type": ("narrative_handoff",)},
    "ledger_entry": {"entry_type": validators.VALID_LEDGER_ENTRY_TYPES},
}
HISTORY_ENUMS = {
    "decision": validators.VALID_DECISION_EVENT_TYPES,
    "case": validators.VALID_CASE_EVENT_TYPES,
    "governance": validators.VALID_GOVERNANCE_EVENT_TYPES,
}


@lru_cache(maxsize=None)
def _schema(name):
    path = Path(__file__).parents[1] / "schemas" / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def _json_validator(name):
    return Draft202012Validator(_schema(name))


@pytest.fixture(scope="module")
def records():
    # Public builders supply the valid fixtures; schemas never generate test data.
    result = _records()
    result["checkpoint"]["audit_slice"] = [result["audit_event"]]
    result["governance"]["policy_checks"] = [
        {"check_id": "review", "title": "Review", "result": validators.VALID_POLICY_CHECK_RESULTS[0]},
    ]
    result["audit_slice"] = radt.build_audit_slice_packet([result["audit_event"]])["payload"]
    return result


def _assert_agreement(schema_name, record_type, record, *, accepted, context=""):
    runtime = validators.validate_record(record_type, record)
    schema_errors = list(_json_validator(schema_name).iter_errors(record))
    assert runtime["ok"] is accepted, (context, runtime["errors"])
    assert (not schema_errors) is accepted, (context, [error.message for error in schema_errors])


@lru_cache(maxsize=None)
def _required_fields(record_type):
    if record_type not in validators.VALID_RECORD_TYPES:
        return ()
    prefix = "Missing required field: "
    return tuple(error.removeprefix(prefix)
                 for error in validators.validate_record(record_type, {})["errors"]
                 if error.startswith(prefix))


def _record_paths(record_type, path=()):
    yield record_type, path
    for field, nested_type in common._NESTED_RECORDS.get(record_type, {}).items():
        child_path = path + (field,)
        if field in common._RECORD_LIST_FIELDS.get(record_type, ()):
            child_path += (0,)
        yield from _record_paths(nested_type, child_path)


def _field_shapes(record_type):
    shapes = {field: kind for table, kind in SHAPE_TABLES for field in table.get(record_type, ())}
    for field in _required_fields(record_type):
        shapes.setdefault(field, "string")
    if record_type not in common._UNVERSIONED_NESTED_RECORDS:
        shapes["schema_version"] = "integer"
    if record_type == "packet":
        shapes["payload_schema_version"] = "integer"
    return shapes


def _set_value(record, path, value):
    """Populate optional nested objects/lists before changing one declared field."""
    current = record
    for index, key in enumerate(path[:-1]):
        if isinstance(key, int):
            while len(current) <= key:
                current.append({})
        elif key not in current:
            current[key] = [] if isinstance(path[index + 1], int) else {}
        current = current[key]
    current[path[-1]] = value


def _field_mutations(record_type, base):
    samples = {"string": "", "integer": 0, "boolean": False, "array": [], "object": {}}
    for child_type, path in _record_paths(record_type):
        for field, kind in _field_shapes(child_type).items():
            for wrong_kind, value in samples.items():
                if wrong_kind != kind:
                    record = deepcopy(base)
                    _set_value(record, path + (field,), value)
                    yield record, (path + (field,), wrong_kind)
            record = deepcopy(base)
            _set_value(record, path + (field,), None)
            yield record, (path + (field,), "null")
        for table, wrong_item in ((common._RECORD_LIST_FIELDS, "not a record"),
                                  (common._STRING_LIST_FIELDS, {})):
            for field in table.get(child_type, ()):
                record = deepcopy(base)
                _set_value(record, path + (field,), [wrong_item])
                yield record, (path + (field,), "invalid list item")


def _enum_mutations(record_type, base):
    for child_type, path in _record_paths(record_type):
        for field, allowed in ENUM_FIELDS.get(child_type, {}).items():
            for value in (*allowed, "invented", "", None, False, 1):
                record = deepcopy(base)
                _set_value(record, path + (field,), value)
                yield record, value in allowed, (path, field, value)
    if record_type in HISTORY_ENUMS:
        for value in (*HISTORY_ENUMS[record_type], "invented", None, False):
            record = deepcopy(base)
            record["history"] = [{"event_type": value}]
            yield record, value in HISTORY_ENUMS[record_type], ("history", value)


def _walk_schema(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_schema(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_schema(child)


@pytest.mark.parametrize("schema_name", SCHEMA_RECORDS)
def test_each_published_schema_is_valid_and_self_contained(schema_name):
    schema = _schema(schema_name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)
    for node in _walk_schema(schema):
        for keyword in ("$ref", "$dynamicRef"):
            if keyword in node:
                assert node[keyword].startswith("#"), (schema_name, node[keyword])
                # No resolver or network registry is needed to validate these files.
    version = RECORD_SCHEMA_VERSIONS[SCHEMA_RECORDS[schema_name]]
    assert schema["properties"]["schema_version"]["const"] == version


def test_parity_suite_covers_every_published_schema():
    paths = (Path(__file__).parents[1] / "schemas").glob("*.schema.json")
    assert {path.name.removesuffix(".schema.json") for path in paths} == set(SCHEMA_RECORDS)


@pytest.mark.parametrize("schema_name,record_type", SCHEMA_RECORDS.items())
def test_complete_records_and_application_extensions_agree(schema_name, record_type, records):
    base = deepcopy(records[record_type])
    _assert_agreement(schema_name, record_type, base, accepted=True)
    base["application_field"] = {"arbitrary": [None, False, 42]}
    _assert_agreement(schema_name, record_type, base, accepted=True)
    for invalid in (None, False, 1, "record", [], [base]):
        _assert_agreement(schema_name, record_type, invalid, accepted=False)


@pytest.mark.parametrize("schema_name,record_type", SCHEMA_RECORDS.items())
def test_required_fields_and_optional_omissions_agree(schema_name, record_type, records):
    base = records[record_type]
    for field in set(base) | set(_required_fields(record_type)):
        record = deepcopy(base)
        record.pop(field, None)
        required = field in _required_fields(record_type) or (
            record_type == "packet" and field == "payload_schema_version")
        _assert_agreement(schema_name, record_type, record, accepted=not required, context=field)


@pytest.mark.parametrize("schema_name,record_type", SCHEMA_RECORDS.items())
def test_runtime_declared_fields_and_nested_shapes_agree(schema_name, record_type, records):
    for record, context in _field_mutations(record_type, records[record_type]):
        _assert_agreement(schema_name, record_type, record, accepted=False, context=context)


@pytest.mark.parametrize("schema_name,record_type", SCHEMA_RECORDS.items())
def test_declared_scalar_fields_do_not_add_unintended_constraints(schema_name, record_type, records):
    # Empty optional strings and negative counts remain valid unless runtime
    # explicitly constrains that field. This also checks both boolean values.
    samples = {"string": ("", "arbitrary"), "integer": (-1, 0, 1), "boolean": (False, True)}
    for child_type, path in _record_paths(record_type):
        for field, kind in _field_shapes(child_type).items():
            for value in samples.get(kind, ()):
                record = deepcopy(records[record_type])
                _set_value(record, path + (field,), value)
                accepted = validators.validate_record(record_type, record)["ok"]
                _assert_agreement(schema_name, record_type, record, accepted=accepted,
                                  context=(path, field, value))


@pytest.mark.parametrize("schema_name,record_type", SCHEMA_RECORDS.items())
def test_versions_and_enumerated_values_agree(schema_name, record_type, records):
    for invalid_version in (0, RECORD_SCHEMA_VERSIONS[record_type] + 1, True, "1"):
        record = deepcopy(records[record_type])
        record["schema_version"] = invalid_version
        _assert_agreement(schema_name, record_type, record, accepted=False, context="schema_version")
    for record, accepted, context in _enum_mutations(record_type, records[record_type]):
        _assert_agreement(schema_name, record_type, record, accepted=accepted, context=context)


@pytest.mark.parametrize("packet_type,record_type", PACKET_RECORDS.items())
def test_every_builtin_packet_checks_present_payload_fields(packet_type, record_type, records):
    packet = radt.build_packet(packet_type, records[record_type])
    _assert_agreement("packet", "packet", packet, accepted=True)
    for payload, context in _field_mutations(record_type, records[record_type]):
        malformed = deepcopy(packet)
        malformed["payload"] = payload
        _assert_agreement("packet", "packet", malformed, accepted=False, context=(packet_type, context))
    for payload, accepted, context in _enum_mutations(record_type, records[record_type]):
        changed = deepcopy(packet)
        changed["payload"] = payload
        _assert_agreement("packet", "packet", changed, accepted=accepted, context=(packet_type, context))
    for field in ("payload_schema_version", "schema_version"):
        malformed = deepcopy(packet)
        target = malformed if field == "payload_schema_version" else malformed["payload"]
        target[field] = RECORD_SCHEMA_VERSIONS[record_type] + 1
        _assert_agreement("packet", "packet", malformed, accepted=False, context=(packet_type, field))


@pytest.mark.parametrize("packet_type", VALID_PACKET_TYPES)
def test_every_builtin_packet_preserves_partial_payload_and_envelope(packet_type):
    packet = radt.build_packet(packet_type, {"schema_version": RECORD_SCHEMA_VERSIONS[packet_type]})
    packet["payload"] = {"application_field": {"value": None}}
    for field in ("source_app", "source_version", "meta"):
        packet.pop(field)
    packet["packet_id"] = ""
    _assert_agreement("packet", "packet", packet, accepted=True)
    assert radt.load_packet_json(radt.export_packet_json(packet)) == packet


@pytest.mark.parametrize("packet_type,payload", [
    ("run", {"checkpoints": [{"approval": {}, "audit_slice": [{}]}]}),
    ("checkpoint", {"approval": {}, "audit_slice": [{}]}),
    ("audit_slice", {"events": [{}]}),
    ("ledger", {"entries": [{"audit_event": {}}]}),
    ("profile", {"control_meta": [{}]}),
    ("narrative_handoff", {"highlights": [{}]}),
    ("compare", {"diff": {"application_field": None}}),
    ("replay", {"controls": {"application_field": None}}),
])
def test_nested_missing_metadata_remains_accepted_in_packets(packet_type, payload):
    packet = radt.build_packet(packet_type, {"schema_version": RECORD_SCHEMA_VERSIONS[packet_type], **payload})
    _assert_agreement("packet", "packet", packet, accepted=True)


@pytest.mark.parametrize("schema_name,path", [
    ("run", ("checkpoints", 0)), ("run", ("checkpoints", 0, "approval")),
    ("checkpoint", ("approval",)), ("governance", ("policy_checks", 0)),
])
def test_complete_records_require_nested_metadata(schema_name, path, records):
    record = deepcopy(records[schema_name])
    _set_value(record, path, {})
    _assert_agreement(schema_name, schema_name, record, accepted=False, context=path)


@pytest.mark.parametrize("schema_name,path", [
    ("checkpoint", ("audit_slice", 0)), ("ledger", ("entries", 0)),
    ("ledger", ("entries", 0, "audit_event")), ("decision", ("history", 0)),
    ("case", ("history", 0)), ("governance", ("history", 0)),
])
def test_shape_only_nested_records_preserve_optional_metadata(schema_name, path, records):
    record = deepcopy(records[schema_name])
    _set_value(record, path, {})
    _assert_agreement(schema_name, schema_name, record, accepted=True, context=path)


@pytest.mark.parametrize("schema_name,path", [
    ("ledger", ("entries", 0)),
    ("governance", ("approval_requirements",)), ("governance", ("policy_checks", 0)),
])
@pytest.mark.parametrize("version", [None, "application-owned", {"version": 42}])
def test_unversioned_nested_objects_preserve_application_owned_versions(schema_name, path, version, records):
    record = deepcopy(records[schema_name])
    _set_value(record, path + ("schema_version",), version)
    _assert_agreement(schema_name, schema_name, record, accepted=True, context=path)


def test_integer_valued_float_is_a_documented_python_type_exception(records):
    record = deepcopy(records["operator_note"])
    record["schema_version"] = 1.0
    assert _json_validator("operator_note").is_valid(record)
    assert not validators.validate_record("operator_note", record)["ok"]


@pytest.mark.parametrize("raw_type", ["Run", " run ", "X_Custom"])
def test_packet_names_are_canonicalized_before_schema_validation(raw_type):
    packet = radt.build_packet(raw_type, {"schema_version": 1})
    packet["packet_type"] = raw_type
    assert validators.validate_record("packet", packet)["ok"]
    assert not _json_validator("packet").is_valid(packet)
    exported = json.loads(radt.export_packet_json(packet))
    _assert_agreement("packet", "packet", exported, accepted=True)
    assert exported["packet_type"] == raw_type.strip().lower()


@pytest.mark.parametrize("packet_type", ["run", "x_custom"])
def test_legacy_version_strings_are_runtime_compatibility_outside_json_contract(packet_type):
    packet = radt.build_packet(packet_type, {"schema_version": 1})
    packet["payload_schema_version"] = " 1 "
    assert validators.validate_record("packet", packet)["ok"]
    assert not _json_validator("packet").is_valid(packet)
    exported = json.loads(radt.export_packet_json(packet))
    assert exported["payload_schema_version"] == " 1 "
    assert not _json_validator("packet").is_valid(exported)


def test_extension_payload_is_application_owned_and_version_equality_is_runtime_only():
    packet = radt.build_packet("x_custom", {"schema_version": 7, "controls": 42})
    _assert_agreement("packet", "packet", packet, accepted=True)
    packet["payload"]["schema_version"] = 8
    assert _json_validator("packet").is_valid(packet)
    result = validators.validate_record("packet", packet)
    assert not result["ok"]
    assert any("does not match" in error for error in result["errors"])
