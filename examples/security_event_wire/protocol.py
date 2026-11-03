"""Strict, pure version-one codecs shared by two standalone source examples.

Hashes identify exact canonical bytes, not trustworthy authors. Authentication,
storage, clocks, HTTP admission and retries belong to the consuming examples.
"""

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import math
import re

VERSION = 1
MAX_INTEGER = 2**63 - 1
MAX_TIME = 253402300799.0
MAX_PAYLOAD_BYTES = 2048
MAX_ENVELOPE_BYTES = 4096
MAX_MESSAGE_BYTES = 2048
MAX_DEPTH = 4
CODES = frozenset({
    "login_succeeded", "password_changed", "identity_verified", "session_revoked",
    "session_logged_out", "passkey_registered", "passkey_removed", "editing_paused",
    "editing_resumed", "account_enabled", "account_disabled", "mfa_key_rotated",
    "authentication_denied", "authorization_denied", "request_denied", "enrollment_issued",
    "enrollment_started", "enrollment_completed", "authentication_policy_activated",
    "security_destination_enabled",
})
REASONS = frozenset({"completed", "unauthenticated", "forbidden", "conflict", "throttled",
                     "invalid_request", "unavailable"})
METHODS = frozenset({"none", "password", "totp", "passkey"})
DELIVERY_ERRORS = frozenset({"config_unavailable", "transport_failed", "tls_failed", "remote_auth_failed",
                           "remote_conflict", "remote_capacity", "remote_throttled", "remote_unavailable",
                           "invalid_receipt"})
_ID = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_EVENT = frozenset({"id", "sequence", "occurred_at", "code", "outcome", "reason", "actor", "target", "method"})
_EVENT_PAYLOAD = frozenset({"v", "source_id", "event"})
_EVENT_REQUEST = frozenset({"v", "collector_id", "destination_id", "kind", "payload", "sha256"})
_EVENT_RECEIPT = frozenset({"v", "collector_id", "destination_id", "source_id", "event_id", "sha256", "receipt_id", "received_at"})
_HEARTBEAT = frozenset({"v", "collector_id", "destination_id", "source_id", "sequence", "pending_events",
                        "oldest_pending_at", "retained_events", "employee_session_reserve", "delivery_error"})
_HEARTBEAT_RECEIPT = frozenset({"v", "collector_id", "destination_id", "source_id", "sequence", "sha256", "received_at"})
_ALERT = frozenset({"v", "collector_id", "alert_id", "source_id", "number", "at", "rule", "severity", "state", "details"})
_ALERT_REQUEST = frozenset({"v", "inbox_id", "destination_id", "payload", "sha256"})
_INBOX_RECEIPT = frozenset({"v", "inbox_id", "destination_id", "collector_id", "alert_id", "number", "sha256", "receipt_id", "received_at"})
_EVENT_CHANNEL = frozenset({"collector_id", "destination_id", "source_id"})
_ALERT_CHANNEL = frozenset({"inbox_id", "destination_id", "collector_id"})


class ProtocolError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__("Security wire message is invalid.")


def _require(condition, code="bad_shape"):
    if not condition:
        raise ProtocolError(code)


def _shape(value, keys):
    _require(type(value) is dict and set(value) == keys)


def _integer(value, *, positive=False):
    _require(type(value) is int and int(positive) <= value <= MAX_INTEGER, "bounds")


def _timestamp(value, *, nullable=False):
    if nullable and value is None:
        return
    _require(type(value) is float and math.isfinite(value) and 0 <= value <= MAX_TIME
             and not (value == 0 and math.copysign(1.0, value) < 0), "bounds")


def _normalize_time(value):
    _require(type(value) in (int, float), "bounds")
    try:
        result = float(value)
    except (ValueError, OverflowError):
        raise ProtocolError("bounds") from None
    _timestamp(result)
    return result


def _identifier(value, *, hashed=False, nullable=False):
    if nullable and value is None:
        return
    _require(type(value) is str and bool((_HASH if hashed else _ID).fullmatch(value)), "bounds")


def _enum(value, choices):
    _require(type(value) is str and value in choices, "unsupported_value")


def _version(value):
    _require(type(value) is int and value == VERSION, "unsupported_version")


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError, OverflowError, UnicodeError):
        raise ProtocolError("invalid_json") from None


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _pairs(items):
    result = {}
    _require(len(items) <= 16, "bounds")
    for key, value in items:
        _require(key not in result, "duplicate_key")
        result[key] = value
    return result


def _number(text, floating=False):
    _require(len(text) <= 32, "bounds")
    result = float(text) if floating else int(text)
    if floating:
        _require(math.isfinite(result) and not (result == 0 and math.copysign(1.0, result) < 0), "bounds")
    return result


def _constant(text):
    raise ProtocolError("invalid_json")


def _read(data, limit):
    _require(type(data) is bytes and 0 < len(data) <= limit, "bounds")
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise ProtocolError("invalid_json") from None
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == "[":
            raise ProtocolError("bad_shape")
        elif char == "{":
            depth += 1
            _require(depth <= MAX_DEPTH, "bounds")
        elif char == "}":
            depth -= 1
            _require(depth >= 0, "invalid_json")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_int=_number,
                           parse_float=lambda value: _number(value, True), parse_constant=_constant)
    except (ValueError, TypeError, RecursionError, OverflowError) as error:
        if isinstance(error, ProtocolError):
            raise
        raise ProtocolError("invalid_json") from None
    _require(type(value) is dict)
    _require(_canonical(value) == data, "noncanonical")
    return value


def _event(value):
    _shape(value, _EVENT_PAYLOAD)
    _version(value["v"])
    _identifier(value["source_id"])
    event = value["event"]
    _shape(event, _EVENT)
    _identifier(event["id"])
    _integer(event["sequence"], positive=True)
    _timestamp(event["occurred_at"])
    _enum(event["code"], CODES)
    _enum(event["outcome"], {"succeeded", "denied"})
    _enum(event["reason"], REASONS)
    _require((event["outcome"] == "succeeded") == (event["reason"] == "completed"))
    _identifier(event["actor"], hashed=True, nullable=True)
    _identifier(event["target"], hashed=True, nullable=True)
    _enum(event["method"], METHODS)


def _backlog(value):
    _integer(value["pending_events"])
    _timestamp(value["oldest_pending_at"], nullable=True)
    _require((value["pending_events"] == 0) == (value["oldest_pending_at"] is None))


def _heartbeat(value):
    _shape(value, _HEARTBEAT)
    _version(value["v"])
    for key in _EVENT_CHANNEL:
        _identifier(value[key])
    _integer(value["sequence"], positive=True)
    _integer(value["retained_events"])
    _integer(value["employee_session_reserve"])
    _backlog(value)
    if value["delivery_error"] is not None:
        _enum(value["delivery_error"], DELIVERY_ERRORS)


def _alert(value):
    _shape(value, _ALERT)
    _version(value["v"])
    for key in ("collector_id", "alert_id", "source_id"):
        _identifier(value[key])
    _integer(value["number"], positive=True)
    _timestamp(value["at"])
    _enum(value["severity"], {"warning", "critical"})
    _enum(value["state"], {"opened", "escalated", "acknowledged", "resolved"})
    _enum(value["rule"], {"source_missing", "source_backlog", "collector_capacity", "event_conflict"})
    detail = value["details"]
    if value["rule"] == "source_missing":
        _shape(detail, {"last_seen_at", "deadline_at"})
        _timestamp(detail["last_seen_at"], nullable=True)
        _timestamp(detail["deadline_at"])
    elif value["rule"] == "source_backlog":
        _shape(detail, {"pending_events", "oldest_pending_at", "threshold_seconds", "basis"})
        _backlog(detail)
        _enum(detail["basis"], {"source_age", "clock_untrusted"})
        _integer(detail["threshold_seconds"], positive=detail["basis"] == "source_age")
        if detail["basis"] == "clock_untrusted":
            _require(detail["threshold_seconds"] == 0)
    elif value["rule"] == "collector_capacity":
        _shape(detail, {"resource", "used", "limit"})
        _enum(detail["resource"], {"events", "bytes", "alert_cases", "alert_transitions"})
        _integer(detail["used"])
        _integer(detail["limit"], positive=True)
    else:
        _shape(detail, {"event_id", "accepted_sha256", "rejected_sha256"})
        _identifier(detail["event_id"])
        _identifier(detail["accepted_sha256"], hashed=True)
        _identifier(detail["rejected_sha256"], hashed=True)
        _require(detail["accepted_sha256"] != detail["rejected_sha256"])


_VALIDATORS = {"event": _event, "alert": _alert, "heartbeat": _heartbeat}


def _payload(data, expected_hash, kind=None):
    _identifier(expected_hash, hashed=True)
    value = _read(data, MAX_PAYLOAD_BYTES)
    _require(_digest(data) == expected_hash, "hash_mismatch")
    if kind is None:
        kind = "event" if set(value) == _EVENT_PAYLOAD else "alert" if set(value) == _ALERT else "heartbeat"
    _enum(kind, _VALIDATORS)
    _VALIDATORS[kind](value)
    return value


@dataclass(frozen=True)
class FrozenPayload:
    data: bytes = field(repr=False)
    sha256: str

    def __post_init__(self):
        _payload(self.data, self.sha256)


@dataclass(frozen=True)
class ParsedMessage:
    fields: dict = field(repr=False)
    data: bytes = field(repr=False)
    sha256: str
    payload: FrozenPayload | None = field(default=None, repr=False)
    payload_fields: dict | None = field(default=None, repr=False)


def from_stored(data, sha256, *, kind="event"):
    _payload(data, sha256, kind)
    return FrozenPayload(data, sha256)


def freeze_event(source_id, event):
    _shape(event, _EVENT)
    value = {"v": VERSION, "source_id": source_id, "event": dict(event)}
    value["event"]["occurred_at"] = _normalize_time(value["event"]["occurred_at"])
    _event(value)
    data = _canonical(value)
    return from_stored(data, _digest(data))


def freeze_alert(fields):
    _shape(fields, _ALERT)
    value = dict(fields)
    value["at"] = _normalize_time(value["at"])
    _require(type(value["details"]) is dict)
    value["details"] = dict(value["details"])
    for key in ("last_seen_at", "deadline_at", "oldest_pending_at"):
        if key in value["details"] and value["details"][key] is not None:
            value["details"][key] = _normalize_time(value["details"][key])
    _alert(value)
    data = _canonical(value)
    return from_stored(data, _digest(data), kind="alert")


def _channel(expected, keys):
    _shape(expected, keys)
    for key in keys:
        _identifier(expected[key])


def _match(value, expected):
    _require(all(value.get(key) == item for key, item in expected.items()), "identity_mismatch")


def _encoded_payload(frozen, kind):
    _require(type(frozen) is FrozenPayload)
    _payload(frozen.data, frozen.sha256, kind)
    return base64.b64encode(frozen.data).decode("ascii")


def _decoded_payload(value, kind):
    encoded = value["payload"]
    _require(type(encoded) is str and 0 < len(encoded) <= 4 * ((MAX_PAYLOAD_BYTES + 2) // 3), "bounds")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ProtocolError("invalid_payload") from None
    _require(base64.b64encode(data).decode("ascii") == encoded, "noncanonical")
    return from_stored(data, value["sha256"], kind=kind)


def event_request(collector_id, destination_id, kind, frozen):
    _identifier(collector_id)
    _identifier(destination_id)
    _enum(kind, {"live", "retained_backfill"})
    data = _canonical({"v": VERSION, "collector_id": collector_id, "destination_id": destination_id,
                       "kind": kind, "payload": _encoded_payload(frozen, "event"), "sha256": frozen.sha256})
    _require(len(data) <= MAX_ENVELOPE_BYTES, "bounds")
    return data


def parse_event_request(body, expected_channel):
    _channel(expected_channel, _EVENT_CHANNEL)
    value = _read(body, MAX_ENVELOPE_BYTES)
    _shape(value, _EVENT_REQUEST)
    _version(value["v"])
    _identifier(value["collector_id"])
    _identifier(value["destination_id"])
    _enum(value["kind"], {"live", "retained_backfill"})
    frozen = _decoded_payload(value, "event")
    decoded = _payload(frozen.data, frozen.sha256, "event")
    _match({"collector_id": value["collector_id"], "destination_id": value["destination_id"],
            "source_id": decoded["source_id"]}, expected_channel)
    return ParsedMessage(value, body, _digest(body), frozen, decoded)


def heartbeat_request(fields):
    _shape(fields, _HEARTBEAT)
    value = dict(fields)
    if value["oldest_pending_at"] is not None:
        value["oldest_pending_at"] = _normalize_time(value["oldest_pending_at"])
    _heartbeat(value)
    data = _canonical(value)
    return from_stored(data, _digest(data), kind="heartbeat")


def parse_heartbeat(body, expected_channel):
    _channel(expected_channel, _EVENT_CHANNEL)
    value = _read(body, MAX_MESSAGE_BYTES)
    _heartbeat(value)
    _match(value, expected_channel)
    return ParsedMessage(value, body, _digest(body))


def alert_request(inbox_id, destination_id, frozen):
    _identifier(inbox_id)
    _identifier(destination_id)
    data = _canonical({"v": VERSION, "inbox_id": inbox_id, "destination_id": destination_id,
                       "payload": _encoded_payload(frozen, "alert"), "sha256": frozen.sha256})
    _require(len(data) <= MAX_ENVELOPE_BYTES, "bounds")
    return data


def parse_alert_request(body, expected_channel):
    _channel(expected_channel, _ALERT_CHANNEL)
    value = _read(body, MAX_ENVELOPE_BYTES)
    _shape(value, _ALERT_REQUEST)
    _version(value["v"])
    _identifier(value["inbox_id"])
    _identifier(value["destination_id"])
    frozen = _decoded_payload(value, "alert")
    decoded = _payload(frozen.data, frozen.sha256, "alert")
    _match({"inbox_id": value["inbox_id"], "destination_id": value["destination_id"],
            "collector_id": decoded["collector_id"]}, expected_channel)
    return ParsedMessage(value, body, _digest(body), frozen, decoded)


def _receipt(value, kind):
    keys = {"event": _EVENT_RECEIPT, "heartbeat": _HEARTBEAT_RECEIPT, "inbox": _INBOX_RECEIPT}[kind]
    _shape(value, keys)
    _version(value["v"])
    for key in keys - {"v", "sequence", "number", "received_at", "sha256"}:
        _identifier(value[key])
    _identifier(value["sha256"], hashed=True)
    _timestamp(value["received_at"])
    if kind != "event":
        _integer(value["sequence" if kind == "heartbeat" else "number"], positive=True)


def _make_receipt(fields, kind):
    _require(type(fields) is dict)
    value = dict(fields)
    _require("received_at" in value)
    value["received_at"] = _normalize_time(value["received_at"])
    _receipt(value, kind)
    data = _canonical(value)
    _require(len(data) <= MAX_MESSAGE_BYTES, "bounds")
    return data


def _parse_receipt(body, expected, kind):
    keys = {"event": _EVENT_RECEIPT, "heartbeat": _HEARTBEAT_RECEIPT, "inbox": _INBOX_RECEIPT}[kind]
    _shape(expected, keys - {"v", "receipt_id", "received_at"})
    for key, value in expected.items():
        if key in {"number", "sequence"}:
            _integer(value, positive=True)
        else:
            _identifier(value, hashed=key == "sha256")
    value = _read(body, MAX_MESSAGE_BYTES)
    _receipt(value, kind)
    _match(value, expected)
    return ParsedMessage(value, body, _digest(body))


def event_receipt(fields):
    return _make_receipt(fields, "event")


def parse_event_receipt(body, expected_delivery):
    return _parse_receipt(body, expected_delivery, "event")


def heartbeat_receipt(fields):
    return _make_receipt(fields, "heartbeat")


def parse_heartbeat_receipt(body, expected_heartbeat):
    return _parse_receipt(body, expected_heartbeat, "heartbeat")


def inbox_receipt(fields):
    return _make_receipt(fields, "inbox")


def parse_inbox_receipt(body, expected_delivery):
    return _parse_receipt(body, expected_delivery, "inbox")
