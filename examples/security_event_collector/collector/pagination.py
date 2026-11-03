"""Bounded operator cursors identify retained anchors, never client timestamps."""

import base64
import binascii
import json
import re

from .storage import ID, ServiceError, safe_json

MAX_CURSOR_BYTES = 256
_ENCODED = re.compile(r"[A-Za-z0-9_-]+\Z")


def _invalid():
    return ServiceError("invalid_message", 400)


def page_limit(value):
    if type(value) is not int or not 1 <= value <= 100:
        raise _invalid()
    return value


def parse_query(raw):
    """Only canonical ASCII limit/cursor values; no aliases or duplicate keys."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CURSOR_BYTES + 32:
        raise _invalid()
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise _invalid() from None
    result = {}
    for part in text.split("&"):
        key, separator, value = part.partition("=")
        if not separator or key not in {"limit", "cursor"} or key in result:
            raise _invalid()
        if key == "limit":
            if re.fullmatch(r"[1-9][0-9]{0,2}", value) is None:
                raise _invalid()
            value = page_limit(int(value))
        elif len(value) > MAX_CURSOR_BYTES or _ENCODED.fullmatch(value) is None:
            raise _invalid()
        result[key] = value
    return result


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _invalid()
        result[key] = value
    return result


def encode_cursor(kind, row):
    fields = {"v": 1, "kind": kind}
    fields.update({"id": row["id"]} if kind == "alerts" else {
        "collector_id": row["collector_id"], "alert_id": row["alert_id"], "number": row["number"],
    })
    return base64.urlsafe_b64encode(safe_json(fields)).rstrip(b"=").decode("ascii")


def decode_cursor(cursor, kind):
    if cursor is None:
        return None
    if (not isinstance(cursor, str) or not 1 <= len(cursor) <= MAX_CURSOR_BYTES
            or _ENCODED.fullmatch(cursor) is None):
        raise _invalid()
    try:
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        fields = json.loads(raw.decode("ascii"), object_pairs_hook=_object)
        expected = {"v", "kind", "id"} if kind == "alerts" else {"v", "kind", "collector_id", "alert_id", "number"}
        if (type(fields) is not dict or set(fields) != expected or type(fields["v"]) is not int
                or fields["v"] != 1 or fields["kind"] != kind or safe_json(fields) != raw):
            raise _invalid()
        for key in ("id",) if kind == "alerts" else ("collector_id", "alert_id"):
            if not isinstance(fields[key], str) or ID.fullmatch(fields[key]) is None:
                raise _invalid()
        if kind == "messages" and (type(fields["number"]) is not int or not 1 <= fields["number"] <= 2**63 - 1):
            raise _invalid()
        if encode_cursor(kind, fields) != cursor:
            raise _invalid()
        return fields
    except (ValueError, UnicodeError, RecursionError, binascii.Error):
        raise _invalid() from None


def page(rows, limit, kind):
    visible = rows[:limit]
    return {kind: visible, "next_cursor": encode_cursor(kind, visible[-1]) if len(rows) > limit else None}
