"""Bounded durable security events and a transactional delivery obligation.

An event and its outbox row must share the business mutation's transaction.
Delivery is at least once: a crash after delivery but before acknowledgement
can repeat it. Consumers must deduplicate the stable event ID. The supplied
consumer is a private local SQLite receipt table; nothing leaves this host.
This is operational evidence, not a tamper-proof log or an external archive.
"""

from __future__ import annotations

import json
import logging
import math
import re
import secrets
import sqlite3
import time
from threading import Lock

LOGGER = logging.getLogger(__name__)
MAX_EVENTS = 10000
MAX_AGE_SECONDS = 30 * 86400
DENIALS_PER_MINUTE = 20
MAX_DENIAL_EVENTS = 1000
MAX_COUNTER = 2**63 - 1
MAX_EVENT_SEQUENCE = 2**63 - 1
CONTAINMENT_CODES = frozenset({
    "login_succeeded", "identity_verified", "editing_paused", "account_disabled",
    "session_revoked", "passkey_removed", "session_logged_out",
})
CODES = frozenset({
    "login_succeeded", "password_changed", "identity_verified", "session_revoked",
    "session_logged_out", "passkey_registered", "passkey_removed", "editing_paused",
    "editing_resumed", "account_enabled", "account_disabled", "mfa_key_rotated",
    "authentication_denied", "authorization_denied", "request_denied",
})
REASONS = frozenset({
    "completed", "unauthenticated", "forbidden", "conflict", "throttled",
    "invalid_request", "unavailable",
})
METHODS = frozenset({"none", "password", "totp", "passkey"})
_PRINCIPAL = re.compile(r"[0-9a-f]{64}\Z")


class EventCapacityError(sqlite3.OperationalError):
    """Required audit obligations filled their bounded private storage."""


def _containment_reserve():
    # Default: 10% of 10,000 events. Small test configurations need enough
    # room to reauthenticate, disable an abusive account and pause editing.
    return min(max(0, MAX_EVENTS - 1), max(3, MAX_EVENTS // 10))


def _normal_capacity():
    return MAX_EVENTS - _containment_reserve()


def _can_use_containment_reserve(connection, code, outcome, actor):
    # Actor comes from the host's verified auth context, never a request label.
    # Recheck current active administrator status inside the mutation's own
    # transaction; a role snapshot or a caller-supplied priority cannot qualify.
    return outcome == "succeeded" and code in CONTAINMENT_CODES and actor is not None and connection.execute(
        "SELECT 1 FROM users WHERE principal=? AND role='admin' AND active=1", (actor,),
    ).fetchone() is not None


def _trim(connection, now, capacity):
    # Never erase an undelivered obligation to make an operation appear audited.
    connection.execute(
        "DELETE FROM security_events WHERE id IN (SELECT e.id FROM security_events e "
        "JOIN security_outbox o ON o.event_id=e.id WHERE o.delivered_at IS NOT NULL "
        "AND e.occurred_at<?)", (now - MAX_AGE_SECONDS,),
    )
    count = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
    if count >= capacity:
        connection.execute(
            "DELETE FROM security_events WHERE id IN (SELECT e.id FROM security_events e "
            "JOIN security_outbox o ON o.event_id=e.id WHERE o.delivered_at IS NOT NULL "
            "ORDER BY e.sequence LIMIT ?)", (count - capacity + 1,),
        )
    if connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] >= capacity:
        raise EventCapacityError("Security event capacity is full; deliver pending obligations before retrying.")


def record_event(connection, code, *, outcome="succeeded", reason="completed", actor=None,
                 target=None, method="none", now=None):
    """Require a trusted transaction; accept fixed codes and opaque principals only.

    This function deliberately propagates failures: the associated sensitive
    mutation must roll back when its required event cannot be committed.
    """
    if not connection.in_transaction:
        raise ValueError("Security events require the action transaction.")
    if (code not in CODES or outcome not in {"succeeded", "denied"} or reason not in REASONS
            or method not in METHODS or (outcome == "succeeded") != (reason == "completed")
            or any(value is not None and (not isinstance(value, str) or not _PRINCIPAL.fullmatch(value))
                   for value in (actor, target))):
        raise ValueError("Unsupported structured security event.")
    now = time.time() if now is None else now
    if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
        raise ValueError("Invalid security event time.")
    capacity = MAX_EVENTS if _can_use_containment_reserve(connection, code, outcome, actor) else _normal_capacity()
    _trim(connection, now, capacity)
    identifier = secrets.token_hex(16)
    connection.execute(
        "INSERT INTO security_events(id,occurred_at,code,outcome,reason,actor,target,method) "
        "VALUES(?,?,?,?,?,?,?,?)", (identifier, now, code, outcome, reason, actor, target, method),
    )
    connection.execute("INSERT INTO security_outbox(event_id) VALUES(?)", (identifier,))
    return identifier


def delivery_status(connection):
    row = connection.execute(
        "SELECT SUM(delivered_at IS NULL),SUM(delivered_at IS NULL AND last_error IS NOT NULL),"
        "SUM(delivered_at IS NOT NULL) FROM security_outbox"
    ).fetchone()
    return {"pending": row[0] or 0, "failed": row[1] or 0, "delivered": row[2] or 0,
            "semantics": "at_least_once_idempotent_local_consumer"}


def _denial_capacity():
    # Anonymous observations must not consume the capacity reserved for login,
    # session revocation, emergency freeze and other required action receipts.
    return min(MAX_DENIAL_EVENTS, MAX_EVENTS // 4)


def _admit_denial(connection):
    limit = _denial_capacity()
    if limit < 1:
        return False
    count = connection.execute("SELECT COUNT(*) FROM security_events WHERE outcome='denied'").fetchone()[0]
    if count >= limit:
        connection.execute(
            "DELETE FROM security_events WHERE id IN (SELECT e.id FROM security_events e "
            "JOIN security_outbox o ON o.event_id=e.id WHERE e.outcome='denied' AND o.delivered_at IS NOT NULL "
            "ORDER BY e.sequence LIMIT ?)", (count - limit + 1,),
        )
    return connection.execute("SELECT COUNT(*) FROM security_events WHERE outcome='denied'").fetchone()[0] < limit


def timeline(connection, *, limit=50, before=None):
    if type(limit) is not int or not 1 <= limit <= 100 or (
        before is not None and (type(before) is not int or not 1 <= before <= MAX_EVENT_SEQUENCE)
    ):
        raise ValueError("Invalid event page.")
    rows = connection.execute(
        "SELECT e.*,CASE WHEN o.delivered_at IS NULL THEN 'pending' ELSE 'delivered' END AS delivery,"
        "o.attempts FROM security_events e JOIN security_outbox o ON o.event_id=e.id "
        "WHERE (? IS NULL OR e.sequence<?) ORDER BY e.sequence DESC LIMIT ?", (before, before, limit + 1),
    ).fetchall()
    visible = [dict(row) for row in rows[:limit]]
    return {"events": visible, "next_before": visible[-1]["sequence"] if len(rows) > limit else None,
            "delivery": delivery_status(connection),
            "retention": {"max_events": MAX_EVENTS, "max_age_days": MAX_AGE_SECONDS // 86400,
                          "max_denial_events": _denial_capacity(),
                          "normal_event_capacity": _normal_capacity(),
                          "containment_reserve": _containment_reserve(),
                          "reserve_eligibility": "current_active_admin_containment_only",
                          "pending_events_preserved": True}}


def consume_local(connection, event):
    """Idempotent local consumer; payloads originate only from the event table."""
    encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
    connection.execute(
        "INSERT OR IGNORE INTO security_sink_receipts VALUES(?,?,?)",
        (event["id"], time.time(), encoded),
    )
    existing = connection.execute(
        "SELECT payload_json FROM security_sink_receipts WHERE event_id=?", (event["id"],),
    ).fetchone()
    if existing[0] != encoded:
        raise ValueError("Security event identity does not match its delivered payload.")


def dispatch_pending(database, *, limit=50, deliver=None, after_delivery=None, transaction_factory=None):
    """Bounded delivery with durable retries and no automatic business replay.

    `deliver` is a trusted injectable consumer for local fault tests. No network
    adapter is configured. `after_delivery` permits a deliberate crash before
    acknowledgment in disposable tests. Concurrent dispatchers may redeliver;
    stable IDs and idempotent consumers are required, never exactly-once claims.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Invalid delivery limit.")
    transaction = transaction_factory or database.transaction
    snapshot = transaction_factory or database.readonly_snapshot
    with snapshot() as connection:
        rows = connection.execute(
            "SELECT e.* FROM security_events e JOIN security_outbox o ON o.event_id=e.id "
            "WHERE o.delivered_at IS NULL AND o.next_attempt_at<=? ORDER BY e.sequence LIMIT ?",
            (time.time(), limit),
        ).fetchall()
    delivered = failed = 0
    for row in rows:
        event = dict(row)
        with transaction() as connection:
            pending = connection.execute(
                "UPDATE security_outbox SET attempts=MIN(attempts+1,?) WHERE event_id=? AND delivered_at IS NULL",
                (MAX_COUNTER, event["id"]),
            ).rowcount
        if not pending:
            continue
        try:
            if deliver is None:
                with transaction() as connection:
                    consume_local(connection, event)
            else:
                deliver(event)
        except Exception as error:
            # HTTP callers reauthorize each delivery transaction. A revoked
            # caller must retain its refusal, never become a successful batch.
            from fastapi import HTTPException
            if isinstance(error, HTTPException):
                raise
            # No adapter text, credentials or submitted data enters diagnostics.
            LOGGER.error("Security event delivery failed; its durable obligation remains pending.")
            with transaction() as connection:
                connection.execute(
                    "UPDATE security_outbox SET last_error='delivery_failed',next_attempt_at=? "
                    "WHERE event_id=? AND delivered_at IS NULL", (time.time() + 30, event["id"]),
                )
            failed += 1
            continue
        if after_delivery is not None:
            after_delivery(event)
        with transaction() as connection:
            connection.execute(
                "UPDATE security_outbox SET delivered_at=?,last_error=NULL WHERE event_id=? AND delivered_at IS NULL",
                (time.time(), event["id"]),
            )
        delivered += 1
    with snapshot() as connection:
        pending = delivery_status(connection)["pending"]
    return {"delivered": delivered, "failed": failed, "pending": pending}


class DenialRecorder:
    """Fixed global admission before any database work; no attacker label keys.

    Denials are observations, never required mutation receipts. Recording errors
    preserve the original refusal and remain visible through protected counters
    and server logging. Durable admission survives process restart.
    """

    def __init__(self, database):
        self.database = database
        self._lock = Lock()
        self._window = -1
        self._admitted = 0
        self._suppressed = 0
        self._failures = 0

    def snapshot(self):
        with self._lock:
            return {"denials_suppressed_since_start": self._suppressed,
                    "recording_failures_since_start": self._failures, "resets_on_restart": True}

    def record(self, code, reason, *, actor=None):
        now = time.time()
        window = int(now // 60)
        with self._lock:
            if window != self._window:
                self._window, self._admitted = window, 0
            if self._admitted >= DENIALS_PER_MINUTE:
                self._suppressed = min(MAX_COUNTER, self._suppressed + 1)
                return
            self._admitted += 1
        try:
            with self.database.transaction() as connection:
                budget = connection.execute("SELECT window,admitted FROM security_denial_budget WHERE id=1").fetchone()
                if budget and budget[0] == window and budget[1] >= DENIALS_PER_MINUTE:
                    with self._lock:
                        self._suppressed = min(MAX_COUNTER, self._suppressed + 1)
                    return
                if not _admit_denial(connection):
                    with self._lock:
                        self._suppressed = min(MAX_COUNTER, self._suppressed + 1)
                    return
                connection.execute(
                    "INSERT INTO security_denial_budget VALUES(1,?,1) ON CONFLICT(id) DO UPDATE SET "
                    "admitted=CASE WHEN window=excluded.window THEN admitted+1 ELSE 1 END,window=excluded.window",
                    (window,),
                )
                record_event(connection, code, outcome="denied", reason=reason, actor=actor, now=now)
        except EventCapacityError:
            # Expected load shedding at the normal watermark protects narrow
            # administrator containment operations; it is not a storage fault.
            with self._lock:
                self._suppressed = min(MAX_COUNTER, self._suppressed + 1)
        except Exception:
            with self._lock:
                self._failures = min(MAX_COUNTER, self._failures + 1)
            LOGGER.error("Security denial observation could not be persisted; original refusal retained.")


class SecurityEventMiddleware:
    """Observe HTTP refusals after route transactions have committed or rolled back."""

    def __init__(self, app, *, recorder):
        self.app, self.recorder = app, recorder

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/"):
            return await self.app(scope, receive, send)
        status = None

        async def observed(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        await self.app(scope, receive, observed)
        reasons = {401: "unauthenticated", 403: "forbidden", 409: "conflict", 415: "invalid_request",
                   422: "invalid_request", 429: "throttled", 503: "unavailable"}
        if status in reasons:
            from starlette.concurrency import run_in_threadpool
            path = scope.get("path", "")
            code = ("authentication_denied" if path in {"/api/login", "/api/password", "/api/security/reauthenticate"}
                    or path.startswith(("/api/security/passkeys/", "/api/passkeys/login/")) else
                    "authorization_denied" if status in {401, 403} else "request_denied")
            await run_in_threadpool(self.recorder.record, code, reasons[status], actor=scope.get("security_actor"))
