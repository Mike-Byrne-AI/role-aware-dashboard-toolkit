"""Bound verification work and persist attempt budgets before contacting a provider."""

import hashlib
import hmac
import logging
import secrets
import time

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .db import utc_now
from .models import Submission
from .security import TransactionAccessStore
from .work_limits import BoundedWork

LOGGER = logging.getLogger(__name__)
ATTEMPT_WINDOW_SECONDS = 60
PEER_ATTEMPT_LIMIT = 10
GLOBAL_ATTEMPT_LIMIT = 30
VERIFICATION_CAPACITY = 4
ATTEMPT_PREFIX = "submission-attempt:"


def current_time():
    """An isolated clock lets tests exercise expiry without delaying the suite."""
    return time.time()


def _check_submission_admission(connection, address, now):
    if TransactionAccessStore(connection).read_freeze().frozen:
        raise HTTPException(503, "Public submissions are temporarily paused. Please try again later.")
    address_count = connection.execute(
        "SELECT COUNT(*) FROM submission_limits WHERE key_hash=? AND submitted_at>?", (address, now - 600),
    ).fetchone()[0]
    global_count = connection.execute(
        "SELECT COUNT(*) FROM submission_limits WHERE submitted_at>?", (now - 3600,),
    ).fetchone()[0]
    pending = connection.execute("SELECT COUNT(*) FROM submissions WHERE status='pending'").fetchone()[0]
    if address_count >= 3 or global_count >= 30 or pending >= 100:
        raise HTTPException(
            429, "Submissions are temporarily limited. Please try again later.", headers={"Retry-After": "600"},
        )


def _reserve_verification(connection, address, now):
    """Reserve all budgets atomically; the caller commits before doing any I/O."""
    # This namespace alone is pruned. Authentication budgets can have different
    # windows, and arbitrary peer cardinality cannot grow this table indefinitely.
    connection.execute(
        "DELETE FROM login_limits WHERE key_hash LIKE ? AND window_start<=?",
        (ATTEMPT_PREFIX + "%", now - ATTEMPT_WINDOW_SECONDS),
    )
    budgets = (
        (ATTEMPT_PREFIX + "global", GLOBAL_ATTEMPT_LIMIT),
        (ATTEMPT_PREFIX + address, PEER_ATTEMPT_LIMIT),
    )
    for key, limit in budgets:
        row = connection.execute("SELECT attempts FROM login_limits WHERE key_hash=?", (key,)).fetchone()
        if row and row["attempts"] >= limit:
            return False
    for key, limit in budgets:
        connection.execute(
            "INSERT INTO login_limits VALUES(?,?,1) ON CONFLICT(key_hash) DO UPDATE SET attempts=attempts+1",
            (key, now),
        )
        attempts = connection.execute("SELECT attempts FROM login_limits WHERE key_hash=?", (key,)).fetchone()[0]
        if attempts == limit:
            # One fixed event per exhausted budget/window, never per rejected
            # request. No peer address, submitted text, token, or key is logged.
            LOGGER.warning("Public verification attempt budget reached.")
    return True


def install_submission_routes(app, database, submission_guard):
    work = BoundedWork(VERIFICATION_CAPACITY, label="Public verification")

    def submit(payload, request):
        remote = request.client.host if request.client else "unknown"
        submission_guard.validate_policy(payload.rules_version, payload.accept_rules)
        address = hmac.new(
            database.identity_key, b"guest-submission\0" + remote.encode(), hashlib.sha256,
        ).hexdigest()
        with database.transaction() as connection:
            now = current_time()
            _check_submission_admission(connection, address, now)
            if not _reserve_verification(connection, address, now):
                return JSONResponse(
                    {"detail": "Verification attempts are temporarily limited. Please try again later."},
                    status_code=429, headers={"Retry-After": str(ATTEMPT_WINDOW_SECONDS)},
                )
        # The reservation is already committed. Rejections, timeouts, and worker
        # cancellation cannot roll it back. No database lock spans the network.
        submission_guard.verify(payload.turnstile_token, remote)
        with database.transaction() as connection:
            now = current_time()
            _check_submission_admission(connection, address, now)
            connection.execute("DELETE FROM submission_limits WHERE submitted_at<=?", (now - 3600,))
            connection.execute(
                "INSERT INTO submissions VALUES(?,?,?,'pending',?,0,NULL)",
                (secrets.token_hex(12), payload.title, payload.body, utc_now()),
            )
            connection.execute("INSERT INTO submission_limits(key_hash,submitted_at) VALUES(?,?)", (address, now))
        return {"submitted": True}

    @app.post("/api/public/submissions", status_code=202)
    async def add_submission(payload: Submission, request: Request):
        # Every blocking phase, including SQLite waits, uses dedicated bounded
        # worker capacity. Health and authenticated routes keep their own workers.
        return await work.run(submit, payload, request)
