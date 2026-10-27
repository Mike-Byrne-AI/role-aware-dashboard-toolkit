"""Transactional posting budgets and capacity for the private team board."""

import hashlib
import hmac
import math
import time

from fastapi import HTTPException

MESSAGE_MINUTE_LIMIT = 10
MESSAGE_HOUR_LIMIT = 100
MESSAGE_CAPACITY = 10_000


def current_time():
    """Keep the quota clock independently controllable in regression tests."""
    return time.time()


def _key(database, user_id, window_seconds):
    subject = f"team-message:{window_seconds}:{user_id}".encode()
    return hmac.new(database.identity_key, subject, hashlib.sha256).hexdigest()


def enforce_message_limits(connection, database, user_id, *, metrics=None):
    """Charge an accepted post in its authorized write transaction.

    Call after resolving an idempotent replay, and before inserting the message.
    The caller must roll back this transaction if the write or audit fails.
    These fixed windows persist across sessions, app instances, and restarts.
    No history is deleted when the board reaches its configured row capacity.
    """
    count = connection.execute(
        "SELECT COUNT(*) FROM (SELECT 1 FROM messages LIMIT ?)", (MESSAGE_CAPACITY,),
    ).fetchone()[0]
    if count >= MESSAGE_CAPACITY:
        if metrics is not None:
            metrics.record("message_capacity_denied")
        raise HTTPException(
            507,
            "Team message storage is full. An operator must back up and remove "
            "selected old messages, or review the configured capacity, before posting resumes.",
        )

    now = current_time()
    windows, retry_after = [], 0
    for seconds, limit in ((60, MESSAGE_MINUTE_LIMIT), (3600, MESSAGE_HOUR_LIMIT)):
        key = _key(database, user_id, seconds)
        row = connection.execute(
            "SELECT window_start,attempts FROM login_limits WHERE key_hash=?", (key,),
        ).fetchone()
        if row and row["window_start"] > now - seconds:
            started, count = row["window_start"], row["attempts"]
        else:
            started, count = now, 0
        if count >= limit:
            retry_after = max(retry_after, math.ceil(started + seconds - now))
        windows.append((key, started, count + 1))
    if retry_after:
        if metrics is not None:
            metrics.record("message_quota_denied")
        raise HTTPException(
            429, "Your team message posting limit has been reached. Please wait before posting again.",
            headers={"Retry-After": str(max(1, retry_after))},
        )
    connection.executemany(
        "INSERT INTO login_limits VALUES(?,?,?) ON CONFLICT(key_hash) DO UPDATE "
        "SET window_start=excluded.window_start,attempts=excluded.attempts", windows,
    )
