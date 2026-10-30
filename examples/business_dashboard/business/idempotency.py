"""Bounded, transactional receipts for authenticated create retries.

Call only after current authentication, CSRF, permission and freeze checks. A
receipt shares the mutation's transaction, so an uncertain response can be
retried without repeating the mutation or consuming a second posting quota.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import sqlite3
import time

from fastapi import HTTPException

RECEIPT_SECONDS = 24 * 60 * 60
MAX_RECEIPTS_PER_USER = 512
MAX_RECEIPTS = 4096
MAX_RESPONSE_BYTES = 32 * 1024
_KEY = re.compile(r"[A-Za-z0-9_-]{16,128}\Z", re.ASCII)


@dataclass
class CreateReceipt:
    """One authorized operation inside its caller's SQLite transaction."""

    connection: sqlite3.Connection
    user_id: str
    endpoint: str
    key_hash: str | None
    request_hash: str
    created_at: float
    replay: dict | None = None

    def remember(self, response: dict) -> dict:
        if self.key_hash is None:
            return response
        if not self.connection.in_transaction or self.replay is not None:
            raise RuntimeError("A create receipt requires its original write transaction.")
        encoded = json.dumps(response, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_RESPONSE_BYTES:
            # Raising before commit also rolls back the corresponding mutation.
            raise sqlite3.DataError("Create response exceeds its receipt limit.")
        self.connection.execute(
            "INSERT INTO create_receipts(user_id,endpoint,key_hash,request_hash,response_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (self.user_id, self.endpoint, self.key_hash, self.request_hash, encoded, self.created_at),
        )
        return response


def reserve_create(connection, request, user_id: str, payload, *, endpoint: str) -> CreateReceipt:
    """Find an exact retry or reserve room, without committing independently.

    The caller holds BEGIN IMMEDIATE and rechecks authorization before calling.
    Keys are scoped to the current account and fixed route; the normalized
    request fingerprint detects accidental key reuse with different content.
    Only successful writes create receipts. Replay is available for 24 hours;
    expired snapshots are pruned on the next keyed write. Unexpired receipts
    are never evicted for capacity.
    """
    if not connection.in_transaction:
        raise RuntimeError("Create receipts require an authorized write transaction.")
    keys = request.headers.getlist("idempotency-key")
    if not keys:
        return CreateReceipt(connection, user_id, endpoint, None, "", 0)
    if len(keys) != 1 or _KEY.fullmatch(keys[0]) is None:
        raise HTTPException(422, "Use one valid Idempotency-Key for this save.")
    key_hash = hashlib.sha256(keys[0].encode("ascii")).hexdigest()
    normalized = json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False)
    request_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    now = time.time()
    connection.execute("DELETE FROM create_receipts WHERE created_at<=?", (now - RECEIPT_SECONDS,))
    row = connection.execute(
        "SELECT request_hash,response_json FROM create_receipts WHERE user_id=? AND endpoint=? AND key_hash=?",
        (user_id, endpoint, key_hash),
    ).fetchone()
    receipt = CreateReceipt(connection, user_id, endpoint, key_hash, request_hash, now)
    if row is not None:
        if row["request_hash"] != request_hash:
            raise HTTPException(409, "This save key belongs to different content. Check saved records before starting a new save.")
        try:
            if len(row["response_json"].encode("utf-8")) > MAX_RESPONSE_BYTES:
                raise ValueError
            receipt.replay = json.loads(row["response_json"])
            if not isinstance(receipt.replay, dict):
                raise ValueError
        except (AttributeError, TypeError, ValueError, RecursionError):
            # Never turn an unreadable existing receipt into another creation.
            raise sqlite3.DataError("Stored create receipt is invalid.") from None
        return receipt
    total = connection.execute("SELECT COUNT(*) FROM create_receipts").fetchone()[0]
    own = connection.execute("SELECT COUNT(*) FROM create_receipts WHERE user_id=?", (user_id,)).fetchone()[0]
    if total >= MAX_RECEIPTS or own >= MAX_RECEIPTS_PER_USER:
        raise HTTPException(503, "Safe retry storage is busy. Keep this save open and try again later.",
                            headers={"Retry-After": "60"})
    return receipt
