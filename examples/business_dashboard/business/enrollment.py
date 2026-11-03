"""Purpose-bound account enrollment and explicit legacy-to-MFA policy cutover."""

from dataclasses import dataclass, field
import hashlib
import hmac
import math
import re
import secrets
import time

import pyotp

from .db import record_activity
from .password_policy import password_policy_error
from .security_events import record_event

GRANT_SECONDS = 24 * 60 * 60
ENROLLMENT_SECONDS = 10 * 60
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_CASE = re.compile(r"[A-Za-z0-9._:-]{1,80}\Z")


class EnrollmentError(ValueError):
    """A bounded operator/user-safe error; never includes submitted secrets."""

    def __init__(self, detail, *, status_code=403, retry_after=None):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.retry_after = retry_after


@dataclass(frozen=True)
class EnrollmentStart:
    token: str = field(repr=False)
    csrf: str = field(repr=False)
    secret: str = field(repr=False)
    uri: str = field(repr=False)
    expires_at: float
    username: str


def current_time():
    return time.time()


def _now(value=None):
    value = current_time() if value is None else value
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("Enrollment requires a finite current timestamp.")
    return value


def _transaction(connection):
    if not connection.in_transaction:
        raise ValueError("Account security changes require an active transaction.")


def _invalid():
    return EnrollmentError("The enrollment details are unavailable or expired. Request a new enrollment from the operator.")


def _limited():
    return EnrollmentError("Too many enrollment attempts. Please wait five minutes.", status_code=429, retry_after=300)


def _hash(value, purpose):
    return hashlib.sha256(("westbridge:enrollment:" + purpose + "\0" + value).encode("ascii")).hexdigest()


def _valid_token(value):
    return isinstance(value, str) and _TOKEN.fullmatch(value) is not None


def enrollment_csrf(token, identity_key):
    if not _valid_token(token):
        raise _invalid()
    return hmac.new(identity_key, ("westbridge:enrollment-csrf:v1\0" + token).encode("ascii"), hashlib.sha256).hexdigest()


def _within(row, now, lifetime):
    values = (row["created_at"], row["expires_at"])
    return all(type(value) in (int, float) and math.isfinite(value) and value >= 0 for value in values) and (
        row["created_at"] <= now < row["expires_at"] <= row["created_at"] + lifetime
    )


def _policy(connection):
    row = connection.execute("SELECT * FROM authentication_policy WHERE id=1").fetchone()
    if row is None or row["mode"] not in {"transition", "strict"}:
        raise ValueError("Account authentication policy is missing or invalid.")
    return row


def account_can_authenticate(connection, user):
    """Lifecycle gate only; callers must still verify actual factors and grants."""
    mode = _policy(connection)["mode"]
    if user is None or user["active"] != 1 or user["role"] not in {"admin", "employee"}:
        return False
    row = connection.execute("SELECT lifecycle FROM account_security WHERE user_id=?", (user["id"],)).fetchone()
    return row is not None and (row["lifecycle"] == "active" or (
        row["lifecycle"] == "legacy" and mode == "transition"
    ))


def requires_mfa(connection, user):
    mode = _policy(connection)["mode"]
    row = connection.execute("SELECT lifecycle FROM account_security WHERE user_id=?", (user["id"],)).fetchone()
    return user["role"] == "admin" or row is None or row["lifecycle"] != "legacy" or mode == "strict"


def _revoke_sessions(connection, user_id):
    connection.execute(
        "DELETE FROM session_predecessors WHERE public_id IN (SELECT v.public_id FROM session_security v "
        "JOIN sessions s ON s.token_hash=v.token_hash WHERE s.user_id=?)", (user_id,),
    )
    connection.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    connection.execute("DELETE FROM passkey_challenges WHERE user_id=?", (user_id,))


def issue_grant(connection, user_id, *, purpose, case_reference=None, now=None):
    """Trusted offline/provisioning action; return the raw grant only once.

    A recovery case reference records the operator's external identity-proofing
    decision. It is not itself identity proof and must contain no personal data.
    """
    _transaction(connection)
    now = _now(now)
    if purpose not in {"initial", "migration", "recovery"}:
        raise ValueError("Choose an initial, migration, or recovery enrollment.")
    if (case_reference is not None and (not isinstance(case_reference, str) or _CASE.fullmatch(case_reference) is None)
            or purpose == "recovery" and case_reference is None):
        raise ValueError("Recovery requires an opaque case reference of 1 to 80 letters, digits, dots, colons, underscores or hyphens.")
    user = connection.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if user is None:
        raise ValueError("The enrollment account does not exist.")
    security = connection.execute("SELECT * FROM account_security WHERE user_id=?", (user_id,)).fetchone()
    mode = _policy(connection)["mode"]
    if purpose == "migration" and (security is None or security["lifecycle"] != "legacy" or mode != "transition"):
        raise ValueError("Migration enrollment is only available for legacy accounts during transition.")
    if purpose == "initial" and security is not None and (security["lifecycle"] != "pending" or security["completed_at"] is not None):
        raise ValueError("Initial enrollment cannot replace an existing account's credentials.")
    if purpose == "initial" and connection.execute(
        "SELECT 1 FROM enrollment_decisions WHERE user_id=? AND purpose<>'initial' LIMIT 1", (user_id,),
    ).fetchone():
        raise ValueError("An existing account requires its reviewed migration or recovery enrollment.")
    lifecycle = "legacy" if purpose == "migration" else "pending"
    revision = security["revision"] + 1 if security else 0
    retired = None
    if purpose == "recovery":
        retired = (security["retired_password_hash"] if security else None) or (
            user["password_hash"] if not user["password_hash"].startswith("!") else None
        )
    connection.execute(
        "INSERT INTO account_security VALUES(?,?,?,NULL,?) ON CONFLICT(user_id) DO UPDATE SET "
        "lifecycle=excluded.lifecycle,revision=excluded.revision,completed_at=NULL,retired_password_hash=excluded.retired_password_hash",
        (user_id, lifecycle, revision, retired),
    )
    connection.execute("UPDATE users SET revision=revision+1 WHERE id=?", (user_id,))
    if purpose != "migration":
        _revoke_sessions(connection, user_id)
        connection.execute("UPDATE users SET password_hash='!enrollment-pending!' WHERE id=?", (user_id,))
        connection.execute("DELETE FROM account_mfa WHERE user_id=?", (user_id,))
        connection.execute("DELETE FROM passkey_credentials WHERE user_id=?", (user_id,))
    connection.execute("DELETE FROM enrollment_sessions WHERE user_id=?", (user_id,))
    connection.execute("DELETE FROM enrollment_grants WHERE user_id=?", (user_id,))
    grant = secrets.token_urlsafe(32)
    connection.execute("INSERT INTO enrollment_grants VALUES(?,?,?,?,?,?,?,NULL,?)", (
        user_id, _hash(grant, "grant"), purpose, user["revision"] + 1, revision, now, now + GRANT_SECONDS, case_reference,
    ))
    event = record_event(connection, "enrollment_issued", target=user["principal"], now=now)
    connection.execute("INSERT INTO enrollment_decisions VALUES(?,?,?,?,?)", (event, user_id, purpose, case_reference, now))
    return grant


def _budget(database, username=None, token=None):
    # These primitives are imported only when invoked, avoiding a route/module
    # import cycle while retaining the same durable 8-in-300 account budget.
    from .auth_routes import _limit_key, _reserve

    with database.transaction() as connection:
        if username is not None:
            user = connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        else:
            user = connection.execute(
                "SELECT u.* FROM users u JOIN enrollment_sessions e ON e.user_id=u.id WHERE e.token_hash=?",
                (_hash(token, "session"),),
            ).fetchone() if _valid_token(token) else None
        if user is None:
            return None, None, None
        key = _limit_key(database, "enrollment-start" if username is not None else "enrollment-complete", user["id"])
        reserved = _reserve(connection, key, _now())
        return dict(user), key, reserved


def start_enrollment(database, username, grant):
    from .auth_routes import _release_success, _reservation_valid

    username = username.casefold() if isinstance(username, str) else ""
    before, key, reserved = _budget(database, username=username)
    if before is None:
        raise _invalid()
    if reserved is None:
        raise _limited()
    # Rejection here rolls back only this action. Its earlier budget charge is
    # already committed, including if audit capacity or encryption later fails.
    with database.transaction() as connection:
        now = _now()
        mode = _policy(connection)["mode"]
        user = connection.execute("SELECT * FROM users WHERE id=?", (before["id"],)).fetchone()
        security = connection.execute("SELECT * FROM account_security WHERE user_id=?", (before["id"],)).fetchone()
        stored = connection.execute("SELECT * FROM enrollment_grants WHERE user_id=?", (before["id"],)).fetchone()
        if (user is None or user["active"] != 1 or user["username"] != username or security is None or stored is None
                or not _valid_token(grant) or not hmac.compare_digest(stored["secret_hash"], _hash(grant, "grant"))
                or stored["claimed_at"] is not None or not _within(stored, now, GRANT_SECONDS)
                or stored["user_revision"] != user["revision"] or stored["security_revision"] != security["revision"]
                or security["lifecycle"] not in {"pending", "legacy"}
                or (stored["purpose"] == "migration") != (security["lifecycle"] == "legacy")
                or (security["lifecycle"] == "legacy" and mode != "transition")):
            raise _invalid()
        if not _reservation_valid(connection, key, reserved, now):
            raise _limited()
        token, secret, generation = secrets.token_urlsafe(32), pyotp.random_base32(), secrets.token_hex(16)
        expires = min(now + ENROLLMENT_SECONDS, stored["expires_at"])
        ciphertext = database.mfa_secrets.encrypt(secret, "enrollment:" + user["id"], generation)
        connection.execute("UPDATE enrollment_grants SET claimed_at=? WHERE user_id=?", (now, user["id"]))
        connection.execute("DELETE FROM enrollment_sessions WHERE user_id=?", (user["id"],))
        connection.execute("INSERT INTO enrollment_sessions VALUES(?,?,?,?,?,?,?,?,?)", (
            _hash(token, "session"), user["id"], stored["secret_hash"], user["revision"], security["revision"],
            now, expires, ciphertext, generation,
        ))
        record_event(connection, "enrollment_started", target=user["principal"], now=now)
        _release_success(connection, key, reserved)
        result = EnrollmentStart(token, enrollment_csrf(token, database.identity_key), secret,
                                 pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Westbridge"), expires, username)
    return result


def _pending(connection, token, csrf, database, now):
    mode = _policy(connection)["mode"]
    if not _valid_token(token) or not isinstance(csrf, str) or not csrf.isascii() or not hmac.compare_digest(
        csrf, enrollment_csrf(token, database.identity_key)
    ):
        raise _invalid()
    pending = connection.execute("SELECT * FROM enrollment_sessions WHERE token_hash=?", (_hash(token, "session"),)).fetchone()
    user = connection.execute("SELECT * FROM users WHERE id=?", (pending["user_id"],)).fetchone() if pending else None
    security = connection.execute("SELECT * FROM account_security WHERE user_id=?", (pending["user_id"],)).fetchone() if pending else None
    grant = connection.execute("SELECT * FROM enrollment_grants WHERE user_id=?", (pending["user_id"],)).fetchone() if pending else None
    if (pending is None or user is None or security is None or user["active"] != 1
            or grant is None or grant["secret_hash"] != pending["grant_hash"]
            or type(grant["claimed_at"]) not in (int, float) or not math.isfinite(grant["claimed_at"])
            or grant["claimed_at"] != pending["created_at"] or not _within(grant, now, GRANT_SECONDS)
            or grant["user_revision"] != pending["user_revision"] or grant["security_revision"] != pending["security_revision"]
            or not _within(pending, now, ENROLLMENT_SECONDS) or pending["user_revision"] != user["revision"]
            or pending["security_revision"] != security["revision"] or security["lifecycle"] not in {"pending", "legacy"}
            or (grant["purpose"] == "migration") != (security["lifecycle"] == "legacy")
            or pending["expires_at"] > grant["expires_at"]
            or (security["lifecycle"] == "legacy" and mode != "transition")):
        raise _invalid()
    return pending, user


def complete_enrollment(database, token, csrf, new_password, otp):
    from .auth_routes import _release_success, _reservation_valid
    from .security import hash_password, verify_password

    before, key, reserved = _budget(database, token=token)
    if before is None:
        raise _invalid()
    if reserved is None:
        raise _limited()
    with database.transaction() as connection:
        pending, user = _pending(connection, token, csrf, database, _now())
        captured = dict(pending)
        retired = connection.execute("SELECT retired_password_hash FROM account_security WHERE user_id=?", (user["id"],)).fetchone()[0]
        previous_password = retired or user["password_hash"]
        if not isinstance(new_password, str):
            raise EnrollmentError("Use 15 to 128 characters for your new password.", status_code=422)
        if _valid_token(new_password) and hmac.compare_digest(_hash(new_password, "grant"), pending["grant_hash"]):
            raise EnrollmentError("Choose a new password distinct from your enrollment code.", status_code=422)
        policy_error = password_policy_error(new_password, username=user["username"], name=user["name"])
        if policy_error:
            raise EnrollmentError(policy_error, status_code=422)
    if verify_password(previous_password, new_password):
        raise EnrollmentError("Choose a new password distinct from your previous password.", status_code=422)
    replacement = hash_password(new_password)
    with database.transaction() as connection:
        now = _now()
        pending, user = _pending(connection, token, csrf, database, now)
        if dict(pending) != captured:
            raise _invalid()
        if not _reservation_valid(connection, key, reserved, now):
            raise _limited()
        if not isinstance(otp, str) or not re.fullmatch(r"[0-9]{6}", otp):
            raise _invalid()
        secret = database.mfa_secrets.decrypt(pending["secret_ciphertext"], "enrollment:" + user["id"], pending["generation"])
        counter = int(now // 30)
        if not pyotp.TOTP(secret).verify(otp, for_time=counter * 30):
            raise _invalid()
        generation = secrets.token_hex(16)
        ciphertext = database.mfa_secrets.encrypt(secret, user["id"], generation)
        _revoke_sessions(connection, user["id"])
        connection.execute("UPDATE users SET password_hash=?,revision=revision+1 WHERE id=?", (replacement, user["id"]))
        connection.execute(
            "INSERT INTO account_mfa VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
            "secret_ciphertext=excluded.secret_ciphertext,generation=excluded.generation,last_counter=excluded.last_counter",
            (user["id"], ciphertext, generation, counter),
        )
        connection.execute("UPDATE account_security SET lifecycle='active',revision=revision+1,completed_at=?,retired_password_hash=NULL WHERE user_id=?", (now, user["id"]))
        connection.execute("DELETE FROM enrollment_sessions WHERE user_id=?", (user["id"],))
        connection.execute("DELETE FROM enrollment_grants WHERE user_id=?", (user["id"],))
        record_event(connection, "enrollment_completed", actor=user["principal"], method="totp", now=now)
        record_activity(connection, user["name"], "Completed account enrollment", "Own account")
        _release_success(connection, key, reserved)


def readiness(connection):
    """Persisted enrollment/factor readiness, not proof of a current real device."""
    policy = _policy(connection)
    unresolved, administrators = [], 0
    for user in connection.execute("SELECT * FROM users WHERE active=1 ORDER BY id"):
        security = connection.execute("SELECT * FROM account_security WHERE user_id=?", (user["id"],)).fetchone()
        lifecycle = security["lifecycle"] if security else "missing"
        confirmed = connection.execute("SELECT 1 FROM account_mfa WHERE user_id=? AND last_counter>=0", (user["id"],)).fetchone()
        passkey = connection.execute("SELECT 1 FROM passkey_credentials WHERE user_id=? LIMIT 1", (user["id"],)).fetchone()
        if lifecycle != "active" or not (confirmed or passkey):
            unresolved.append({"id": user["id"], "username": user["username"], "lifecycle": lifecycle,
                               "reason": "enrollment_required" if lifecycle != "active" else "confirmed_factor_required"})
        elif user["role"] == "admin":
            administrators += 1
    return {"mode": policy["mode"], "revision": policy["revision"], "ready": not unresolved and administrators > 0,
            "unresolved": unresolved, "ready_administrators": administrators}


def activate_strict(connection, *, now=None):
    _transaction(connection)
    now = _now(now)
    result = readiness(connection)
    if not result["ready"]:
        raise EnrollmentError("Every active account must finish enrollment with a confirmed factor, including an administrator.", status_code=409)
    if result["mode"] != "strict":
        connection.execute("UPDATE authentication_policy SET mode='strict',revision=revision+1 WHERE id=1")
        connection.execute("DELETE FROM sessions")
        connection.execute("DELETE FROM session_predecessors")
        connection.execute("DELETE FROM passkey_challenges")
        connection.execute("DELETE FROM enrollment_sessions")
        connection.execute("DELETE FROM enrollment_grants")
        record_event(connection, "authentication_policy_activated", now=now)
    return readiness(connection)
