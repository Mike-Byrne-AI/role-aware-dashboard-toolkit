"""Purpose-bound browser correlation; never account authentication authority.

Every mutating helper requires its caller's transaction. Cookies and contexts
must be published only after that transaction commits. The independent durable
clock observation in Database.transaction survives authorization rollback.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
import base64
import hashlib
import hmac
import math
import re
import secrets
import time

from fastapi import HTTPException

FLOW_SECONDS = 8 * 60 * 60
CONTEXT_SECONDS = 120
MAX_GENERATION = 2_147_483_647
MAX_USER_FLOWS = 64
MAX_FLOWS = 10_000
MAX_TIME = 253402300799
COOKIE_NAME = "westbridge_login_flow"
HTTPS_COOKIE_NAME = "__Host-westbridge_login_flow"
CHANGED = "Sign-in changed or expired. Start sign-in again."
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_B64 = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_CLOCK_OBSERVER = ContextVar("westbridge_browser_flow_clock_observer", default=None)


def current_time():
    return time.time()


def _reject():
    raise HTTPException(409, CHANGED)


def _integer(value, maximum=MAX_TIME):
    return type(value) is int and 0 <= value <= maximum


def _sample(now=None):
    value = current_time() if now is None else now
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= MAX_TIME:
        raise ValueError("Browser flow clock is invalid.")
    return value


def _state(connection):
    rows = connection.execute("SELECT * FROM browser_flow_state").fetchall()
    if (len(rows) != 1 or rows[0]["id"] != 1 or not isinstance(rows[0]["epoch"], str)
            or not _HEX.fullmatch(rows[0]["epoch"]) or not _integer(rows[0]["rejection_time_floor"])):
        raise ValueError("Browser flow state is missing or invalid.")
    return rows[0]


@contextmanager
def observe_clock(connection):
    """Record only validated clock samples for this exact connection and epoch."""
    observed = {}
    token = _CLOCK_OBSERVER.set((connection, observed))
    try:
        yield observed
    finally:
        _CLOCK_OBSERVER.reset(token)


def preserve_observed_time(connection, observed):
    """After operation savepoint rollback, preserve its trusted clock evidence.

    The caller must still hold the outer writer lock. Never copy arbitrary
    operation-written floor values or observations from a different epoch.
    """
    if not connection.in_transaction:
        raise ValueError("Clock observation preservation requires the writer transaction.")
    state = _state(connection)
    floor = observed.get(state["epoch"], state["rejection_time_floor"])
    if floor > state["rejection_time_floor"]:
        connection.execute("UPDATE browser_flow_state SET rejection_time_floor=? WHERE id=1", (floor,))


def checked_time(connection, now=None, *, advance=True):
    if not connection.in_transaction:
        raise ValueError("Browser flow decisions require a transaction.")
    state, observed = _state(connection), _sample(now)
    if observed < state["rejection_time_floor"]:
        _reject()
    checked = int(observed)
    observer = _CLOCK_OBSERVER.get()
    if observer is not None and observer[0] is connection:
        observations = observer[1]
        observations[state["epoch"]] = max(checked, observations.get(state["epoch"], 0))
    if advance and checked > state["rejection_time_floor"]:
        connection.execute("UPDATE browser_flow_state SET rejection_time_floor=? WHERE id=1", (checked,))
    return checked


def clock_valid(connection, now=None):
    return _sample(now) >= _state(connection)["rejection_time_floor"]


def validate_state(connection):
    """Structural custody validation, deliberately independent of wall time."""
    _state(connection)
    count = connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0]
    if count > MAX_FLOWS or connection.execute(
        "SELECT 1 FROM browser_login_flows GROUP BY created_by_user_id HAVING COUNT(*)>?", (MAX_USER_FLOWS,),
    ).fetchone():
        raise ValueError("Browser flow retention exceeds its supported bounds.")
    for row in connection.execute("SELECT * FROM browser_login_flows"):
        if (not isinstance(row["flow_hash"], str) or not _HEX.fullmatch(row["flow_hash"])
                or not _integer(row["issued_at"], MAX_TIME - FLOW_SECONDS)
                or not _integer(row["expires_at"]) or row["expires_at"] != row["issued_at"] + FLOW_SECONDS
                or not _integer(row["generation"], MAX_GENERATION) or row["generation"] < 1
                or type(row["closed"]) is not int or row["closed"] not in (0, 1)):
            raise ValueError("Browser flow record is invalid.")
        binding = connection.execute(
            "SELECT s.expires_at FROM session_browser_flow b JOIN session_security q ON q.public_id=b.public_id "
            "JOIN sessions s ON s.token_hash=q.token_hash WHERE b.flow_hash=?", (row["flow_hash"],),
        ).fetchone()
        if ((not row["closed"] and binding is None) or (row["closed"] and binding is not None)
                or (binding is not None and binding[0] > row["expires_at"])):
            raise ValueError("Browser flow session binding is invalid.")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ValueError("Browser flow references are invalid.")


def reset_after_restore(connection, minimum_floor, now=None):
    """Discard ephemeral authority and rotate epoch using the caller's authority.

    An archived singleton is not current authority. The caller explicitly supplies
    the captured current floor (or archive floor for an unreconciled quarantine).
    False means the restored output must remain quarantined for clock recovery.
    """
    if not connection.in_transaction or not _integer(minimum_floor):
        raise ValueError("Invalid browser flow restore boundary.")
    observed = _sample(now)
    connection.execute("DELETE FROM session_browser_flow")
    connection.execute("DELETE FROM browser_login_flows")
    connection.execute("DELETE FROM passkey_challenges")
    connection.execute("DELETE FROM sessions")
    connection.execute("DELETE FROM browser_flow_state")
    connection.execute("INSERT INTO browser_flow_state VALUES(1,?,?)",
                       (secrets.token_hex(32), max(minimum_floor, int(observed))))
    return observed >= minimum_floor


def cookie_name(origin):
    return HTTPS_COOKIE_NAME if origin.scheme == "https" else COOKIE_NAME


def read_cookie(request, origin):
    selected = cookie_name(origin)
    count = sum(segment.partition("=")[0].strip() == selected
                for header in request.headers.getlist("cookie")
                for segment in header.split(";") if "=" in segment)
    if count > 1:
        raise HTTPException(400, "Ambiguous sign-in cookies. Start sign-in again.")
    return request.cookies.get(selected)


def _encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical32(value):
    if not _B64.fullmatch(value):
        _reject()
    decoded = base64.urlsafe_b64decode(value + "=")
    if len(decoded) != 32 or _encode(decoded) != value:
        _reject()
    return value


def _mac(key, purpose, *parts):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Invalid browser flow signing key.")
    message = b"westbridge-browser-flow-" + purpose + b"\0" + b"\0".join(str(part).encode("ascii") for part in parts)
    return _encode(hmac.new(key, message, hashlib.sha256).digest())


def _decimal(value, maximum):
    if not value.isascii() or not value.isdigit() or len(value) > 12:
        _reject()
    parsed = int(value)
    if str(parsed) != value or not _integer(parsed, maximum):
        _reject()
    return parsed


def _flow(connection, key, cookie, now):
    if not isinstance(cookie, str) or not cookie.isascii() or len(cookie) > 160:
        _reject()
    parts = cookie.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        _reject()
    issued = _decimal(parts[1], MAX_TIME - FLOW_SECONDS)
    nonce, signature = _canonical32(parts[2]), _canonical32(parts[3])
    epoch = _state(connection)["epoch"]
    if (issued > now or now >= issued + FLOW_SECONDS
            or not hmac.compare_digest(signature, _mac(key, b"cookie-v1", epoch, issued, nonce))):
        _reject()
    hashed = hashlib.sha256(b"westbridge-browser-flow-hash-v1\0" + cookie.encode("ascii")).hexdigest()
    row = connection.execute("SELECT * FROM browser_login_flows WHERE flow_hash=?", (hashed,)).fetchone()
    if row and (row["closed"] or row["issued_at"] != issued or row["expires_at"] != issued + FLOW_SECONDS
                or not _integer(row["generation"], MAX_GENERATION) or row["generation"] < 1):
        _reject()
    return hashed, issued, row["generation"] if row else 0, epoch


@dataclass(frozen=True)
class FlowProof:
    flow_hash: str
    generation: int
    issued_at: int
    expires_at: int
    now: int
    cookie: str = field(repr=False)
    context: str = field(repr=False)
    key: bytes = field(repr=False)
    admitted: bool = False
    old_public_id: str | None = None


@dataclass(frozen=True)
class FlowContext:
    cookie: str = field(repr=False)
    csrf: str = field(repr=False)
    expires_at: int
    flow_expires_at: int
    generation: int
    set_cookie: bool


def validate_context(connection, key, flow_cookie, context, *, now=None):
    checked = checked_time(connection, now)
    hashed, issued, generation, epoch = _flow(connection, key, flow_cookie, checked)
    if not isinstance(context, str) or not context.isascii() or len(context) > 128:
        _reject()
    parts = context.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        _reject()
    captured = _decimal(parts[1], MAX_GENERATION)
    created = _decimal(parts[2], MAX_TIME)
    signature = _canonical32(parts[3])
    if (captured != generation or created < issued or created > checked
            or checked >= min(created + CONTEXT_SECONDS, issued + FLOW_SECONDS)
            or not hmac.compare_digest(signature, _mac(key, b"context-v1", epoch, hashed, captured, created))):
        _reject()
    return FlowProof(hashed, generation, issued, issued + FLOW_SECONDS, checked, flow_cookie, context, key)


def purge_expired(connection, *, now=None):
    checked = checked_time(connection, now)
    return connection.execute(
        "DELETE FROM browser_login_flows WHERE expires_at<=? AND flow_hash NOT IN "
        "(SELECT flow_hash FROM session_browser_flow)", (checked,),
    ).rowcount


def _capacity(connection, user_id, now):
    checked = checked_time(connection, now)
    # Expired heads cannot retain capacity forever merely because no request
    # performed ordinary session cleanup. Every bound head is capped at F's H;
    # close only those past H, through the same real cascade, before purging.
    # Unexpired tombstones and the current winning flow remain untouched.
    connection.execute(
        "DELETE FROM sessions WHERE token_hash IN (SELECT s.token_hash FROM session_security s "
        "JOIN session_browser_flow b ON b.public_id=s.public_id "
        "JOIN browser_login_flows f ON f.flow_hash=b.flow_hash WHERE f.expires_at<=?)", (checked,),
    )
    purge_expired(connection, now=now)
    total = connection.execute("SELECT COUNT(*) FROM browser_login_flows").fetchone()[0]
    owned = connection.execute("SELECT COUNT(*) FROM browser_login_flows WHERE created_by_user_id=?", (user_id,)).fetchone()[0]
    if total >= MAX_FLOWS or owned >= MAX_USER_FLOWS:
        _reject()


def admit_login(connection, proof, user_id):
    """Reserve the winning generation before factor advancement, in its transaction."""
    if proof.admitted:
        _reject()
    # Re-sample inside the final transaction; a prior proof never freezes time.
    live = validate_context(connection, proof.key, proof.cookie, proof.context)
    if live.generation >= MAX_GENERATION:
        _reject()
    if live.generation == 0:
        _capacity(connection, user_id, live.now)
        connection.execute("INSERT INTO browser_login_flows VALUES(?,?,?,?,0,?)",
                           (live.flow_hash, live.issued_at, live.expires_at, 1, user_id))
    else:
        changed = connection.execute(
            "UPDATE browser_login_flows SET generation=generation+1 WHERE flow_hash=? AND generation=? AND closed=0",
            (live.flow_hash, live.generation),
        )
        if changed.rowcount != 1:
            _reject()
    old = connection.execute("SELECT public_id FROM session_browser_flow WHERE flow_hash=?", (live.flow_hash,)).fetchone()
    return replace(live, admitted=True, old_public_id=old[0] if old else None)


def bind_login(connection, proof, public_id):
    if not proof.admitted:
        _reject()
    checked = checked_time(connection)
    row = connection.execute("SELECT generation,closed,expires_at FROM browser_login_flows WHERE flow_hash=?",
                             (proof.flow_hash,)).fetchone()
    if not row or row["closed"] or row["generation"] != proof.generation + 1 or checked >= row["expires_at"]:
        _reject()
    # UPDATE (not DELETE/INSERT) is essential: deletion deliberately closes F.
    if proof.old_public_id is not None:
        changed = connection.execute("UPDATE session_browser_flow SET public_id=? WHERE public_id=? AND flow_hash=?",
                                     (public_id, proof.old_public_id, proof.flow_hash))
        if changed.rowcount != 1:
            _reject()
    else:
        connection.execute("INSERT INTO session_browser_flow VALUES(?,?)", (public_id, proof.flow_hash))


def binding_hash(proof, purpose="login"):
    if purpose != "login":
        raise ValueError("Unsupported browser flow challenge purpose.")
    return hashlib.sha256(b"westbridge-browser-flow-challenge-v1\0" + purpose.encode("ascii") + b"\0"
                          + proof.flow_hash.encode("ascii") + b"\0" + str(proof.generation).encode("ascii")).hexdigest()


def bound_session(connection, hashed, *, now=None, required=False):
    row = connection.execute(
        "SELECT b.public_id,f.* FROM session_security s JOIN session_browser_flow b ON b.public_id=s.public_id "
        "JOIN browser_login_flows f ON f.flow_hash=b.flow_hash WHERE s.token_hash=?", (hashed,),
    ).fetchone()
    if row is None:
        if required:
            _reject()
        return None
    checked = checked_time(connection, now)
    if row["closed"] or checked >= row["expires_at"]:
        _reject()
    return row


def require_bound_session(connection, hashed, *, now=None):
    return bound_session(connection, hashed, now=now, required=True)


def bootstrap(connection, key, flow_cookie=None, *, session_token=None, csrf=None, authenticated=False, now=None):
    checked = checked_time(connection, now)
    if not authenticated and session_token:
        from .security import authenticate
        try:
            authenticate(connection, session_token, key)
        except HTTPException as exc:
            if exc.status_code != 401:
                raise
        else:
            raise HTTPException(403, "Request verification failed. Refresh and try again.")
    known = None
    try:
        known = _flow(connection, key, flow_cookie, checked)
    except HTTPException:
        pass
    selected = None
    if authenticated:
        from .security import authenticate, token_hash
        auth = authenticate(connection, session_token, key)
        auth.check_csrf(csrf)
        selected = connection.execute("SELECT public_id FROM session_security WHERE token_hash=?",
                                      (token_hash(session_token),)).fetchone()
        if selected is None:
            _reject()
        matched = connection.execute("SELECT flow_hash FROM session_browser_flow WHERE public_id=?", (selected[0],)).fetchone()
        if not known or matched is None or matched[0] != known[0]:
            known = None
    minted = known is None
    if minted:
        if checked > MAX_TIME - FLOW_SECONDS:
            _reject()
        epoch, nonce = _state(connection)["epoch"], _encode(secrets.token_bytes(32))
        flow_cookie = f"v1.{checked}.{nonce}.{_mac(key, b'cookie-v1', epoch, checked, nonce)}"
        known = _flow(connection, key, flow_cookie, checked)
        if selected is not None:
            _capacity(connection, auth.user["id"], checked)
            connection.execute("INSERT INTO browser_login_flows VALUES(?,?,?,?,0,?)",
                               (known[0], checked, checked + FLOW_SECONDS, 1, auth.user["id"]))
            connection.execute("DELETE FROM session_browser_flow WHERE public_id=?", (selected[0],))
            connection.execute("INSERT INTO session_browser_flow VALUES(?,?)", (selected[0], known[0]))
            connection.execute(
                "UPDATE sessions SET expires_at=MIN(CAST(expires_at AS INTEGER),CAST(created_at AS INTEGER)+?,?),"
                "last_seen=? WHERE token_hash=?",
                (FLOW_SECONDS, checked + FLOW_SECONDS, checked, token_hash(session_token)),
            )
            known = (known[0], known[1], 1, known[3])
    hashed, issued, generation, epoch = known
    context = f"v1.{generation}.{checked}.{_mac(key, b'context-v1', epoch, hashed, generation, checked)}"
    return FlowContext(flow_cookie, context, min(checked + CONTEXT_SECONDS, issued + FLOW_SECONDS),
                       issued + FLOW_SECONDS, generation, minted)


def set_flow_cookie(response, origin, context):
    if context.set_cookie:
        response.set_cookie(cookie_name(origin), context.cookie,
                            max_age=max(0, context.flow_expires_at - math.ceil(_sample())),
                            httponly=True, secure=origin.scheme == "https", samesite="strict", path="/")
