"""Westbridge HTTP application: host operations protected by toolkit policies."""

from contextlib import contextmanager
from datetime import datetime
import hashlib
import hmac
import logging
from pathlib import Path
import secrets
import sqlite3
import time

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from role_aware_dashboard_toolkit import __version__
from role_aware_dashboard_toolkit.access import AccessDenied
from role_aware_dashboard_toolkit.access_store import AccessStoreError, FreezeConflict

from .db import Database, record_activity, utc_now
from .abuse import PUBLIC_RULES, SubmissionGuard
from .mfa import verify_admin_code
from .models import Contact, ContactUpdate, Empty, Freeze, Login, Message, PasswordChange, Post, PostUpdate, RevisionRequest, Schedule, ScheduleUpdate, Submission, SubmissionReview, UserUpdate
from .request_security import RequestSecurityMiddleware, validate_origin
from .security import COOKIE_NAME, ROLES, SESSION_SECONDS, TransactionAccessStore, authenticate, dummy_password_check, hash_password, token_hash, verify_password

LOGGER = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"


def _identifier():
    return secrets.token_hex(12)


def _post(row, *, public=False):
    keys = ("id", "title", "body", "category", "published_at")
    result = {key: row[key] for key in keys}
    if not public:
        result.update(published=bool(row["published"]), revision=row["revision"])
    return result


def _event(connection, row):
    result = {key: row[key] for key in ("id", "title", "starts_at", "ends_at", "location", "notes", "revision")}
    result["employee_ids"] = [item[0] for item in connection.execute("SELECT user_id FROM assignments WHERE event_id=? ORDER BY user_id", (row["id"],))]
    return result


def _current(connection, table, identifier, revision):
    # Table names are internal constants supplied only by route implementations.
    row = connection.execute(f"SELECT * FROM {table} WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise HTTPException(404, "The record was not found.")
    if row["revision"] != revision:
        raise HTTPException(409, "This record changed. Refresh before saving again.")
    return row


def _validate_schedule(connection, payload, identifier):
    for employee_id in payload.employee_ids:
        user = connection.execute("SELECT role,active FROM users WHERE id=?", (employee_id,)).fetchone()
        if not user or user["role"] != "employee" or user["active"] != 1:
            raise HTTPException(422, "Select active employees for the schedule.")
        overlap = connection.execute(
            "SELECT 1 FROM events e JOIN assignments a ON a.event_id=e.id WHERE a.user_id=? AND e.id<>? "
            "AND e.archived=0 AND e.starts_at<? AND e.ends_at>? LIMIT 1",
            (employee_id, identifier, payload.ends_at, payload.starts_at),
        ).fetchone()
        if overlap:
            raise HTTPException(409, "An employee already has an assignment during that time.")


def _check_submission_admission(connection, address, now):
    if TransactionAccessStore(connection).read_freeze().frozen:
        raise HTTPException(503, "Public submissions are temporarily paused. Please try again later.")
    address_count = connection.execute("SELECT COUNT(*) FROM submission_limits WHERE key_hash=? AND submitted_at>?", (address, now - 600)).fetchone()[0]
    global_count = connection.execute("SELECT COUNT(*) FROM submission_limits WHERE submitted_at>?", (now - 3600,)).fetchone()[0]
    pending = connection.execute("SELECT COUNT(*) FROM submissions WHERE status='pending'").fetchone()[0]
    if address_count >= 3 or global_count >= 30 or pending >= 100:
        raise HTTPException(429, "Submissions are temporarily limited. Please try again later.", headers={"Retry-After": "600"})


def create_app(data_dir, *, public_origin="http://127.0.0.1:8091") -> FastAPI:
    origin = validate_origin(public_origin)
    submission_guard = SubmissionGuard.from_origin(public_origin)
    database = Database(data_dir)
    app = FastAPI(title="Westbridge", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.database = database
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[origin.hostname], www_redirect=False)
    app.add_middleware(RequestSecurityMiddleware, public_origin=public_origin, challenge_required=submission_guard.required)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exception):
        # Pydantic errors can contain the submitted password; never serialize them.
        return JSONResponse({"detail": "Check the submitted fields and try again."}, status_code=422)

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exception):
        LOGGER.error("Business storage operation failed (%s).", type(exception).__name__)
        return JSONResponse({"detail": "Storage is unavailable. Please try again later."}, status_code=503)

    @app.exception_handler(AccessStoreError)
    async def access_store_error(request, exception):
        LOGGER.error("Business access store rejected an operation.")
        return JSONResponse({"detail": "Access storage is unavailable."}, status_code=503)

    @app.exception_handler(AccessDenied)
    async def access_denied(request, exception):
        return JSONResponse({"detail": "This action is not allowed."}, status_code=403)

    @contextmanager
    def authorized(request, permission="can_view_team", *, write=False, csrf=False):
        with database.transaction() as connection:
            auth = authenticate(connection, request.cookies.get(COOKIE_NAME), database.identity_key)
            if write or csrf:
                auth.check_csrf(request.headers.get("x-csrf-token"))
            auth.authorize(permission, write=write)
            yield connection, auth

    @app.get("/api/session")
    def session(request: Request):
        with database.transaction() as connection:
            try:
                auth = authenticate(connection, request.cookies.get(COOKIE_NAME), database.identity_key)
                auth.authorize("can_view_team")
            except HTTPException as error:
                if error.status_code == 401:
                    return {"user": None}
                raise
            return auth.session_payload()

    @app.post("/api/login")
    def login(payload: Login, request: Request, response: Response):
        username = payload.username.casefold()
        now = time.time()
        remote = request.client.host if request.client else "unknown"
        keys = [("account:" + username, 8), ("address:" + remote, 30)]
        with database.transaction() as connection:
            connection.execute("DELETE FROM login_limits WHERE window_start<?", (now - 300,))
            keyed = []
            for value, limit in keys:
                key = hmac.new(database.identity_key, value.encode(), hashlib.sha256).hexdigest()
                keyed.append(key)
                row = connection.execute("SELECT attempts FROM login_limits WHERE key_hash=?", (key,)).fetchone()
                if row and row[0] >= limit:
                    return JSONResponse({"detail": "Too many sign-in attempts. Please wait five minutes."}, status_code=429, headers={"Retry-After": "300"})
            user = connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            valid = verify_password(user["password_hash"], payload.password) if user else False
            if not user:
                dummy_password_check(payload.password)
            generation = None
            eligible = valid and user["active"] == 1 and user["role"] in ROLES
            if eligible and user["role"] == "admin":
                generation = verify_admin_code(connection, user["id"], payload.otp)
                eligible = generation is not None
            if not eligible:
                for key in keyed:
                    connection.execute("INSERT INTO login_limits VALUES(?,?,1) ON CONFLICT(key_hash) DO UPDATE SET attempts=attempts+1", (key, now))
                return JSONResponse({"detail": "The sign-in details are incorrect."}, status_code=401)
            connection.execute("DELETE FROM login_limits WHERE key_hash=?", (keyed[0],))
            connection.execute("DELETE FROM sessions WHERE expires_at<=? OR last_seen<?", (now, now - 1800))
            old = request.cookies.get(COOKIE_NAME)
            if old:
                connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(old),))
            connection.execute("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT -1 OFFSET 7)", (user["id"],))
            token = secrets.token_urlsafe(32)
            connection.execute("INSERT INTO sessions VALUES(?,?,?,?,?)", (token_hash(token), user["id"], now, now, now + SESSION_SECONDS))
            if generation:
                connection.execute("INSERT INTO session_mfa VALUES(?,?)", (token_hash(token), generation))
            auth = authenticate(connection, token, database.identity_key)
            auth.authorize("can_view_team")
            record_activity(connection, user["name"], "Signed in", "Workspace")
            result = auth.session_payload()
        response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True, secure=origin.scheme == "https", samesite="strict", path="/")
        return result

    @app.post("/api/logout")
    def logout(payload: Empty, request: Request, response: Response):
        with authorized(request, csrf=True) as (connection, auth):
            connection.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(request.cookies[COOKIE_NAME]),))
        response.delete_cookie(COOKIE_NAME, path="/", secure=origin.scheme == "https", httponly=True, samesite="strict")
        return {"ok": True}

    @app.post("/api/password")
    def password(payload: PasswordChange, request: Request, response: Response):
        with authorized(request, csrf=True) as (connection, auth):
            if not verify_password(auth.user["password_hash"], payload.current_password):
                raise HTTPException(403, "The current password is incorrect.")
            connection.execute("UPDATE users SET password_hash=?,revision=revision+1 WHERE id=?", (hash_password(payload.new_password), auth.user["id"]))
            connection.execute("DELETE FROM sessions WHERE user_id=?", (auth.user["id"],))
            record_activity(connection, auth.user["name"], "Changed password", "Own account")
        response.delete_cookie(COOKIE_NAME, path="/", secure=origin.scheme == "https", httponly=True, samesite="strict")
        return {"ok": True}

    @app.get("/api/public/posts")
    def public_posts():
        with database.transaction() as connection:
            freeze = TransactionAccessStore(connection).read_freeze()
            return {"posts": [_post(row, public=True) for row in connection.execute("SELECT * FROM posts WHERE published=1 ORDER BY published_at DESC,id")],
                    "accepting_submissions": not freeze.frozen,
                    "posting_rules": PUBLIC_RULES, "submission_challenge": submission_guard.public_config()}

    @app.post("/api/public/submissions", status_code=202)
    def add_submission(payload: Submission, request: Request):
        # Guests never supply identity or publication state. A shared write
        # transaction makes the pause, queue cap and rolling limits atomic.
        remote = request.client.host if request.client else "unknown"
        submission_guard.validate_policy(payload.rules_version, payload.accept_rules)
        address = hmac.new(database.identity_key, b"guest-submission\0" + remote.encode(), hashlib.sha256).hexdigest()
        # Reject already-paused/full queues before spending an external check.
        # Never hold the SQLite lock across that network request, and recheck
        # every admission condition transactionally after verification.
        with database.transaction() as connection:
            _check_submission_admission(connection, address, time.time())
        submission_guard.verify(payload.turnstile_token, remote)
        with database.transaction() as connection:
            now = time.time()
            _check_submission_admission(connection, address, now)
            connection.execute("DELETE FROM submission_limits WHERE submitted_at<=?", (now - 3600,))
            connection.execute("INSERT INTO submissions VALUES(?,?,?,'pending',?,0,NULL)", (_identifier(), payload.title, payload.body, utc_now()))
            connection.execute("INSERT INTO submission_limits(key_hash,submitted_at) VALUES(?,?)", (address, now))
        return {"submitted": True}

    @app.get("/api/schedule")
    def schedule(request: Request):
        with authorized(request) as (connection, auth):
            freeze = auth.policy.store.read_freeze()
            return {"events": [_event(connection, row) for row in connection.execute("SELECT * FROM events WHERE archived=0 ORDER BY starts_at,id")],
                    "employees": [dict(row) for row in connection.execute("SELECT id,name FROM users WHERE role='employee' AND active=1 ORDER BY name")],
                    "frozen": freeze.frozen, "freeze_revision": freeze.revision}

    @app.post("/api/schedule", status_code=201)
    def add_event(payload: Schedule, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            identifier = _identifier()
            _validate_schedule(connection, payload, identifier)
            connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?,0,0)", (identifier, payload.title, payload.starts_at, payload.ends_at, payload.location, payload.notes))
            connection.executemany("INSERT INTO assignments VALUES(?,?)", [(identifier, item) for item in payload.employee_ids])
            record_activity(connection, auth.user["name"], "Scheduled work", payload.title)
            return {"event": _event(connection, connection.execute("SELECT * FROM events WHERE id=?", (identifier,)).fetchone())}

    @app.put("/api/schedule/{identifier}")
    def edit_event(identifier: str, payload: ScheduleUpdate, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            row = _current(connection, "events", identifier, payload.revision)
            if row["archived"]:
                raise HTTPException(409, "This event is archived.")
            _validate_schedule(connection, payload, identifier)
            connection.execute("UPDATE events SET title=?,starts_at=?,ends_at=?,location=?,notes=?,revision=revision+1 WHERE id=?", (payload.title, payload.starts_at, payload.ends_at, payload.location, payload.notes, identifier))
            connection.execute("DELETE FROM assignments WHERE event_id=?", (identifier,))
            connection.executemany("INSERT INTO assignments VALUES(?,?)", [(identifier, item) for item in payload.employee_ids])
            record_activity(connection, auth.user["name"], "Updated schedule", payload.title)
            return {"event": _event(connection, connection.execute("SELECT * FROM events WHERE id=?", (identifier,)).fetchone())}

    @app.post("/api/schedule/{identifier}/archive")
    def archive_event(identifier: str, payload: RevisionRequest, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            row = _current(connection, "events", identifier, payload.revision)
            if row["archived"]:
                raise HTTPException(409, "This event is already archived.")
            connection.execute("UPDATE events SET archived=1,revision=revision+1 WHERE id=?", (identifier,))
            record_activity(connection, auth.user["name"], "Archived schedule event", row["title"])
            return {"ok": True}

    @app.get("/api/messages")
    def messages(request: Request):
        with authorized(request) as (connection, auth):
            return {"messages": [dict(row) for row in connection.execute("SELECT m.id,u.name AS author,m.body,m.created_at FROM messages m JOIN users u ON u.id=m.author_id ORDER BY m.created_at DESC,m.rowid DESC LIMIT 200")]}

    @app.post("/api/messages", status_code=201)
    def add_message(payload: Message, request: Request):
        with authorized(request, "can_post_messages", write=True) as (connection, auth):
            identifier, created = _identifier(), utc_now()
            connection.execute("INSERT INTO messages VALUES(?,?,?,?)", (identifier, auth.user["id"], payload.body, created))
            record_activity(connection, auth.user["name"], "Posted a team message", "Team board")
            return {"message": {"id": identifier, "author": auth.user["name"], "body": payload.body, "created_at": created}}

    @app.get("/api/admin/overview")
    def overview(request: Request):
        with authorized(request, "can_manage_business") as (connection, auth):
            revenue = [dict(row) for row in connection.execute("SELECT * FROM revenue ORDER BY month")]
            latest = revenue[-1] if revenue else {"revenue": 0, "cost": 0}
            pipeline = connection.execute("SELECT COALESCE(SUM(value),0),COUNT(*) FROM contacts WHERE stage<>'Won'").fetchone()
            hours = 0
            for event in connection.execute("SELECT e.starts_at,e.ends_at,COUNT(a.user_id) AS people FROM events e JOIN assignments a ON a.event_id=e.id WHERE e.archived=0 AND e.ends_at>? GROUP BY e.id", (utc_now(),)):
                hours += (datetime.fromisoformat(event["ends_at"]) - datetime.fromisoformat(event["starts_at"])).total_seconds() / 3600 * event["people"]
            return {"metrics": {"monthly_revenue": latest["revenue"], "monthly_cost": latest["cost"], "pipeline_value": pipeline[0], "open_leads": pipeline[1], "scheduled_hours": round(hours, 2)},
                    "revenue": revenue, "activity": [dict(row) for row in connection.execute("SELECT * FROM activity ORDER BY id DESC LIMIT 50")], "toolkit_version": __version__}

    @app.get("/api/admin/contacts")
    def contacts(request: Request):
        with authorized(request, "can_manage_business") as (connection, auth):
            return {"contacts": [dict(row) for row in connection.execute("SELECT * FROM contacts ORDER BY company,name")]}

    @app.post("/api/admin/contacts", status_code=201)
    def add_contact(payload: Contact, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            identifier = _identifier()
            connection.execute("INSERT INTO contacts VALUES(?,?,?,?,?,?,?,0)", (identifier, payload.name, payload.company, payload.email, payload.stage, payload.value, payload.notes))
            record_activity(connection, auth.user["name"], "Added outreach contact", payload.company)
            return {"contact": dict(connection.execute("SELECT * FROM contacts WHERE id=?", (identifier,)).fetchone())}

    @app.put("/api/admin/contacts/{identifier}")
    def edit_contact(identifier: str, payload: ContactUpdate, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            _current(connection, "contacts", identifier, payload.revision)
            connection.execute("UPDATE contacts SET name=?,company=?,email=?,stage=?,value=?,notes=?,revision=revision+1 WHERE id=?", (payload.name, payload.company, payload.email, payload.stage, payload.value, payload.notes, identifier))
            record_activity(connection, auth.user["name"], "Updated outreach contact", payload.company)
            return {"contact": dict(connection.execute("SELECT * FROM contacts WHERE id=?", (identifier,)).fetchone())}

    @app.get("/api/admin/posts")
    def posts(request: Request):
        with authorized(request, "can_manage_business") as (connection, auth):
            return {"posts": [_post(row) for row in connection.execute("SELECT * FROM posts ORDER BY published_at DESC,id")], "posting_rules": PUBLIC_RULES}

    @app.get("/api/admin/submissions")
    def submissions(request: Request):
        with authorized(request, "can_manage_business") as (connection, auth):
            return {"submissions": [dict(row) for row in connection.execute("SELECT id,title,body,submitted_at,revision FROM submissions WHERE status='pending' ORDER BY submitted_at,id")]}

    @app.post("/api/admin/submissions/{identifier}/review")
    def review_submission(identifier: str, payload: SubmissionReview, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            submission = _current(connection, "submissions", identifier, payload.revision)
            if submission["status"] != "pending":
                raise HTTPException(409, "This submission has already been reviewed. Refresh the queue.")
            post_id = None
            if payload.decision == "approve":
                post_id = _identifier()
                connection.execute("INSERT INTO posts VALUES(?,?,?,'Community',1,?,0)", (post_id, submission["title"], submission["body"], utc_now()))
            status = "approved" if post_id else "rejected"
            connection.execute("UPDATE submissions SET status=?,post_id=?,revision=revision+1 WHERE id=?", (status, post_id, identifier))
            record_activity(connection, auth.user["name"], "Approved guest submission" if post_id else "Rejected guest submission", identifier)
        return {"reviewed": True}

    @app.post("/api/admin/posts", status_code=201)
    def add_post(payload: Post, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            identifier = _identifier()
            connection.execute("INSERT INTO posts VALUES(?,?,?,?,?,?,0)", (identifier, payload.title, payload.body, payload.category, int(payload.published), utc_now() if payload.published else None))
            record_activity(connection, auth.user["name"], "Created public-board post", payload.title)
            return {"post": _post(connection.execute("SELECT * FROM posts WHERE id=?", (identifier,)).fetchone())}

    @app.put("/api/admin/posts/{identifier}")
    def edit_post(identifier: str, payload: PostUpdate, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            current = _current(connection, "posts", identifier, payload.revision)
            published = (current["published_at"] or utc_now()) if payload.published else None
            connection.execute("UPDATE posts SET title=?,body=?,category=?,published=?,published_at=?,revision=revision+1 WHERE id=?", (payload.title, payload.body, payload.category, int(payload.published), published, identifier))
            record_activity(connection, auth.user["name"], "Updated public-board post", payload.title)
            return {"post": _post(connection.execute("SELECT * FROM posts WHERE id=?", (identifier,)).fetchone())}

    @app.post("/api/admin/posts/{identifier}/unpublish")
    def unpublish_post(identifier: str, payload: RevisionRequest, request: Request):
        # A narrow containment action remains available during a pause. No
        # content, category or publication fields are accepted from the caller.
        with authorized(request, "can_manage_business", csrf=True) as (connection, auth):
            current = _current(connection, "posts", identifier, payload.revision)
            if not current["published"]:
                raise HTTPException(409, "This post is already removed from the public board.")
            connection.execute("UPDATE posts SET published=0,published_at=NULL,revision=revision+1 WHERE id=?", (identifier,))
            record_activity(connection, auth.user["name"], "Removed public-board post", identifier)
            return {"post": _post(connection.execute("SELECT * FROM posts WHERE id=?", (identifier,)).fetchone())}

    @app.post("/api/admin/freeze")
    def freeze(payload: Freeze, request: Request):
        with authorized(request, "can_manage_freeze", csrf=True) as (connection, auth):
            try:
                state = auth.policy.change_freeze(auth.user["principal"], auth.user["role"], payload.frozen, payload.revision, ROLES)
            except FreezeConflict:
                raise HTTPException(409, "Editing status changed. Refresh before trying again.") from None
            record_activity(connection, auth.user["name"], "Paused editing" if state.frozen else "Resumed editing", "Workspace")
            return {"frozen": state.frozen, "freeze_revision": state.revision}

    @app.get("/api/admin/users")
    def users(request: Request):
        with authorized(request, "can_manage_business") as (connection, auth):
            result = []
            for row in connection.execute("SELECT id,username,name,role,active,revision FROM users ORDER BY role,name"):
                value = dict(row)
                value["active"] = bool(value["active"])
                result.append(value)
            return {"users": result}

    @app.put("/api/admin/users/{identifier}")
    def edit_user(identifier: str, payload: UserUpdate, request: Request):
        # Account security remains operable while business editing is paused.
        with authorized(request, "can_manage_business", csrf=True, write=payload.active) as (connection, auth):
            user = _current(connection, "users", identifier, payload.revision)
            if not payload.active and (identifier == auth.user["id"] or (user["role"] == "admin" and connection.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0] <= 1)):
                raise HTTPException(409, "You cannot disable yourself or the last administrator.")
            connection.execute("UPDATE users SET active=?,revision=revision+1 WHERE id=?", (int(payload.active), identifier))
            if not payload.active:
                connection.execute("DELETE FROM sessions WHERE user_id=?", (identifier,))
            record_activity(connection, auth.user["name"], "Enabled account" if payload.active else "Disabled account", user["name"])
            return {"ok": True}

    @app.get("/healthz")
    def health():
        try:
            with database.transaction() as connection:
                TransactionAccessStore(connection).read_freeze()
        except (OSError, ValueError, sqlite3.Error, AccessStoreError) as error:
            LOGGER.error("Business health storage check failed (%s).", type(error).__name__)
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ok"}

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC, check_dir=False), name="static")
    return app
