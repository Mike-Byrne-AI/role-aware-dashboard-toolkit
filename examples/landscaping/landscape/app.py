"""A fictional company host that exercises the toolkit's real access policy."""

from __future__ import annotations

import math
import json
import os
import time
from contextlib import contextmanager
from datetime import date as CalendarDate, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import anyio
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from role_aware_dashboard_toolkit.access import AccessDenied, FreezeConflict
from starlette.staticfiles import StaticFiles

from .action_workflow import ActionConflict, ActionDenied, ActionValidation, execute_change
from .db import Database, add_audit, rate_blocked, rate_failure, rate_key, utc_now
from .paths import default_data_dir
from .security import (
    ABSOLUTE_SECONDS, COOKIE_NAME, IDLE_SECONDS, ROLES, AuthError, authenticate,
    csrf_for_token, dummy_verify, hash_password, new_token, principal_for_user,
    token_hash, verify_password,
)


STATIC = Path(__file__).resolve().parent / "static"
BODY_LIMIT = 16 * 1024
BUSINESS_TIME_ZONE = ZoneInfo("America/New_York")
Username = Annotated[str, Field(min_length=3, max_length=32, pattern=r"^[a-z][a-z0-9_]{2,31}$")]
Password = Annotated[str, Field(min_length=12, max_length=128)]
Name = Annotated[str, Field(min_length=1, max_length=80)]
ShortText = Annotated[str, Field(min_length=1, max_length=200)]
Notes = Annotated[str, Field(max_length=2000)]
Service = Literal["mowing", "pruning", "planting", "cleanup", "irrigation"]
Stage = Literal["Lead", "Contacted", "Booked", "Completed"]


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)

    @field_validator("*", mode="after", check_fields=False)
    @classmethod
    def reject_controls(cls, value):
        if isinstance(value, str) and any(ord(char) < 32 and char not in "\n\t" for char in value):
            raise ValueError("Control characters are not accepted.")
        return value


class Empty(Body):
    pass


class Login(Body):
    username: Username
    password: Annotated[str, Field(min_length=1, max_length=128)]


class PasswordChange(Body):
    current_password: Annotated[str, Field(min_length=1, max_length=128)]
    new_password: Password


class Message(Body):
    body: Annotated[str, Field(min_length=1, max_length=1000)]

    @field_validator("body")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Write a message first.")
        return value


class CreateUser(Body):
    username: Username
    display_name: Name
    password: Password


class ResetPassword(Body):
    password: Password


class SetActive(Body):
    active: bool


class SetFreeze(Body):
    frozen: bool
    expected_revision: Annotated[int, Field(ge=0, le=9223372036854775805)]


class JobRevision(Body):
    expected_revision: Annotated[int, Field(ge=0, le=9223372036854775805)]


class SetCrew(JobRevision):
    worker_ids: Annotated[list[Annotated[str, Field(min_length=1, max_length=128)]], Field(max_length=10)]
    capacity: Annotated[int, Field(ge=1, le=10)]

    @field_validator("worker_ids")
    @classmethod
    def unique_workers(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Choose each worker only once.")
        return value


class JobChange(JobRevision):
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    acknowledge_conflicts: bool = False

    @field_validator("reason")
    @classmethod
    def nonblank_reason(cls, value):
        if not value.strip():
            raise ValueError("Explain this change.")
        return value.strip()


class SetJobSchedule(JobChange):
    starts_at: Annotated[str, Field(min_length=10, max_length=40)]

    @field_validator("starts_at")
    @classmethod
    def future_date(cls, value):
        return future_start(value)


class SetJobStatus(JobChange):
    status: Literal["scheduled", "completed", "cancelled"]


def future_start(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed <= datetime.now(timezone.utc):
            raise ValueError
        parsed = parsed.astimezone(timezone.utc)
        # Every supported duration must still have a representable end time.
        _end = parsed + timedelta(hours=24)
    except (ValueError, OverflowError):
        raise ValueError("Choose a future date and time with a time zone.") from None
    return parsed.isoformat(timespec="seconds")


class Customer(Body):
    name: Name
    contact: ShortText
    service: Service
    stage: Stage
    value: Annotated[float, Field(ge=0, le=10000000, allow_inf_nan=False)]
    notes: Notes = ""


class CustomerUpdate(Body):
    stage: Stage
    notes: Notes


class CreateJob(Body):
    customer: Name
    site: ShortText
    service: Service
    starts_at: Annotated[str, Field(min_length=10, max_length=40)]
    hours: Annotated[float, Field(gt=0, le=24, allow_inf_nan=False)]
    pay: Annotated[float, Field(ge=0, le=100000, allow_inf_nan=False)]
    capacity: Annotated[int, Field(ge=1, le=10)] = 2

    @field_validator("starts_at")
    @classmethod
    def future_date(cls, value):
        return future_start(value)


SECURITY_HEADERS = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
}


class RequestBoundary:
    """Validate host/origin and cap actual streamed bytes before JSON parsing."""

    def __init__(self, app, *, database: Database, allowed_hosts: list[str]):
        self.app = app
        self.database = database
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = time.monotonic()
        status = 500

        async def wrapped_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                blocked = {key.encode() for key in SECURITY_HEADERS}
                headers = [(key, value) for key, value in message.get("headers", []) if key.lower() not in blocked]
                headers.extend((key.encode(), value.encode()) for key, value in SECURITY_HEADERS.items())
                message = {**message, "headers": headers}
            await send(message)

        async def reject(code: int, detail: str):
            await JSONResponse({"detail": detail}, status_code=code)(scope, receive, wrapped_send)

        try:
            raw_headers = scope.get("headers", [])
            headers = {key.lower(): value.decode("latin-1") for key, value in raw_headers}
            if any(sum(key.lower() == name for key, _ in raw_headers) > 1 for name in (b"host", b"origin", b"content-length", b"x-csrf-token")):
                return await reject(400, "Invalid request headers.")
            host = headers.get(b"host", "")
            try:
                parsed_host = urlsplit(f"//{host}")
                valid_host = (
                    parsed_host.hostname in self.allowed_hosts and not parsed_host.username
                    and not parsed_host.password and not parsed_host.path and not parsed_host.query
                    and not parsed_host.fragment and not any(char.isspace() for char in host)
                )
                _port = parsed_host.port
            except ValueError:
                valid_host = False
            if not valid_host:
                return await reject(400, "This host is not allowed.")
            origin = headers.get(b"origin")
            expected_origin = f"{scope.get('scheme', 'http')}://{host}"
            if origin is not None and origin != expected_origin:
                return await reject(403, "This request origin is not allowed.")
            if headers.get(b"sec-fetch-site", "").lower() in ("cross-site", "same-site"):
                return await reject(403, "This request origin is not allowed.")
            content_length = headers.get(b"content-length")
            if content_length is not None:
                try:
                    length = int(content_length)
                except ValueError:
                    return await reject(400, "Invalid request size.")
                if length < 0 or length > BODY_LIMIT:
                    return await reject(413, "Request is too large.")
            if scope["method"] in ("POST", "PATCH", "PUT") and scope["path"].startswith("/api/"):
                if headers.get(b"content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    return await reject(415, "Send JSON for this request.")
            payload = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                payload.extend(message.get("body", b""))
                if len(payload) > BODY_LIMIT:
                    return await reject(413, "Request is too large.")
                if not message.get("more_body", False):
                    break
            sent_body = False
            scope.setdefault("state", {})["has_request_body"] = bool(payload)

            async def replay_body():
                nonlocal sent_body
                if not sent_body:
                    sent_body = True
                    return {"type": "http.request", "body": bytes(payload), "more_body": False}
                return await receive()

            await self.app(scope, replay_body, wrapped_send)
        finally:
            route = scope.get("route")
            safe_route = getattr(route, "path", "unmatched")
            await anyio.to_thread.run_sync(self.database.record_request, status, (time.monotonic() - started) * 1000, safe_route)


def public_user(row, *, active: bool = False):
    result = {key: row[key] for key in ("id", "username", "display_name", "role")}
    if active:
        result["active"] = bool(row["active"])
    return result


def create_app(data_dir, *, testing=False, secure_cookies=False, allowed_hosts=None) -> FastAPI:
    database = Database(data_dir)
    application = FastAPI(title="Cedar & Stone trial", docs_url=None, redoc_url=None, openapi_url=None)
    application.state.database = database
    application.state.db_path = database.path
    application.state.identity_key = database.identity_key
    application.state.started_at = time.monotonic()
    hosts = allowed_hosts or ["localhost", "127.0.0.1"] + (["testserver"] if testing else [])
    if any("*" in host for host in hosts):
        raise ValueError("Use explicit allowed hosts.")
    application.add_middleware(RequestBoundary, database=database, allowed_hosts=hosts)

    @application.exception_handler(AuthError)
    async def auth_error(_request, exc):
        payload = {"detail": exc.detail}
        if exc.code:
            payload["code"] = exc.code
        return JSONResponse(payload, status_code=exc.status_code)

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request, _exc):
        # FastAPI's default errors include the rejected input, including passwords.
        return JSONResponse({"detail": "Check the submitted fields and try again."}, status_code=422)

    @application.exception_handler(Exception)
    async def unexpected_error(_request, _exc):
        return JSONResponse({"detail": "The request could not be completed. Please try again."}, status_code=500, headers=SECURITY_HEADERS)

    @contextmanager
    def access(request: Request, permission: str | None = None, *, write: bool = False):
        failure = None
        with database.transaction() as conn:
            actor = "anonymous"
            conn.execute("SAVEPOINT protected_action")
            try:
                ctx = authenticate(conn, request.cookies.get(COOKIE_NAME), database.identity_key)
                actor = ctx.user["username"]
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    ctx.check_csrf(request.headers.get("X-CSRF-Token"))
                if permission:
                    ctx.authorize(permission, write=write)
                yield conn, ctx
                conn.execute("RELEASE protected_action")
            except AuthError as error:
                conn.execute("ROLLBACK TO protected_action")
                conn.execute("RELEASE protected_action")
                add_audit(conn, actor, "authorization.denied", request.scope["route"].path, "denied")
                failure = error
        if failure:
            raise failure

    def session_response(ctx):
        freeze = ctx.freeze()
        return {"user": public_user(ctx.user), "csrf_token": ctx.csrf_token, "frozen": freeze.frozen, "freeze_revision": freeze.revision}

    def only_worker(conn, user_id):
        target = conn.execute("SELECT * FROM users WHERE id=? AND role='worker'", (user_id,)).fetchone()
        if not target:
            raise AuthError(404, "Worker account not found.")
        return target

    @application.post("/api/login")
    def login(body: Login, request: Request):
        now = time.time()
        result = None
        failure = None
        with database.transaction() as conn:
            keys = [(rate_key(database.identity_key, "account", body.username), 5),
                    (rate_key(database.identity_key, "source", request.client.host if request.client else "unknown"), 30)]
            if rate_blocked(conn, keys, now):
                add_audit(conn, "anonymous", "login.throttled", "account", "denied")
                failure = AuthError(429, "Sign-in is temporarily limited. Try again later.")
            else:
                user = conn.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
                if user:
                    valid = verify_password(user["password_hash"], body.password)
                else:
                    dummy_verify(body.password)
                    valid = False
                if not valid or not user or user["active"] != 1:
                    rate_failure(conn, keys, now)
                    add_audit(conn, "anonymous", "login.failed", "account", "denied")
                    failure = AuthError(401, "The username or password is incorrect.")
                else:
                    previous = request.cookies.get(COOKIE_NAME)
                    if previous:
                        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(previous),))
                    conn.execute("DELETE FROM sessions WHERE expires_at<=? OR last_seen<=?", (now, now - IDLE_SECONDS))
                    # Bound retained sessions per account; newest sessions remain usable.
                    conn.execute("DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 9)", (user["id"], user["id"]))
                    token = new_token()
                    csrf = csrf_for_token(token, database.identity_key)
                    conn.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)", (token_hash(token), user["id"], token_hash(csrf), now, now, now + ABSOLUTE_SECONDS))
                    ctx = authenticate(conn, token, database.identity_key)
                    result = session_response(ctx)
                    conn.execute("DELETE FROM login_limits WHERE key_hash=?", (keys[0][0],))
                    add_audit(conn, user["username"], "login.succeeded", "session")
        if failure:
            raise failure
        response = JSONResponse(result)
        response.set_cookie(COOKIE_NAME, token, max_age=ABSOLUTE_SECONDS, secure=secure_cookies, httponly=True, samesite="strict", path="/")
        return response

    @application.get("/api/session")
    def get_session(request: Request):
        with access(request) as (_conn, ctx):
            return session_response(ctx)

    @application.post("/api/logout")
    def logout(body: Empty, request: Request):
        with access(request) as (conn, ctx):
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (ctx.token_hash,))
            add_audit(conn, ctx.user["username"], "logout", "session")
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE_NAME, path="/", secure=secure_cookies, httponly=True, samesite="strict")
        return response

    @application.post("/api/password")
    def change_password(body: PasswordChange, request: Request):
        failure = None
        with access(request) as (conn, ctx):
            now = time.time()
            keys = [(rate_key(database.identity_key, "password-account", ctx.user["id"]), 5),
                    (rate_key(database.identity_key, "password-source", request.client.host if request.client else "unknown"), 30)]
            if rate_blocked(conn, keys, now):
                add_audit(conn, ctx.user["username"], "password.throttled", "account", "denied")
                failure = AuthError(429, "Password changes are temporarily limited. Try again later.")
            elif not verify_password(ctx.user["password_hash"], body.current_password):
                rate_failure(conn, keys, now, login=False)
                add_audit(conn, ctx.user["username"], "password.failed", "account", "denied")
                failure = AuthError(403, "The current password is incorrect.")
            else:
                password_hash = hash_password(body.new_password)
                ctx.authorize("can_view_work")
                conn.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, ctx.user["id"]))
                conn.execute("DELETE FROM sessions WHERE user_id=?", (ctx.user["id"],))
                conn.execute("DELETE FROM login_limits WHERE key_hash=?", (keys[0][0],))
                add_audit(conn, ctx.user["username"], "password.changed", ctx.user["username"])
        if failure:
            raise failure
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE_NAME, path="/", secure=secure_cookies, httponly=True, samesite="strict")
        return response

    @application.get("/api/workers")
    def workers(request: Request):
        with access(request, "can_view_workers") as (conn, _ctx):
            return {"workers": [public_user(row, active=True) for row in conn.execute("SELECT * FROM users WHERE role='worker' ORDER BY username")]}

    @application.get("/api/jobs")
    def jobs(request: Request, sort: str = "starts_at", direction: str = "asc", service: str | None = None, view: str = "all", date: str | None = None):
        with access(request, "can_view_work") as (conn, ctx):
            if set(request.query_params) - {"sort", "direction", "service", "view", "date"}:
                raise AuthError(422, "Choose a supported schedule filter.")
            if sort not in {"starts_at", "hours", "pay", "service", "customer", "status"} or direction not in {"asc", "desc"}:
                raise AuthError(422, "Choose a supported sort order.")
            if service is not None and service not in {"mowing", "pruning", "planting", "cleanup", "irrigation"}:
                raise AuthError(422, "Choose a supported service.")
            if view not in {"all", "open", "mine", "history"}:
                raise AuthError(422, "Choose a supported schedule view.")
            selected_date = None
            if date is not None:
                try:
                    selected_date = CalendarDate.fromisoformat(date)
                    if selected_date.isoformat() != date:
                        raise ValueError
                except ValueError:
                    raise AuthError(422, "Choose a date in YYYY-MM-DD format.") from None
            now = datetime.now(timezone.utc)
            crew_by_job = {}
            joined_ids = set()
            for member in conn.execute(
                "SELECT s.job_id,s.user_id,u.display_name FROM job_signups s "
                "JOIN users u ON u.id=s.user_id ORDER BY s.created_at,u.display_name,s.user_id"
            ):
                crew_by_job.setdefault(member["job_id"], []).append({"display_name": member["display_name"]})
                if ctx.role == "worker" and member["user_id"] == ctx.user["id"]:
                    joined_ids.add(member["job_id"])
            rows = []
            summary = {"total_jobs": 0, "open_spots": 0, "my_jobs": 0, "my_hours": 0}
            for record in conn.execute("SELECT id,customer,site,service,starts_at,hours,pay,capacity,lifecycle FROM jobs WHERE archived=0 ORDER BY id"):
                job = dict(record)
                starts = datetime.fromisoformat(job["starts_at"])
                crew = crew_by_job.get(job["id"], [])
                joined = job["id"] in joined_ids
                remaining = max(0, job["capacity"] - len(crew))
                started = starts <= now
                scheduled = job["lifecycle"] == "scheduled"
                job.update({"crew": crew, "signup_count": len(crew), "remaining_spots": remaining,
                            "joined": joined, "status": job["lifecycle"] if not scheduled else "started" if started else "available" if remaining else "full"})
                if scheduled and not started:
                    summary["total_jobs"] += 1
                    summary["open_spots"] += remaining
                    if joined:
                        summary["my_jobs"] += 1
                        summary["my_hours"] += job["hours"]
                if (view == "history") == scheduled:
                    continue
                if service is not None and job["service"] != service:
                    continue
                if selected_date is not None and starts.astimezone(BUSINESS_TIME_ZONE).date() != selected_date:
                    continue
                if view == "open" and job["status"] != "available":
                    continue
                if view == "mine" and not joined:
                    continue
                rows.append(job)
            def sort_key(job):
                if sort == "starts_at":
                    return datetime.fromisoformat(job["starts_at"])
                if sort == "status":
                    return {"available": 0, "full": 1, "started": 2, "completed": 3, "cancelled": 4}[job["status"]]
                return job[sort].casefold() if isinstance(job[sort], str) else job[sort]
            rows.sort(key=sort_key, reverse=direction == "desc")
            freeze = ctx.freeze()
            return {"jobs": rows, "summary": summary, "frozen": freeze.frozen, "freeze_revision": freeze.revision}

    def mutate_signup(request, job_id, cancel):
        with access(request, "can_signup", write=True) as (conn, ctx):
            if ctx.role != "worker":
                raise AuthError(403, "Only workers can join or leave jobs.")
            if request.query_params or (cancel and request.state.has_request_body):
                raise AuthError(422, "This action accepts no account or actor overrides.")
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job or job["archived"]:
                raise AuthError(404, "Job not found.")
            if job["lifecycle"] != "scheduled":
                raise AuthError(409, "This job is closed. Its crew can only be corrected by an administrator.")
            if datetime.fromisoformat(job["starts_at"]) <= datetime.now(timezone.utc):
                raise AuthError(409, "This job has started. Its crew can no longer be changed.")
            joined = conn.execute("SELECT 1 FROM job_signups WHERE job_id=? AND user_id=?", (job_id, ctx.user["id"])).fetchone()
            if (cancel and not joined) or (not cancel and joined):
                return {"ok": True}
            if not cancel:
                count = conn.execute("SELECT COUNT(*) FROM job_signups WHERE job_id=?", (job_id,)).fetchone()[0]
                if count >= job["capacity"]:
                    raise AuthError(409, "This job is full. Choose another open job.")
            before = job_snapshot(conn, job_id)
            ctx.authorize("can_signup", write=True)
            if cancel:
                conn.execute("DELETE FROM job_signups WHERE job_id=? AND user_id=?", (job_id, ctx.user["id"]))
            else:
                conn.execute("INSERT INTO job_signups(job_id,user_id,created_at) VALUES(?,?,?)", (job_id, ctx.user["id"], utc_now()))
            conn.execute("UPDATE jobs SET revision=revision+1 WHERE id=?", (job_id,))
            action = "job.signup_cancelled" if cancel else "job.signed_up"
            record_job_history(conn, ctx.user["username"], action, "Worker left this job." if cancel else "Worker signed up.", before, job_snapshot(conn, job_id))
            add_audit(conn, ctx.user["username"], action, job_id)
            return {"ok": True}

    @application.post("/api/jobs/{job_id}/signup")
    def signup(job_id: str, body: Empty, request: Request):
        return mutate_signup(request, job_id, False)

    @application.delete("/api/jobs/{job_id}/signup")
    def cancel_signup(job_id: str, request: Request):
        return mutate_signup(request, job_id, True)

    @application.get("/api/messages")
    def messages(request: Request):
        with access(request, "can_view_messages") as (conn, ctx):
            rows = conn.execute("SELECT m.id,u.display_name AS author,m.body,m.created_at FROM messages m JOIN users u ON u.id=m.author_id ORDER BY m.id DESC LIMIT 100").fetchall()
            return {"messages": [dict(row) for row in reversed(rows)], "frozen": ctx.freeze().frozen}

    @application.post("/api/messages")
    def post_message(body: Message, request: Request):
        with access(request, "can_post_messages", write=True) as (conn, ctx):
            conn.execute("INSERT INTO messages(author_id,body,created_at) VALUES(?,?,?)", (ctx.user["id"], body.body, utc_now()))
            add_audit(conn, ctx.user["username"], "message.created", "shared_board")
            return {"ok": True}

    @application.post("/api/admin/users")
    def create_user(body: CreateUser, request: Request):
        with access(request, "can_manage_users", write=True) as (conn, ctx):
            if conn.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
                raise AuthError(409, "That username is already in use.")
            user_id = new_token()
            password_hash = hash_password(body.password)
            ctx.authorize("can_manage_users", write=True)
            conn.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?)", (user_id, body.username, body.display_name, password_hash, "worker", 1, principal_for_user(user_id, database.identity_key), time.time()))
            add_audit(conn, ctx.user["username"], "account.created", body.username)
            user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            return {"user": public_user(user, active=True)}

    @application.post("/api/admin/users/{user_id}/password")
    def reset_password(user_id: str, body: ResetPassword, request: Request):
        with access(request, "can_manage_users") as (conn, ctx):
            user = only_worker(conn, user_id)
            password_hash = hash_password(body.password)
            ctx.authorize("can_manage_users")
            conn.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash, user_id))
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM login_limits WHERE key_hash=?", (rate_key(database.identity_key, "account", user["username"]),))
            add_audit(conn, ctx.user["username"], "account.password_reset", user["username"])
            return {"ok": True}

    @application.patch("/api/admin/users/{user_id}")
    def set_active(user_id: str, body: SetActive, request: Request):
        with access(request, "can_manage_users") as (conn, ctx):
            user = only_worker(conn, user_id)
            ctx.authorize("can_manage_users")
            conn.execute("UPDATE users SET active=? WHERE id=?", (int(body.active), user_id))
            if not body.active:
                conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
                upcoming = utc_now()
                affected = [job_snapshot(conn, row[0]) for row in conn.execute(
                    "SELECT j.id FROM jobs j JOIN job_signups s ON s.job_id=j.id "
                    "WHERE s.user_id=? AND j.lifecycle='scheduled' AND julianday(j.starts_at)>julianday(?)",
                    (user_id, upcoming),
                ).fetchall()]
                conn.execute(
                    "UPDATE jobs SET revision=revision+1 WHERE lifecycle='scheduled' AND julianday(starts_at)>julianday(?) "
                    "AND id IN (SELECT job_id FROM job_signups WHERE user_id=?)",
                    (upcoming, user_id),
                )
                removed = conn.execute(
                    "DELETE FROM job_signups WHERE user_id=? AND job_id IN "
                    "(SELECT id FROM jobs WHERE lifecycle='scheduled' AND julianday(starts_at)>julianday(?))",
                    (user_id, upcoming),
                ).rowcount
                for before in affected:
                    record_job_history(conn, ctx.user["username"], "job.inactive_worker_removed",
                                       "Worker account disabled.", before, job_snapshot(conn, before["id"]))
                add_audit(conn, ctx.user["username"], "schedule.memberships_released", f"{user['username']}:{removed}")
            add_audit(conn, ctx.user["username"], "account.enabled" if body.active else "account.disabled", user["username"])
            return {"ok": True}

    @application.post("/api/admin/freeze")
    def set_freeze(body: SetFreeze, request: Request):
        with access(request, "can_manage_freeze") as (conn, ctx):
            try:
                freeze = ctx.policy.change_freeze(ctx.principal, ctx.role, body.frozen, body.expected_revision, ROLES)
            except FreezeConflict:
                raise AuthError(409, "Freeze state changed. Refresh before trying again.") from None
            except AccessDenied:
                raise AuthError(403, "This action is not allowed.") from None
            add_audit(conn, ctx.user["username"], "business.frozen" if freeze.frozen else "business.resumed", "dashboard")
            return {"frozen": freeze.frozen, "freeze_revision": freeze.revision}

    @application.post("/api/admin/jobs")
    def create_job(body: CreateJob, request: Request):
        with access(request, "can_manage_jobs", write=True) as (conn, ctx):
            job_query(request)
            if datetime.fromisoformat(body.starts_at) <= datetime.now(timezone.utc):
                raise AuthError(422, "Choose a future date and time.")
            job_id = new_token()
            ctx.authorize("can_manage_jobs", write=True)
            conn.execute("INSERT INTO jobs(id,customer,site,service,starts_at,hours,pay,capacity) VALUES(?,?,?,?,?,?,?,?)", (job_id, body.customer, body.site, body.service, body.starts_at, body.hours, body.pay, body.capacity))
            record_job_history(conn, ctx.user["username"], "job.created", "Job created.", None, job_snapshot(conn, job_id))
            add_audit(conn, ctx.user["username"], "job.created", job_id)
            return {"ok": True}

    def job_query(request, allowed=()):
        if set(request.query_params) - set(allowed) or len(request.query_params.multi_items()) != len(request.query_params):
            raise AuthError(422, "Choose supported job fields.")
        if request.method == "GET" and request.state.has_request_body:
            raise AuthError(422, "This action accepts no request body.")

    def managed_job(conn, job_id):
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise AuthError(404, "Job not found.")
        job = dict(row)
        job["archived"] = bool(job["archived"])
        job["crew"] = [dict(member) for member in conn.execute(
            "SELECT u.id,u.display_name FROM job_signups s JOIN users u ON u.id=s.user_id "
            "WHERE s.job_id=? ORDER BY s.created_at,u.display_name,u.id", (job_id,),
        )]
        job["signup_count"] = len(job["crew"])
        job["remaining_spots"] = max(0, job["capacity"] - job["signup_count"])
        started = datetime.fromisoformat(job["starts_at"]) <= datetime.now(timezone.utc)
        job["status"] = "archived" if job["archived"] else job["lifecycle"] if job["lifecycle"] != "scheduled" else "started" if started else "available" if job["remaining_spots"] else "full"
        return job

    def current_job(conn, job_id, revision):
        job = managed_job(conn, job_id)
        if job["revision"] != revision:
            raise AuthError(409, "This job changed. Reload it and review the latest details before saving.")
        return job

    def job_snapshot(conn, job_id):
        # This explicit business-record selection is safe for admin history.
        # Session bearers, passwords, identity keys and user records never enter it.
        job = managed_job(conn, job_id)
        return {key: job[key] for key in (
            "id", "customer", "site", "service", "starts_at", "hours", "pay",
            "capacity", "archived", "revision", "lifecycle", "crew",
        )}

    def record_job_history(conn, actor, action, reason, before, after):
        conn.execute(
            "INSERT INTO job_history(job_id,actor,action,reason,before_json,after_json,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (after["id"], actor, action, reason, json.dumps(before, sort_keys=True),
             json.dumps(after, sort_keys=True), utc_now()),
        )

    def check_job_overlap(conn, job, starts_at, acknowledged):
        """Warn only about half-open work intervals for retained active crew."""
        if acknowledged or not job["crew"]:
            return
        starts = datetime.fromisoformat(starts_at)
        ends = starts + timedelta(hours=job["hours"])
        crew_ids = {member["id"] for member in job["crew"]}
        conflicts = set()
        for other in conn.execute(
            "SELECT j.starts_at,j.hours,u.id,u.display_name FROM jobs j "
            "JOIN job_signups s ON s.job_id=j.id JOIN users u ON u.id=s.user_id "
            "WHERE j.id<>? AND j.archived=0 AND j.lifecycle='scheduled' AND u.active=1",
            (job["id"],),
        ):
            if other["id"] not in crew_ids:
                continue
            other_starts = datetime.fromisoformat(other["starts_at"])
            other_ends = other_starts + timedelta(hours=other["hours"])
            if starts < other_ends and other_starts < ends:
                conflicts.add(other["display_name"])
        if conflicts:
            raise AuthError(
                409, "This change overlaps another scheduled job for " + ", ".join(sorted(conflicts))
                + ". Review the crew schedule and explicitly acknowledge the overlap to continue.",
                code="schedule_conflict",
            )

    def change_job(conn, ctx, job_id, body, action, propose):
        def authorize():
            ctx.authorize("can_manage_jobs", write=True)
            return ctx.principal

        def save(after, revision):
            return conn.execute(
                "UPDATE jobs SET starts_at=?,lifecycle=?,revision=? WHERE id=? AND revision=?",
                (after["starts_at"], after["lifecycle"], after["revision"], job_id, revision),
            ).rowcount == 1

        def audit(result):
            recorded_action = action
            if body.acknowledge_conflicts:
                recorded_action += ".overlap_acknowledged"
            record_job_history(conn, ctx.user["username"], recorded_action, result.reason, result.before, result.after)
            add_audit(conn, ctx.user["username"], recorded_action, job_id)

        try:
            execute_change(connection=conn, expected_revision=body.expected_revision,
                           authorize=authorize, load=lambda: job_snapshot(conn, job_id),
                           propose=propose, save=save, audit=audit, reason=body.reason, require_reason=True)
        except ActionConflict:
            raise AuthError(409, "This job changed. Reload it and review the latest details before saving.") from None
        except ActionDenied:
            raise AuthError(403, "This action is no longer allowed. Refresh before trying again.") from None
        except ActionValidation as exc:
            raise AuthError(422, str(exc)) from None
        return {"ok": True, "job": managed_job(conn, job_id)}

    @application.get("/api/admin/jobs")
    def admin_jobs(request: Request, view: str = "active"):
        with access(request, "can_manage_jobs") as (conn, ctx):
            job_query(request, ("view",))
            if view not in ("active", "archived"):
                raise AuthError(422, "Choose active or archived jobs.")
            job_ids = [row[0] for row in conn.execute(
                "SELECT id FROM jobs WHERE archived=? ORDER BY starts_at,id", (int(view == "archived"),),
            )]
            freeze = ctx.freeze()
            return {"jobs": [managed_job(conn, job_id) for job_id in job_ids],
                    "frozen": freeze.frozen, "freeze_revision": freeze.revision}

    @application.get("/api/admin/jobs/{job_id}")
    def admin_job(job_id: str, request: Request):
        with access(request, "can_manage_jobs") as (conn, ctx):
            job_query(request)
            job = managed_job(conn, job_id)
            freeze = ctx.freeze()
            return {"job": job, "frozen": freeze.frozen, "freeze_revision": freeze.revision}

    @application.get("/api/admin/jobs/{job_id}/history")
    def job_history(job_id: str, request: Request):
        with access(request, "can_manage_jobs") as (conn, _ctx):
            job_query(request)
            managed_job(conn, job_id)
            history = []
            for row in conn.execute("SELECT * FROM job_history WHERE job_id=? ORDER BY id DESC", (job_id,)):
                entry = dict(row)
                entry["before"] = json.loads(entry.pop("before_json"))
                entry["after"] = json.loads(entry.pop("after_json"))
                history.append(entry)
            return {"history": history}

    @application.put("/api/admin/jobs/{job_id}/schedule")
    def reschedule_job(job_id: str, body: SetJobSchedule, request: Request):
        with access(request, "can_manage_jobs", write=True) as (conn, ctx):
            job_query(request)

            def propose(job):
                if job["archived"]:
                    raise AuthError(409, "Restore this job before rescheduling it.")
                if job["lifecycle"] != "scheduled":
                    raise AuthError(409, "Reopen this job before rescheduling it.")
                if datetime.fromisoformat(body.starts_at) <= datetime.now(timezone.utc):
                    raise AuthError(422, "Choose a future date and time.")
                if body.starts_at != job["starts_at"]:
                    check_job_overlap(conn, job, body.starts_at, body.acknowledge_conflicts)
                return {"starts_at": body.starts_at}

            return change_job(conn, ctx, job_id, body, "job.rescheduled", propose)

    @application.post("/api/admin/jobs/{job_id}/status")
    def set_job_status(job_id: str, body: SetJobStatus, request: Request):
        with access(request, "can_manage_jobs", write=True) as (conn, ctx):
            job_query(request)

            def propose(job):
                if job["archived"]:
                    raise AuthError(409, "Restore this job before changing its status.")
                if body.status == job["lifecycle"]:
                    return {}
                if body.status != "scheduled" and job["lifecycle"] != "scheduled":
                    raise AuthError(409, "Reopen this job before changing its completed or cancelled status.")
                if body.status == "completed" and datetime.fromisoformat(job["starts_at"]) > datetime.now(timezone.utc):
                    raise AuthError(409, "This job has not started. It cannot be marked complete yet.")
                if body.status == "scheduled":
                    for member in job["crew"]:
                        if not conn.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND role='worker'", (member["id"],)).fetchone():
                            raise AuthError(409, "Correct the crew to remove disabled worker accounts before reopening this job.")
                    check_job_overlap(conn, job, job["starts_at"], body.acknowledge_conflicts)
                return {"lifecycle": body.status}

            action = {"scheduled": "job.reopened", "completed": "job.completed", "cancelled": "job.cancelled"}[body.status]
            return change_job(conn, ctx, job_id, body, action, propose)

    @application.put("/api/admin/jobs/{job_id}/crew")
    def set_crew(job_id: str, body: SetCrew, request: Request):
        with access(request, "can_manage_jobs", write=True) as (conn, ctx):
            job_query(request)
            job = current_job(conn, job_id, body.expected_revision)
            if job["archived"]:
                raise AuthError(409, "Restore this job before assigning a crew.")
            if len(body.worker_ids) > body.capacity:
                raise AuthError(422, "Crew size must fit all selected workers.")
            for user_id in body.worker_ids:
                if not conn.execute("SELECT 1 FROM users WHERE id=? AND role='worker' AND active=1", (user_id,)).fetchone():
                    raise AuthError(422, "Choose active worker accounts.")
            old_ids = {member["id"] for member in job["crew"]}
            new_ids = set(body.worker_ids)
            before = job_snapshot(conn, job_id)
            ctx.authorize("can_manage_jobs", write=True)
            for user_id in sorted(old_ids - new_ids):
                conn.execute("DELETE FROM job_signups WHERE job_id=? AND user_id=?", (job_id, user_id))
                add_audit(conn, ctx.user["username"], "job.crew_removed", f"{job_id}:{user_id}")
            for user_id in sorted(new_ids - old_ids):
                conn.execute("INSERT INTO job_signups(job_id,user_id,created_at) VALUES(?,?,?)", (job_id, user_id, utc_now()))
                add_audit(conn, ctx.user["username"], "job.crew_assigned", f"{job_id}:{user_id}")
            if body.capacity != job["capacity"]:
                add_audit(conn, ctx.user["username"], "job.capacity_changed", f"{job_id}:{job['capacity']}->{body.capacity}")
            if old_ids != new_ids or body.capacity != job["capacity"]:
                conn.execute("UPDATE jobs SET capacity=?,revision=revision+1 WHERE id=?", (body.capacity, job_id))
                record_job_history(conn, ctx.user["username"], "job.crew_updated", "Administrator corrected the crew or capacity.", before, job_snapshot(conn, job_id))
            return {"ok": True, "job": managed_job(conn, job_id)}

    @application.post("/api/admin/jobs/{job_id}/archive")
    def archive_job(job_id: str, body: JobRevision, request: Request):
        with access(request, "can_manage_jobs", write=True) as (conn, ctx):
            job_query(request)
            job = current_job(conn, job_id, body.expected_revision)
            before = job_snapshot(conn, job_id)
            ctx.authorize("can_manage_jobs", write=True)
            if not job["archived"]:
                conn.execute("UPDATE jobs SET archived=1,revision=revision+1 WHERE id=?", (job_id,))
                record_job_history(conn, ctx.user["username"], "job.archived", "Job removed from the shared schedule.", before, job_snapshot(conn, job_id))
                add_audit(conn, ctx.user["username"], "job.archived", job_id)
            return {"ok": True, "job": managed_job(conn, job_id)}

    @application.post("/api/admin/jobs/{job_id}/restore")
    def restore_job(job_id: str, body: JobRevision, request: Request):
        with access(request, "can_manage_jobs", write=True) as (conn, ctx):
            job_query(request)
            job = current_job(conn, job_id, body.expected_revision)
            if not job["archived"]:
                raise AuthError(409, "This job is already on the schedule.")
            before = job_snapshot(conn, job_id)
            ctx.authorize("can_manage_jobs", write=True)
            conn.execute("DELETE FROM job_signups WHERE job_id=?", (job_id,))
            for member in job["crew"]:
                add_audit(conn, ctx.user["username"], "job.restore_assignment_cleared", f"{job_id}:{member['id']}")
            conn.execute("UPDATE jobs SET archived=0,revision=revision+1 WHERE id=?", (job_id,))
            record_job_history(conn, ctx.user["username"], "job.restored", "Job restored with an empty crew.", before, job_snapshot(conn, job_id))
            add_audit(conn, ctx.user["username"], "job.restored", job_id)
            return {"ok": True, "job": managed_job(conn, job_id)}

    @application.get("/api/admin/customers")
    def customers(request: Request):
        with access(request, "can_view_customers") as (conn, _ctx):
            return {"customers": [dict(row) for row in conn.execute("SELECT * FROM customers ORDER BY name,id")]}

    @application.post("/api/admin/customers")
    def create_customer(body: Customer, request: Request):
        with access(request, "can_manage_customers", write=True) as (conn, ctx):
            customer_id = new_token()
            conn.execute("INSERT INTO customers VALUES(?,?,?,?,?,?,?)", (customer_id, body.name, body.contact, body.service, body.stage, body.value, body.notes))
            add_audit(conn, ctx.user["username"], "customer.created", customer_id)
            return {"ok": True}

    @application.patch("/api/admin/customers/{customer_id}")
    def update_customer(customer_id: str, body: CustomerUpdate, request: Request):
        with access(request, "can_manage_customers", write=True) as (conn, ctx):
            result = conn.execute("UPDATE customers SET stage=?,notes=? WHERE id=?", (body.stage, body.notes, customer_id))
            if result.rowcount != 1:
                raise AuthError(404, "Customer not found.")
            add_audit(conn, ctx.user["username"], "customer.updated", customer_id)
            return {"ok": True}

    @application.get("/api/admin/health")
    def health(request: Request):
        from importlib.metadata import version

        with access(request, "can_view_health") as (conn, ctx):
            totals = dict(conn.execute("SELECT requests,denied_requests,failed_logins FROM telemetry WHERE id=1").fetchone())
            durations = [row[0] for row in conn.execute("SELECT milliseconds FROM request_samples ORDER BY milliseconds")]
            now = time.time()
            active = conn.execute("SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.active=1 AND s.expires_at>? AND s.last_seen>? AND s.created_at>?", (now, now-IDLE_SECONDS, now-ABSOLUTE_SECONDS)).fetchone()[0]
            telemetry = {**totals, "uptime_seconds": round(time.monotonic()-application.state.started_at, 1), "active_sessions": active, "p95_ms": round(durations[max(0, math.ceil(len(durations)*.95)-1)], 1) if durations else 0}
            audit = [dict(row) for row in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100")]
            freeze = ctx.freeze()
            return {"telemetry": telemetry, "audit": audit, "frozen": freeze.frozen, "freeze_revision": freeze.revision, "toolkit": {"version": version("role-aware-dashboard-toolkit"), "integration": "examples/landscaping"}}

    @application.get("/api/admin/metrics")
    def metrics(request: Request):
        with access(request, "can_view_metrics") as (conn, _ctx):
            pipeline = [dict(row) for row in conn.execute("SELECT stage,COUNT(*) AS count,SUM(value) AS value FROM customers GROUP BY stage ORDER BY CASE stage WHEN 'Lead' THEN 1 WHEN 'Contacted' THEN 2 WHEN 'Booked' THEN 3 ELSE 4 END")]
            summary = conn.execute("SELECT COUNT(*) AS total_jobs,COALESCE(SUM(hours),0) AS scheduled_hours,COALESCE(SUM(capacity),0) AS total_spots FROM jobs WHERE archived=0 AND lifecycle='scheduled'").fetchone()
            filled_spots = conn.execute("SELECT COUNT(*) FROM job_signups s JOIN jobs j ON j.id=s.job_id WHERE j.archived=0 AND j.lifecycle='scheduled'").fetchone()[0]
            lifecycle_counts = {state: 0 for state in ("scheduled", "completed", "cancelled")}
            lifecycle_counts.update({row["lifecycle"]: row["count"] for row in conn.execute("SELECT lifecycle,COUNT(*) AS count FROM jobs WHERE archived=0 GROUP BY lifecycle")})
            by_service = [dict(row) for row in conn.execute(
                "WITH services AS (SELECT service FROM jobs WHERE archived=0 AND lifecycle='scheduled' UNION SELECT service FROM customers), "
                "job_counts AS (SELECT service,COUNT(*) AS jobs FROM jobs WHERE archived=0 AND lifecycle='scheduled' GROUP BY service), "
                "customer_revenue AS (SELECT service,SUM(value) AS revenue FROM customers "
                "WHERE stage IN ('Booked','Completed') GROUP BY service) "
                "SELECT s.service,COALESCE(j.jobs,0) AS jobs,COALESCE(c.revenue,0) AS revenue "
                "FROM services s LEFT JOIN job_counts j ON j.service=s.service "
                "LEFT JOIN customer_revenue c ON c.service=s.service ORDER BY s.service"
            )]
            active_workers = conn.execute("SELECT COUNT(*) FROM users WHERE role='worker' AND active=1").fetchone()[0]
            return {"metrics": {"pipeline_value": sum(row["value"] for row in pipeline if row["stage"] in ("Lead", "Contacted")), "booked_revenue": sum(row["value"] for row in pipeline if row["stage"] in ("Booked", "Completed")), "scheduled_hours": summary["scheduled_hours"], "signup_rate": filled_spots / summary["total_spots"] if summary["total_spots"] else 0, "filled_spots": filled_spots, "total_spots": summary["total_spots"], "active_workers": active_workers, "total_jobs": summary["total_jobs"], "scheduled_jobs": lifecycle_counts["scheduled"], "completed_jobs": lifecycle_counts["completed"], "cancelled_jobs": lifecycle_counts["cancelled"]}, "by_service": by_service, "pipeline": pipeline}

    def shell(request: Request, permission=None):
        try:
            with access(request, permission):
                pass
        except AuthError as exc:
            if exc.status_code == 401:
                return RedirectResponse("/", status_code=303)
            return HTMLResponse("<!doctype html><html lang='en'><title>Access denied</title><h1>Access denied</h1><p>This page is not available to your account.</p><a href='/'>Return to your dashboard</a></html>", status_code=403)
        return FileResponse(STATIC / "index.html")

    @application.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @application.get("/work/{username}")
    def work_page(username: str, request: Request):
        try:
            with access(request, "can_view_work"):
                pass
        except AuthError:
            return RedirectResponse("/", status_code=303)
        return RedirectResponse("/schedule", status_code=303)

    @application.get("/schedule")
    def schedule_page(request: Request):
        return shell(request, "can_view_work")

    @application.get("/admin/customers")
    def customers_page(request: Request):
        return shell(request, "can_view_customers")

    @application.get("/admin/health")
    def health_page(request: Request):
        return shell(request, "can_view_health")

    @application.get("/admin/metrics")
    def metrics_page(request: Request):
        return shell(request, "can_view_metrics")

    application.mount("/static", StaticFiles(directory=STATIC), name="static")
    return application


def create_default_app() -> FastAPI:
    """ASGI factory; importing this module never opens or creates private storage.

    Provision synthetic data with ``run.py`` before using this factory directly.
    Explicit configuration stays host-owned and cannot bypass the path boundary.
    """
    configured_hosts = os.environ.get("LANDSCAPE_ALLOWED_HOSTS")
    return create_app(
        os.environ.get("LANDSCAPE_DATA_DIR") or default_data_dir(),
        secure_cookies=os.environ.get("LANDSCAPE_SECURE_COOKIES") == "1",
        allowed_hosts=configured_hosts.split(",") if configured_hosts else None,
    )
