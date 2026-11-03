"""Bounded HTTP bootstrap for purpose-bound, fixed-lifetime browser sign-in."""

from fastapi import Request, Response

from . import browser_flow
from .models import Empty
from .security import read_session_token, session_cookie_name
from .work_limits import BoundedWork


def login_proof(connection, database, request, origin):
    """Reject ambiguous headers before admitting proof or expensive work."""
    values = request.headers.getlist("x-login-csrf")
    supplied = values[0] if len(values) == 1 else None
    return browser_flow.validate_context(
        connection, database.identity_key, browser_flow.read_cookie(request, origin), supplied,
    )


def install_login_context_routes(app, database, origin):
    metrics = app.state.security_metrics
    work = BoundedWork(2, "Sign-in context", on_event=lambda event: metrics.record("login_context_" + event))

    def context(request, response):
        values = request.headers.getlist("x-csrf-token")
        csrf = values[0] if len(values) == 1 else None
        # A claimed authenticated bootstrap never falls back to anonymous when
        # the bearer has become stale while this request was in flight.
        authenticated = bool(values)
        with database.transaction() as connection:
            result = browser_flow.bootstrap(
                connection, database.identity_key, browser_flow.read_cookie(request, origin),
                session_token=read_session_token(request, session_cookie_name(origin)),
                csrf=csrf, authenticated=authenticated,
            )
        # Neither a newly signed cookie nor its context escapes before commit.
        if result.set_cookie:
            browser_flow.set_flow_cookie(response, origin, result)
        return {"csrf": result.csrf, "expires_at": result.expires_at,
                "flow_expires_at": result.flow_expires_at}

    @app.post("/api/login/context")
    async def login_context(payload: Empty, request: Request, response: Response):
        return await work.run(context, request, response)
