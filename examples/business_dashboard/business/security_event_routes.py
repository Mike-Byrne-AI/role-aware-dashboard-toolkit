"""Protected incident timeline and local outbox delivery controls."""

from contextlib import contextmanager

from fastapi import Query, Request

from .models import Empty
from .security import COOKIE_NAME, token_hash
from .security_events import (
    MAX_EVENT_SEQUENCE, DenialRecorder, SecurityEventMiddleware, dispatch_pending, timeline,
)
from .session_state import require_recent


def install_security_event_routes(app, database, authorized):
    recorder = DenialRecorder(database)
    app.state.security_event_recorder = recorder
    app.add_middleware(SecurityEventMiddleware, recorder=recorder)

    @app.get("/api/admin/security/events")
    def events(request: Request, limit: int = Query(50, ge=1, le=100),
               before: int | None = Query(None, ge=1, le=MAX_EVENT_SEQUENCE)):
        with authorized(request, "can_manage_business") as (connection, auth):
            result = timeline(connection, limit=limit, before=before)
            result["observation"] = recorder.snapshot()
            return result

    @app.post("/api/admin/security/events/dispatch")
    def dispatch(payload: Empty, request: Request):
        @contextmanager
        def current_authority():
            with authorized(request, "can_manage_business", csrf=True) as (connection, auth):
                require_recent(connection, token_hash(request.cookies[COOKIE_NAME]))
                yield connection

        with current_authority():
            pass
        return dispatch_pending(database, transaction_factory=current_authority)
