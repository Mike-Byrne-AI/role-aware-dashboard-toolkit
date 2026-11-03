"""Protected incident timeline and local outbox delivery controls."""

from contextlib import contextmanager

from fastapi import Query, Request

from .models import Empty
from .security import read_session_token, session_cookie_name, token_hash
from .security_events import (
    MAX_EVENT_SEQUENCE, DenialRecorder, SecurityEventMiddleware, dispatch_pending, timeline,
)
from .session_state import require_recent
from .event_destinations import destination_status


def install_security_event_routes(app, database, authorized, origin):
    cookie_name = session_cookie_name(origin)
    recorder = DenialRecorder(database)
    app.state.security_event_recorder = recorder
    app.add_middleware(SecurityEventMiddleware, recorder=recorder)

    @app.get("/api/admin/security/events")
    def events(request: Request, limit: int = Query(50, ge=1, le=100),
               before: int | None = Query(None, ge=1, le=MAX_EVENT_SEQUENCE)):
        with authorized(request, "can_manage_business") as (connection, auth):
            result = timeline(connection, limit=limit, before=before)
            result["observation"] = recorder.snapshot()
            result["automatic_delivery"] = app.state.security_dispatcher.snapshot()
            result["remote_delivery"] = {
                "worker": app.state.remote_security_dispatcher.snapshot(),
                "destinations": [destination_status(connection, row[0]) for row in connection.execute(
                    "SELECT destination_id FROM security_destinations WHERE kind='https' ORDER BY enabled_at,destination_id"
                )],
            }
            return result

    @app.post("/api/admin/security/events/dispatch")
    def dispatch(payload: Empty, request: Request):
        @contextmanager
        def current_authority():
            with authorized(request, "can_manage_business", csrf=True) as (connection, auth):
                require_recent(connection, token_hash(read_session_token(request, cookie_name)))
                yield connection

        with current_authority():
            pass
        return dispatch_pending(database, transaction_factory=current_authority)
