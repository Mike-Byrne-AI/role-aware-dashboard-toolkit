"""Contact-to-delivery workflow inside the host's authorization transaction."""
from __future__ import annotations

import secrets

from fastapi import HTTPException, Request

from .db import record_activity, utc_now
from .idempotency import reserve_create
from .models import Body, Revision, RevisionRequest, Schedule

class ScheduleWork(Schedule):
    contact_revision: Revision


class WorkTransition(RevisionRequest):
    event_revision: Revision
    note: Body


def work_rows(connection, auth):
    """Employees receive assigned work only, without outreach data."""
    admin = auth.user["role"] == "admin"
    rows = connection.execute(
        "SELECT w.*,e.title,e.starts_at,e.ends_at,e.revision AS event_revision,e.location "
        "FROM work_items w JOIN events e ON e.id=w.event_id "
        "WHERE (? OR EXISTS(SELECT 1 FROM assignments a WHERE a.event_id=e.id AND a.user_id=?)) "
        "ORDER BY w.status='completed',e.starts_at,w.id",
        (admin, auth.user["id"]),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        contact = item.pop("contact_id")
        if admin:
            item["contact_id"] = contact
            item["company"] = connection.execute("SELECT company FROM contacts WHERE id=?", (contact,)).fetchone()[0]
        item["assignees"] = [dict(user) for user in connection.execute(
            "SELECT u.id,u.name FROM assignments a JOIN users u ON u.id=a.user_id WHERE a.event_id=? ORDER BY u.name",
            (row["event_id"],),
        )]
        item["history"] = [dict(event) for event in connection.execute(
            "SELECT u.name AS actor,h.from_status,h.to_status,h.note,h.created_at FROM work_history h "
            "JOIN users u ON u.id=h.actor_id WHERE h.work_id=? ORDER BY h.id", (row["id"],),
        )]
        result.append(item)
    return result


def delivery_summary(connection):
    counts = dict(connection.execute("SELECT status,COUNT(*) FROM work_items GROUP BY status").fetchall())
    return {
        "scheduled": counts.get("scheduled", 0), "in_progress": counts.get("in_progress", 0),
        "completed": counts.get("completed", 0),
        "ready_to_schedule": connection.execute(
            "SELECT COUNT(*) FROM contacts c WHERE c.stage='Won' AND NOT EXISTS(SELECT 1 FROM work_items w WHERE w.contact_id=c.id)"
        ).fetchone()[0],
        "pending_submissions": connection.execute("SELECT COUNT(*) FROM submissions WHERE status='pending'").fetchone()[0],
    }


def protect_linked_event(connection, identifier, *, archive=False):
    row = connection.execute("SELECT status FROM work_items WHERE event_id=?", (identifier,)).fetchone()
    if row and (archive or row[0] == "completed"):
        raise HTTPException(409, "This event belongs to delivery work. Completed work is retained and linked events cannot be archived.")


def install_delivery_routes(app, authorized, validate_schedule, current):
    @app.get("/api/work")
    def work(request: Request):
        with authorized(request) as (connection, auth):
            return {"work": work_rows(connection, auth)}

    @app.post("/api/admin/contacts/{identifier}/schedule", status_code=201)
    def schedule_work(identifier: str, payload: ScheduleWork, request: Request):
        with authorized(request, "can_manage_business", write=True) as (connection, auth):
            receipt = reserve_create(connection, request, auth.user["id"], payload,
                                     endpoint=f"/api/admin/contacts/{identifier}/schedule")
            if receipt.replay is not None:
                return receipt.replay
            contact = current(connection, "contacts", identifier, payload.contact_revision)
            if contact["stage"] != "Won":
                raise HTTPException(409, "Mark this opportunity Won before scheduling delivery.")
            if connection.execute("SELECT 1 FROM work_items WHERE contact_id=?", (identifier,)).fetchone():
                raise HTTPException(409, "This opportunity already has delivery work. Open Work to continue.")
            event_id, work_id = secrets.token_hex(12), secrets.token_hex(12)
            validate_schedule(connection, payload, event_id)
            auth.authorize("can_manage_business", write=True)
            connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?,0,0)",
                               (event_id, payload.title, payload.starts_at, payload.ends_at, payload.location, payload.notes))
            connection.executemany("INSERT INTO assignments VALUES(?,?)", [(event_id, user) for user in payload.employee_ids])
            now = utc_now()
            connection.execute("INSERT INTO work_items VALUES(?,?,?,'scheduled',0,?,NULL)", (work_id, identifier, event_id, now))
            connection.execute("INSERT INTO work_history(work_id,actor_id,from_status,to_status,note,created_at) VALUES(?,?,NULL,'scheduled',?,?)",
                               (work_id, auth.user["id"], "Scheduled from a won opportunity.", now))
            record_activity(connection, auth.user["name"], "Scheduled delivery", payload.title)
            return receipt.remember({"work": {"id": work_id, "event_id": event_id, "status": "scheduled", "revision": 0}})

    def transition(identifier, payload, request, before, after):
        # Admin changes retain the existing fresh-verification requirement.
        with authorized(request, "can_progress_work", write=True) as (connection, auth):
            if auth.user["role"] == "admin":
                from .session_state import require_recent
                require_recent(connection, auth.session_hash)
            row = connection.execute("SELECT * FROM work_items WHERE id=?", (identifier,)).fetchone()
            if not row:
                raise HTTPException(404, "The work was not found.")
            if auth.user["role"] != "admin" and not connection.execute(
                "SELECT 1 FROM assignments WHERE event_id=? AND user_id=?", (row["event_id"], auth.user["id"])
            ).fetchone():
                raise HTTPException(404, "The work was not found.")
            if row["revision"] != payload.revision or row["status"] != before:
                raise HTTPException(409, "This work changed. Refresh before trying again.")
            event = current(connection, "events", row["event_id"], payload.event_revision)
            if event["archived"]:
                raise HTTPException(409, "The linked schedule is archived.")
            auth.authorize("can_progress_work", write=True)
            now = utc_now()
            connection.execute("UPDATE work_items SET status=?,revision=revision+1,completed_at=? WHERE id=? AND revision=?",
                               (after, now if after == "completed" else None, identifier, payload.revision))
            connection.execute("INSERT INTO work_history(work_id,actor_id,from_status,to_status,note,created_at) VALUES(?,?,?,?,?,?)",
                               (identifier, auth.user["id"], before, after, payload.note, now))
            record_activity(connection, auth.user["name"], "Completed work" if after == "completed" else "Started work", event["title"])
            return {"ok": True, "status": after, "revision": payload.revision + 1}

    @app.post("/api/work/{identifier}/start")
    def start_work(identifier: str, payload: WorkTransition, request: Request):
        return transition(identifier, payload, request, "scheduled", "in_progress")

    @app.post("/api/work/{identifier}/complete")
    def complete_work(identifier: str, payload: WorkTransition, request: Request):
        return transition(identifier, payload, request, "in_progress", "completed")
