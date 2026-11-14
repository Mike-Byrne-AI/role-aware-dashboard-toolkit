"""Additive schema for the host-owned delivery workflow."""
WORK_SCHEMA = """
CREATE TABLE work_items (
 id TEXT PRIMARY KEY, contact_id TEXT UNIQUE NOT NULL REFERENCES contacts(id),
 event_id TEXT UNIQUE NOT NULL REFERENCES events(id),
 status TEXT NOT NULL CHECK(status IN ('scheduled','in_progress','completed')),
 revision INTEGER NOT NULL DEFAULT 0 CHECK(revision>=0),
 created_at TEXT NOT NULL, completed_at TEXT,
 CHECK((status='completed' AND completed_at IS NOT NULL) OR (status<>'completed' AND completed_at IS NULL))
);
CREATE TABLE work_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, work_id TEXT NOT NULL REFERENCES work_items(id),
 actor_id TEXT NOT NULL REFERENCES users(id), from_status TEXT,
 to_status TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX work_history_item ON work_history(work_id,id);
"""
