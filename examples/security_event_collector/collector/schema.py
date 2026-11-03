"""Collector/inbox schema; receipts and accepted payloads have no mutation API."""

VERSION = 1
SCHEMA = """
CREATE TABLE settings (
 id INTEGER PRIMARY KEY CHECK(id=1), kind TEXT NOT NULL CHECK(kind IN ('collector','inbox')),
 service_id TEXT NOT NULL, source_id TEXT NOT NULL, created_at REAL NOT NULL,
 max_events INTEGER NOT NULL, max_bytes INTEGER NOT NULL, max_cases INTEGER NOT NULL,
 max_transitions INTEGER NOT NULL, heartbeat_timeout INTEGER NOT NULL, backlog_threshold INTEGER NOT NULL
);
CREATE TABLE channels (
 destination_id TEXT PRIMARY KEY, peer_id TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1))
);
CREATE TABLE credentials (
 verifier TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('ingest','operator')),
 destination_id TEXT, expires_at REAL
);
CREATE TABLE clock_state (id INTEGER PRIMARY KEY CHECK(id=1), last_time REAL NOT NULL);
CREATE TABLE rate_limits (namespace TEXT PRIMARY KEY, tokens REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE events (
 source_id TEXT NOT NULL, event_id TEXT NOT NULL, payload BLOB NOT NULL, sha256 TEXT NOT NULL,
 receipt_id TEXT NOT NULL, received_at REAL NOT NULL, PRIMARY KEY(source_id,event_id)
);
CREATE TABLE event_receipts (
 source_id TEXT NOT NULL, event_id TEXT NOT NULL, destination_id TEXT NOT NULL, kind TEXT NOT NULL,
 receipt BLOB NOT NULL, PRIMARY KEY(source_id,event_id,destination_id),
 FOREIGN KEY(source_id,event_id) REFERENCES events(source_id,event_id)
);
CREATE TABLE heartbeats (
 source_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, sha256 TEXT NOT NULL, body BLOB NOT NULL,
 receipt BLOB NOT NULL, received_at REAL NOT NULL, clock_untrusted INTEGER NOT NULL CHECK(clock_untrusted IN (0,1))
);
CREATE TABLE alert_cases (
 id TEXT PRIMARY KEY, source_id TEXT NOT NULL, rule TEXT NOT NULL, subject TEXT NOT NULL,
 severity TEXT NOT NULL, condition_open INTEGER NOT NULL CHECK(condition_open IN (0,1)),
 acknowledged INTEGER NOT NULL CHECK(acknowledged IN (0,1)), number INTEGER NOT NULL,
 created_at REAL NOT NULL, last_observed REAL NOT NULL, details TEXT NOT NULL
);
CREATE UNIQUE INDEX open_case ON alert_cases(source_id,rule,subject) WHERE condition_open=1;
CREATE TABLE alert_transitions (
 alert_id TEXT NOT NULL REFERENCES alert_cases(id), number INTEGER NOT NULL,
 payload BLOB NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(alert_id,number)
);
CREATE TABLE alert_destination (
 id INTEGER PRIMARY KEY CHECK(id=1), inbox_id TEXT NOT NULL, destination_id TEXT NOT NULL, endpoint TEXT
);
CREATE TABLE alert_outbox (
 alert_id TEXT NOT NULL, number INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at REAL NOT NULL DEFAULT 0, last_error TEXT, acknowledged_at REAL, receipt BLOB,
 PRIMARY KEY(alert_id,number), FOREIGN KEY(alert_id,number) REFERENCES alert_transitions(alert_id,number)
);
CREATE TABLE inbox_messages (
 collector_id TEXT NOT NULL, alert_id TEXT NOT NULL, number INTEGER NOT NULL,
 payload BLOB NOT NULL, sha256 TEXT NOT NULL, receipt_id TEXT NOT NULL, received_at REAL NOT NULL,
 PRIMARY KEY(collector_id,alert_id,number)
);
CREATE TABLE inbox_receipts (
 collector_id TEXT NOT NULL, alert_id TEXT NOT NULL, number INTEGER NOT NULL,
 destination_id TEXT NOT NULL, receipt BLOB NOT NULL,
 PRIMARY KEY(collector_id,alert_id,number,destination_id),
 FOREIGN KEY(collector_id,alert_id,number) REFERENCES inbox_messages(collector_id,alert_id,number)
);
CREATE TABLE inbox_acknowledgements (
 collector_id TEXT NOT NULL, alert_id TEXT NOT NULL, number INTEGER NOT NULL, acknowledged_at REAL NOT NULL,
 PRIMARY KEY(collector_id,alert_id,number),
 FOREIGN KEY(collector_id,alert_id,number) REFERENCES inbox_messages(collector_id,alert_id,number)
);
"""
for _table in ("events", "event_receipts", "alert_transitions", "inbox_messages", "inbox_receipts", "inbox_acknowledgements"):
    for _operation in ("UPDATE", "DELETE"):
        SCHEMA += (f"CREATE TRIGGER immutable_{_table}_{_operation.lower()} BEFORE {_operation} ON {_table} "
                   "BEGIN SELECT RAISE(ABORT,'Immutable accepted record'); END;\n")
SCHEMA += f"PRAGMA user_version={VERSION};\n"
