
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','worker')),
 active INTEGER NOT NULL CHECK(active IN (0,1)), principal TEXT UNIQUE NOT NULL,
 created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 csrf_hash TEXT NOT NULL, created_at REAL NOT NULL, last_seen REAL NOT NULL,
 expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS settings (
 id INTEGER PRIMARY KEY CHECK(id=1), frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),
 freeze_revision INTEGER NOT NULL CHECK(freeze_revision>=0), changed_by TEXT
);
INSERT OR IGNORE INTO settings VALUES (1,0,0,NULL);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id),
 customer TEXT NOT NULL, site TEXT NOT NULL, service TEXT NOT NULL,
 starts_at TEXT NOT NULL, hours REAL NOT NULL CHECK(hours>0),
 pay REAL NOT NULL CHECK(pay>=0), status TEXT NOT NULL CHECK(status IN ('available','signed_up')),
 signed_by TEXT REFERENCES users(id),
 CHECK((status='available' AND signed_by IS NULL) OR (status='signed_up' AND signed_by=owner_id))
);
CREATE INDEX IF NOT EXISTS jobs_owner ON jobs(owner_id);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, author_id TEXT NOT NULL REFERENCES users(id),
 body TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, contact TEXT NOT NULL, service TEXT NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('Lead','Contacted','Booked','Completed')),
 value REAL NOT NULL CHECK(value>=0), notes TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
 actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_limits (
 key_hash TEXT PRIMARY KEY, window_start REAL NOT NULL, failures INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry (
 id INTEGER PRIMARY KEY CHECK(id=1), requests INTEGER NOT NULL,
 denied_requests INTEGER NOT NULL, failed_logins INTEGER NOT NULL
);
INSERT OR IGNORE INTO telemetry VALUES (1,0,0,0);
CREATE TABLE IF NOT EXISTS request_samples (
 id INTEGER PRIMARY KEY AUTOINCREMENT, milliseconds REAL NOT NULL
);
