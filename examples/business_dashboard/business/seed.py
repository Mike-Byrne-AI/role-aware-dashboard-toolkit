"""Explicit, once-only fictional provisioning; secrets never enter source/logs."""

from datetime import datetime, timedelta, timezone
import secrets
import sqlite3

from .db import SCHEMA, create_private_file, validate_data_dir, utc_now
from .security import hash_password, principal_for_user
from .mfa import enroll_in_transaction

ACCOUNTS = (
    ("admin", "Morgan Reed", "admin"),
    ("alex", "Alex Morgan", "employee"),
    ("blair", "Blair Chen", "employee"),
    ("casey", "Casey Brooks", "employee"),
    ("drew", "Drew Parker", "employee"),
    ("ellis", "Ellis Jordan", "employee"),
)


def provision(data_dir) -> dict[str, str]:
    """Create only in an empty private directory; return credentials to caller."""
    directory = validate_data_dir(data_dir, create=True)
    if any(directory.iterdir()):
        raise ValueError("Provisioning requires an empty directory. Existing state was preserved.")
    key = secrets.token_bytes(32)
    create_private_file(directory / "identity.key", key)
    database_path = directory / "business.sqlite3"
    create_private_file(database_path, b"")
    credentials = {username: secrets.token_urlsafe(18) for username, _, _ in ACCOUNTS}
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        # BEGIN is included so schema and seeded rows commit together.
        connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
        for username, name, role in ACCOUNTS:
            connection.execute("INSERT INTO users VALUES(?,?,?,?,?,1,?,0)",
                               (username, username, name, hash_password(credentials[username]), role, principal_for_user(username, key)))
        now = utc_now()
        # Seed a normal workday in the provisioning machine's local time zone.
        tomorrow = (datetime.now() + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0).astimezone(timezone.utc)
        event_specs = (
            ("event-1", "Weekly operations briefing", 0, 2, "Meeting room A", "Align this week's priorities and client commitments.", ["alex", "blair", "casey", "drew", "ellis"]),
            ("event-2", "Client delivery workshop", 1, 4, "Studio 02", "Review the delivery plan and prepare the next milestone.", ["alex", "casey"]),
            ("event-3", "Service quality review", 2, 3, "Main office", "Check service outcomes and capture improvements.", ["blair", "drew"]),
            ("event-4", "Quarterly planning", 3, 2, "Meeting room B", "Bring current priorities and capacity notes.", ["ellis", "alex"]),
        )
        for event_id, title, days, hours, location, notes, employees in event_specs:
            start = tomorrow + timedelta(days=days)
            end = start + timedelta(hours=hours)
            connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?,0,0)",
                               (event_id, title, start.isoformat(), end.isoformat(), location, notes))
            connection.executemany("INSERT INTO assignments VALUES(?,?)", [(event_id, user_id) for user_id in employees])
        for message_id, author, body in (
            ("message-1", "admin", "Welcome to the team workspace. The schedule is ready for review; please use this board for updates that help everyone."),
            ("message-2", "blair", "The client handover checklist has been updated. Please bring any final questions to the operations briefing."),
            ("message-3", "alex", "Workshop materials are ready in Studio 02. I will share the follow-up notes here after the session."),
        ):
            connection.execute("INSERT INTO messages VALUES(?,?,?,?)", (message_id, author, body, now))
        connection.executemany("INSERT INTO contacts VALUES(?,?,?,?,?,?,?,0)", [
            ("contact-1", "Jordan Lee", "Northline Studio", "jordan@example.com", "Proposal", 18500, "Scope and timeline shared. Follow up next week."),
            ("contact-2", "Taylor Quinn", "Fieldwork Co.", "taylor@example.com", "Contacted", 9200, "Interested in a service partnership."),
            ("contact-3", "Sam Rivera", "Common Ground", "sam@example.com", "New", 6400, "Introductory conversation requested."),
            ("contact-4", "Robin Hayes", "Form & Function", "robin@example.com", "Won", 12400, "Engagement confirmed; handover in progress."),
        ])
        connection.executemany("INSERT INTO posts VALUES(?,?,?,?,?,?,0)", [
            ("post-1", "A thoughtful approach to everyday business", "We help growing teams turn clear priorities into reliable delivery. Explore what is happening at Westbridge and get to know the way we work.", "Company news", 1, now),
            ("post-2", "Open studio: meet the team", "Join our next open studio to hear about recent projects, ask questions and connect with the people behind the work. Details will be shared here soon.", "Events", 1, now),
            ("post-3", "A new quarter, a clear focus", "This quarter we are improving client handovers, sharing practical resources and building lasting working relationships.", "Updates", 1, now),
            ("post-4", "Upcoming partnership announcement", "Draft announcement for internal review before publication.", "Company news", 0, None),
        ])
        current = datetime.now(timezone.utc)
        for offset, revenue, cost in ((5, 28400, 19300), (4, 31800, 21100), (3, 30200, 20700), (2, 36500, 23800), (1, 39200, 25200), (0, 42600, 27100)):
            month_index = current.year * 12 + current.month - 1 - offset
            month = f"{month_index // 12:04d}-{month_index % 12 + 1:02d}"
            connection.execute("INSERT INTO revenue VALUES(?,?,?)", (month, revenue, cost))
        connection.execute("INSERT INTO activity(actor,action,target,created_at) VALUES(?,?,?,?)", ("Morgan Reed", "Workspace provisioned", "Westbridge", now))
        sheet = "# Westbridge private demo accounts\n\nKeep this file private. These passwords were generated for this installation.\n\n| Username | Name | Role | Password |\n| --- | --- | --- | --- |\n"
        for username, name, role in ACCOUNTS:
            sheet += f"| {username} | {name} | {role} | {credentials[username]} |\n"
        sheet += "\nGuest access needs no password and opens only the published public board.\n"
        create_private_file(directory / "ACCOUNTS.md", sheet.encode())
        enroll_in_transaction(connection, directory)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return credentials
