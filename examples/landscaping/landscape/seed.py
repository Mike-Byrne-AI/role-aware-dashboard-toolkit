"""Explicit, private provisioning of the fictional landscaping trial."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import time
import uuid
from zoneinfo import ZoneInfo

from .db import Database, add_audit
from .security import hash_password, principal_for_user


ACCOUNTS = (
    ("admin", "Morgan Reed", "admin"),
    ("alex", "Alex Rivera", "worker"),
    ("blair", "Blair Chen", "worker"),
    ("casey", "Casey Brooks", "worker"),
    ("drew", "Drew Parker", "worker"),
    ("ellis", "Ellis Quinn", "worker"),
)
SERVICES = ("mowing", "pruning", "planting", "cleanup", "irrigation", "mowing")
CUSTOMER_NAMES = (
    "Juniper House",
    "Clover Corner",
    "Willow Court",
    "Fern & Finch Cafe",
    "Meadow Cottage",
    "Acorn Studio",
    "Birch Lane Library",
    "Sage Garden Club",
    "Maple Mews",
    "Pinecrest Workshop",
)


def seed_trial(data_dir: str | Path) -> dict[str, str]:
    """Create six accounts and fake records once; return private test credentials.

    The database contains password hashes only. Initial passwords are also
    written to a deliberately private local handoff file, never to stdout or
    the web application. Existing users or an existing handoff block seeding.
    """
    database = Database(data_dir)
    handoff = database.path.parent / "TRIAL_ACCOUNTS.md"
    passwords: dict[str, str] = {}
    for username, _, _ in ACCOUNTS:
        password = secrets.token_urlsafe(24)
        while password in passwords.values():
            password = secrets.token_urlsafe(24)
        passwords[username] = password
    hashes = {username: hash_password(password) for username, password in passwords.items()}
    # Fictional company workdays follow the user's local business time zone;
    # persisted timestamps remain UTC for unambiguous API/browser handling.
    now = datetime.now(ZoneInfo("America/New_York"))
    created_handoff = False

    try:
        with database.transaction() as connection:
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None:
                raise ValueError("Trial database already contains accounts; refusing to seed.")
            descriptor = os.open(
                handoff,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            created_handoff = True
            # Explicit fchmod also protects against an unexpected permissive
            # process umask and documents this file's credential boundary.
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(_credential_handoff(passwords))
                handle.flush()
                os.fsync(handle.fileno())

            worker_ids: list[str] = []
            for username, display_name, role in ACCOUNTS:
                user_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO users "
                    "(id,username,display_name,password_hash,role,active,principal,created_at) "
                    "VALUES (?,?,?,?,?,1,?,?)",
                    (
                        user_id,
                        username,
                        display_name,
                        hashes[username],
                        role,
                        principal_for_user(user_id, database.identity_key),
                        time.time(),
                    ),
                )
                if role == "worker":
                    worker_ids.append(user_id)

            for job_number in range(12):
                job_id = uuid.uuid4().hex
                starts = (now + timedelta(days=job_number // 4 + 1)).replace(
                    hour=(8, 10, 13, 15)[job_number % 4],
                    minute=0,
                    second=0,
                    microsecond=0,
                )
                customer_number = job_number % len(CUSTOMER_NAMES)
                hours = (1.5, 2.0, 3.0, 2.5, 1.0, 2.0)[job_number % 6]
                capacity = 2 if job_number % 2 == 0 else 3
                connection.execute(
                    "INSERT INTO jobs "
                    "(id,customer,site,service,starts_at,hours,pay,capacity) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        job_id,
                        CUSTOMER_NAMES[customer_number],
                        f"{100 + customer_number * 17} Meadow Lane, Cedar Hollow (fictional)",
                        SERVICES[job_number % len(SERVICES)],
                        starts.astimezone(timezone.utc).isoformat(),
                        hours,
                        round(hours * (28 + job_number % 5), 2),
                        capacity,
                    ),
                )
                # Include empty, partly staffed and full crews. Memberships
                # are individual worker signups, never an owner of the job.
                for crew_number in range((0, 1, 2, 2)[job_number % 4]):
                    connection.execute(
                        "INSERT INTO job_signups (job_id,user_id,created_at) VALUES (?,?,?)",
                        (
                            job_id,
                            worker_ids[(job_number + crew_number) % len(worker_ids)],
                            now.astimezone(timezone.utc).isoformat(),
                        ),
                    )

            stages = ("Lead", "Contacted", "Booked", "Completed")
            for number, name in enumerate(CUSTOMER_NAMES):
                connection.execute(
                    "INSERT INTO customers (id,name,contact,service,stage,value,notes) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (
                        uuid.uuid4().hex,
                        name,
                        f"customer{number + 1}@example.test",
                        SERVICES[number % len(SERVICES)],
                        stages[number % len(stages)],
                        float(180 + number * 75),
                        "Fictional trial customer. No real outreach or payments.",
                    ),
                )
            add_audit(connection, "system", "trial.seed", "fictional company")
    except BaseException:
        if created_handoff:
            handoff.unlink(missing_ok=True)
        raise
    return passwords


def _credential_handoff(passwords: dict[str, str]) -> str:
    rows = "\n".join(f"| {username} | `{password}` |" for username, password in passwords.items())
    return (
        "# Private trial accounts\n\n"
        "Cedar & Stone Landscaping is a fictional local trial. These randomly generated "
        "passwords grant access to this trial only. Keep this file private; do not commit, "
        "publish, or place it under the web root. Change passwords through the dashboard "
        "when handing accounts to other testers.\n\n"
        "The admin account can manage worker accounts and view all company pages. "
        "Workers share the crew schedule and message board, and can join or leave jobs "
        "only for themselves.\n\n"
        "| Username | Initial password |\n| --- | --- |\n"
        f"{rows}\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Explicitly seed a private fictional landscaping trial.")
    parser.add_argument("--data-dir", required=True, type=Path, help="Private runtime directory outside the application source.")
    args = parser.parse_args()
    try:
        seed_trial(args.data_dir)
    except (ValueError, FileExistsError) as error:
        parser.exit(1, f"Seeding refused: {error}\n")
    print(f"Trial created. Private account handoff: {args.data_dir.resolve() / 'TRIAL_ACCOUNTS.md'}")


if __name__ == "__main__":
    main()
