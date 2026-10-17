"""Start the local demo without replacing existing accounts or saved work."""

from __future__ import annotations

import argparse
from contextlib import closing
import os
from pathlib import Path
import sqlite3

from .db import Database, _check_private
from .paths import default_data_dir, validate_data_dir
from .seed import seed_trial


def prepare_demo(data_dir: str | Path) -> tuple[Database, bool]:
    """Seed only empty storage; retain existing accounts on every restart.

    An existing database without accounts is a partial/custom initialization,
    not permission to reset or silently repopulate it. Its operator must choose
    a new empty directory or repair that state explicitly.
    """
    directory = validate_data_dir(data_dir)
    empty = not directory.exists() or not any(directory.iterdir())
    if not empty:
        database_path = directory / "landscape.sqlite3"
        key_path = directory / "identity.key"
        if not database_path.is_file() or not key_path.is_file():
            raise ValueError("Existing storage is incomplete. Preserve its original database and identity key.")
        _check_private(directory, directory=True)
        _check_private(database_path)
        _check_private(key_path)
        # Inspect before Database can initialize or migrate anything. Partial
        # storage without accounts is never permission to make new identities.
        try:
            with closing(sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)) as connection:
                has_accounts = connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
        except sqlite3.Error:
            raise ValueError("Existing storage could not be read; refusing to initialize it.") from None
        if not has_accounts:
            raise ValueError("Existing storage has no accounts; refusing to reseed it.")
        return Database(directory), False
    database = Database(directory)
    # seed_trial refuses existing accounts and an existing private account sheet
    # inside its transaction, including a concurrent first startup.
    seed_trial(directory)
    return database, True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Cedar & Stone landscaping demo locally.")
    parser.add_argument(
        "--data-dir", type=Path,
        default=os.environ.get("LANDSCAPE_DATA_DIR") or default_data_dir(),
        help="Private persistent storage outside the repository (default: %(default)s).",
    )
    parser.add_argument("--port", type=int, default=8089, help="Local HTTP port (default: 8089).")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Run this POSIX demo in Linux, macOS, or Windows WSL (Ubuntu).")
    if not 1 <= args.port <= 65535:
        parser.error("Choose a port from 1 through 65535.")
    try:
        database, seeded = prepare_demo(args.data_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Demo startup refused: {error}\n")

    from .app import create_app
    import uvicorn

    account_sheet = database.directory / "TRIAL_ACCOUNTS.md"
    print("Created fictional demo accounts." if seeded else "Reusing saved demo accounts and work.", flush=True)
    print(f"Private data directory: {database.directory}", flush=True)
    if account_sheet.is_file():
        print(f"Initial account passwords: open {account_sheet} privately.", flush=True)
    else:
        print("The original account sheet is absent; use your existing account password.", flush=True)
    print(f"Open http://127.0.0.1:{args.port} in a browser on this computer. Stop with Ctrl+C.", flush=True)
    uvicorn.run(
        create_app(database.directory), host="127.0.0.1", port=args.port,
        access_log=False, proxy_headers=False,
    )
