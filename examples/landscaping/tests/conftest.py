"""Isolated fake-data fixtures; no running demo account is ever used by tests."""

from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
import os
import sys
import shutil
import sqlite3

from fastapi.testclient import TestClient
import pytest

if os.name == "nt":
    pytest.skip("The landscaping host requires POSIX permissions; run in WSL on Windows", allow_module_level=True)

# Load this example package without depending on the shell working directory.
EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXAMPLE_ROOT))

WORKERS = ("alex", "blair", "casey", "drew", "ellis")
COOKIE = "landscape_demo_session"
NEW_PASSWORD = "Isolated test password 42!"


@dataclass
class Actor:
    client: TestClient
    profile: dict
    csrf: str = field(repr=False)
    password: str = field(repr=False)

    def request(self, method, path, **kwargs):
        headers = {"Origin": "http://testserver", "X-CSRF-Token": self.csrf}
        headers.update(kwargs.pop("headers", {}))
        return self.client.request(method, path, headers=headers, **kwargs)


class Trial:
    def __init__(self, app, credentials, stack):
        self.app = app
        self.credentials = credentials
        self.stack = stack
        self.db_path = Path(app.state.db_path)
        with self.db() as connection:
            self.ids = dict(connection.execute("SELECT username,id FROM users"))
            self.job_ids = [row[0] for row in connection.execute("SELECT id FROM jobs ORDER BY starts_at,id")]
            self.empty_job = connection.execute(
                "SELECT j.id FROM jobs j WHERE NOT EXISTS "
                "(SELECT 1 FROM job_signups s WHERE s.job_id=j.id) ORDER BY j.starts_at,j.id LIMIT 1"
            ).fetchone()[0]

    def db(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def client(self, **kwargs):
        return self.stack.enter_context(TestClient(self.app, **kwargs))

    def login(self, username, password=None, client=None):
        client = client or self.client()
        password = password or self.credentials[username]
        response = client.post(
            "/api/login",
            json={"username": username, "password": password},
            headers={"Origin": "http://testserver"},
        )
        assert response.status_code == 200, "Fixture account login failed"
        data = response.json()
        return Actor(client, data["user"], data["csrf_token"], password)


@pytest.fixture(scope="session")
def seeded_template(tmp_path_factory):
    from landscape.seed import seed_trial

    directory = tmp_path_factory.mktemp("landscape-seed") / "private"
    credentials = seed_trial(directory)
    assert set(credentials) == {"admin", *WORKERS}
    assert len(set(credentials.values())) == 6
    return directory, credentials


@pytest.fixture
def trial(tmp_path, seeded_template):
    from landscape.app import create_app

    template, credentials = seeded_template
    data_dir = tmp_path / "private"
    shutil.copytree(template, data_dir)
    app = create_app(data_dir, testing=True, allowed_hosts=["testserver"])
    with ExitStack() as stack:
        yield Trial(app, credentials, stack)


@pytest.fixture
def admin(trial):
    return trial.login("admin")
