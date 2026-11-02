"""The switchable browser fixture owns every real application's lifespan."""

from contextlib import asynccontextmanager
from pathlib import Path
import tempfile
import time

import pytest

from tests.test_business_dashboard import ORIGIN
from fastapi.testclient import TestClient
from tools.business_dashboard_browser import LabFixture


def test_lab_fixture_starts_both_workers_and_unwinds_them_after_switch_or_startup_failure():
    with tempfile.TemporaryDirectory(prefix="radt-browser-lifespan-") as temporary:
        root = Path(temporary).resolve()
        output = root / "evidence"
        output.mkdir()
        fixture = LabFixture(root / "private", ORIGIN, output)
        dispatchers = [app.state.security_dispatcher for app in (fixture.absent, fixture.configured)]
        assert all(not worker.snapshot()["running"] for worker in dispatchers)
        with TestClient(fixture, base_url=ORIGIN) as client:
            assert all(worker.snapshot()["running"] for worker in dispatchers)
            threads = [worker._thread for worker in dispatchers]
            assert threads[0] is not threads[1]
            deadline = time.monotonic() + 5
            while not all(worker.snapshot()["last_cycle_at"] is not None for worker in dispatchers):
                assert time.monotonic() < deadline, "Both real delivery loops must execute"
                time.sleep(0.01)
            assert fixture.application is fixture.absent
            assert client.get("/healthz").status_code == 200
            fixture.select_evidence()
            assert fixture.application is fixture.configured
            assert client.get("/healthz").status_code == 200
            assert all(worker.snapshot()["running"] for worker in dispatchers)
        assert all(not thread.is_alive() for thread in threads)
        assert all(worker._thread is None for worker in dispatchers)

        original = fixture.configured.router.lifespan_context

        @asynccontextmanager
        async def failed_startup(app):
            async with original(app):
                assert all(worker.snapshot()["running"] for worker in dispatchers)
                raise RuntimeError("Disposable configured-app startup failure")
                yield  # pragma: no cover -- preserve the async context manager shape

        fixture.configured.router.lifespan_context = failed_startup
        with pytest.raises(RuntimeError, match="Disposable configured-app startup failure"):
            with TestClient(fixture, base_url=ORIGIN):
                pytest.fail("Failed application startup must not serve requests")
        assert all(not worker.snapshot()["running"] for worker in dispatchers)
        assert all(worker._thread is None for worker in dispatchers)
