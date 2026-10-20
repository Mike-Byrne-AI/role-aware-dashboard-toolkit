"""Blocking security work cannot consume all host workers or evade admission."""

import asyncio
from pathlib import Path
import sys
from threading import Event, Lock

import pytest

anyio = pytest.importorskip("anyio")
pytest.importorskip("fastapi")
from fastapi import HTTPException  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "business_dashboard"))
from business import work_limits  # noqa: E402
from business.work_limits import BoundedWork  # noqa: E402


def assert_busy(error):
    assert error.value.status_code == 429
    assert error.value.headers == {"Retry-After": "1"}


def test_capacity_bounds_callbacks_without_occupying_default_workers():
    async def scenario():
        work = BoundedWork(2)
        release, lock = Event(), Lock()
        entered = asyncio.Event()
        loop = asyncio.get_running_loop()
        active = peak = 0
        limiter = anyio.to_thread.current_default_thread_limiter()
        old_limit, limiter.total_tokens = limiter.total_tokens, 1

        def held(value):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                if active == 2:
                    loop.call_soon_threadsafe(entered.set)
            try:
                assert release.wait(5), "Test did not release blocking callbacks"
                return value
            finally:
                with lock:
                    active -= 1

        tasks = [asyncio.create_task(work.run(held, value)) for value in ("first", "second")]
        try:
            await asyncio.wait_for(entered.wait(), 3)
            with pytest.raises(HTTPException) as error:
                await work.run(lambda: pytest.fail("Overflow callback ran"))
            assert_busy(error)
            assert await asyncio.wait_for(anyio.to_thread.run_sync(lambda: "healthy"), 1) == "healthy"
            assert peak == 2
        finally:
            release.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            limiter.total_tokens = old_limit
        assert results == ["first", "second"]
        assert active == 0
        assert await work.run(lambda: "reused") == "reused"

    asyncio.run(scenario())


def test_callback_exception_releases_admission():
    async def scenario():
        work = BoundedWork(1)

        def fail():
            raise RuntimeError("Synthetic callback failure")

        with pytest.raises(RuntimeError, match="Synthetic callback"):
            await work.run(fail)
        assert await work.run(lambda value: value, 42) == 42

    asyncio.run(scenario())


def test_direct_task_cancellation_does_not_release_running_callback():
    async def scenario():
        work = BoundedWork(1)
        release = Event()
        entered = asyncio.Event()
        loop = asyncio.get_running_loop()

        def held():
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(5), "Test did not release cancelled callback"

        task = asyncio.create_task(work.run(held))
        try:
            await asyncio.wait_for(entered.wait(), 3)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(HTTPException) as error:
                await work.run(lambda: pytest.fail("Cancelled worker lost its slot"))
            assert_busy(error)
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)

        async def reuse_after_worker_exits():
            while True:
                try:
                    return await work.run(lambda: "recovered")
                except HTTPException as error:
                    assert error.status_code == 429
                    await asyncio.sleep(0)

        assert await asyncio.wait_for(reuse_after_worker_exits(), 3) == "recovered"

    asyncio.run(scenario())


def test_cancellation_before_worker_starts_releases_slot_and_disarms_late_callback(monkeypatch):
    async def scenario():
        work = BoundedWork(1)
        queued = []
        entered, never = asyncio.Event(), asyncio.Event()
        original = work_limits.anyio.to_thread.run_sync

        async def hold_before_start(callback, *args, **kwargs):
            queued.append(callback)
            entered.set()
            await never.wait()

        monkeypatch.setattr(work_limits.anyio.to_thread, "run_sync", hold_before_start)
        task = asyncio.create_task(work.run(lambda: pytest.fail("Cancelled queued callback ran")))
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        monkeypatch.setattr(work_limits.anyio.to_thread, "run_sync", original)
        assert await work.run(lambda: "available") == "available"
        # Simulate an offloader that dispatches the queued callback after the
        # awaiting task was cancelled. It must neither run nor release twice.
        assert queued[0]() is None
        assert await work.run(lambda: "still available") == "still available"

    asyncio.run(scenario())


def test_offloader_failure_before_start_releases_slot(monkeypatch):
    async def scenario():
        work = BoundedWork(1)
        original = work_limits.anyio.to_thread.run_sync

        async def fail_before_start(*args, **kwargs):
            raise RuntimeError("Synthetic offloader failure")

        monkeypatch.setattr(work_limits.anyio.to_thread, "run_sync", fail_before_start)
        with pytest.raises(RuntimeError, match="offloader"):
            await work.run(lambda: pytest.fail("Offloader ran callback"))
        monkeypatch.setattr(work_limits.anyio.to_thread, "run_sync", original)
        assert await work.run(lambda: "available") == "available"

    asyncio.run(scenario())


@pytest.mark.parametrize("capacity", [0, -1, True, 1.5])
def test_invalid_capacity_rejected(capacity):
    with pytest.raises(ValueError, match="positive integer"):
        BoundedWork(capacity)
