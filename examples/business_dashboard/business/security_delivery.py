"""Lifespan-owned, bounded local delivery of committed security events."""

from __future__ import annotations

import logging
from threading import Event, Lock, Thread
import time

from .security_events import MAX_COUNTER, delivery_status, dispatch_pending

LOGGER = logging.getLogger(__name__)


class SecurityEventDispatcher:
    """One local worker per app, shared safely by overlapping lifespans.

    The final stop waits for the current local delivery operation, never abandons
    a writer. Dispatch checks for shutdown between events. No network consumer,
    unbounded task queue, or cross-event-loop synchronization is involved.
    """

    def __init__(self, database, *, interval=5.0, batch_limit=100):
        if not isinstance(interval, (int, float)) or not 0.01 <= interval <= 60:
            raise ValueError("Invalid security delivery interval.")
        if type(batch_limit) is not int or not 1 <= batch_limit <= 100:
            raise ValueError("Invalid security delivery batch limit.")
        self.database, self.interval, self.batch_limit = database, float(interval), batch_limit
        self._lifecycle = Lock()
        self._state = Lock()
        self._thread = None
        self._stop = None
        self._users = 0
        self._last_cycle = None
        self._last_delivery = None
        self._last_result = None
        self._failures = 0
        self._consecutive_failures = 0

    def start(self):
        with self._lifecycle:
            self._users += 1
            if self._thread is not None:
                return
            self._stop = Event()
            with self._state:
                self._thread = Thread(target=self._run, args=(self._stop,),
                                      name="westbridge-security-delivery", daemon=True)
            try:
                self._thread.start()
            except BaseException:
                with self._state:
                    self._thread = None
                self._users -= 1
                raise

    def stop(self):
        with self._lifecycle:
            if self._users == 0:
                return
            self._users -= 1
            if self._users:
                return
            self._stop.set()
            self._thread.join()
            with self._state:
                self._thread = None
            self._stop = None

    def snapshot(self):
        # Never wait for the lifecycle join while a caller holds a DB read or
        # write transaction: the worker may need that transaction to finish.
        with self._state:
            running = self._thread is not None and self._thread.is_alive()
            return {"running": running, "interval_seconds": self.interval,
                    "batch_limit": self.batch_limit, "last_cycle_at": self._last_cycle,
                    "last_delivery_at": self._last_delivery,
                    "last_result": dict(self._last_result) if self._last_result is not None else None,
                    "failed_cycles_since_start": self._failures,
                    "consecutive_failed_cycles": self._consecutive_failures,
                    "resets_on_process_restart": True}

    def _run(self, stopping):
        while not stopping.is_set():
            result = None
            try:
                result = dispatch_pending(self.database, limit=self.batch_limit,
                                          stop_requested=stopping.is_set)
                # A retry-deferred cycle can attempt nothing while a previous
                # failed obligation remains. Only the durable acknowledgement
                # clears that failure; an empty batch is not recovery. Read
                # outside the state lock so protected status stays nonblocking.
                with self.database.readonly_snapshot() as connection:
                    unresolved = delivery_status(connection)["failed"] > 0
                failed = result["failed"] > 0 or unresolved
            except Exception:
                failed = True
            now = time.time()
            with self._state:
                previously_failed = self._consecutive_failures > 0
                self._last_cycle = now
                self._last_result = result
                if result is not None and result["delivered"]:
                    self._last_delivery = now
                if failed:
                    self._failures = min(MAX_COUNTER, self._failures + 1)
                    self._consecutive_failures = min(MAX_COUNTER, self._consecutive_failures + 1)
                else:
                    self._consecutive_failures = 0
            if failed and not previously_failed:
                LOGGER.error("Automatic security-event delivery failed; pending obligations remain. Inspect protected delivery status.")
            elif previously_failed and not failed:
                LOGGER.info("Automatic security-event delivery resumed; inspect pending obligations separately.")
            stopping.wait(self.interval)
