"""Nonwaiting admission for blocking host work, isolated from the default pool."""

from threading import BoundedSemaphore, Lock

import anyio
from fastapi import HTTPException


class _Ticket:
    """Keep admission until a running callback exits, even if its task is cancelled."""

    def __init__(self, slots):
        self.slots = slots
        self.lock = Lock()
        self.started = False
        self.cancelled = False
        self.released = False

    def start(self):
        with self.lock:
            if self.cancelled:
                return False
            self.started = True
            return True

    def _release(self):
        if not self.released:
            self.released = True
            self.slots.release()

    def finish(self):
        with self.lock:
            self._release()

    def cancel_before_start(self):
        with self.lock:
            if not self.started:
                self.cancelled = True
                self._release()


class BoundedWork:
    """Bound actual callbacks per instance without queuing excess requests.

    A worker keeps its slot until it exits. Cancelling an awaiting request cannot
    create extra capacity while its callback still runs. Cancellation before
    callback start releases the slot and makes any late queued callback a no-op.
    """

    def __init__(self, capacity, label="This operation", *, on_event=None):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        self.slots = BoundedSemaphore(capacity)
        self.label = label
        self.on_event = on_event

    async def run(self, function, *args):
        if not self.slots.acquire(blocking=False):
            if self.on_event is not None:
                self.on_event("busy")
            raise HTTPException(
                429, f"{self.label} is temporarily busy. Please try again shortly.",
                headers={"Retry-After": "1"},
            )
        ticket = _Ticket(self.slots)

        def invoke():
            if not ticket.start():
                return None
            try:
                if self.on_event is not None:
                    self.on_event("started")
                return function(*args)
            finally:
                ticket.finish()

        try:
            # The semaphore bounds all calls, including cancelled request tasks.
            # This separate limiter avoids consuming the default pool's tokens
            # and works when one app is exercised from multiple event loops.
            return await anyio.to_thread.run_sync(
                invoke, limiter=anyio.CapacityLimiter(1), abandon_on_cancel=False,
            )
        finally:
            ticket.cancel_before_start()
