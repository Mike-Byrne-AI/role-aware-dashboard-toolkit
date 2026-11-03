"""Lifespan-owned remote events and independently scheduled heartbeats."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import random
from threading import Event, Lock, Thread
import time

from .event_config import ConfigurationError, load_delivery_configuration
from .event_destinations import (
    DELIVERY_ERRORS, MAX_COUNTER, DestinationDescriptor, allocate_heartbeat, destination_status, source_identity,
)
from .event_dispatch import acknowledge_event, fail_event, prepare_event_batch
from .event_wire import load_transport, wire

LOGGER = logging.getLogger(__name__)
_SLOW_ERRORS = frozenset({"config_unavailable", "tls_failed", "remote_auth_failed", "remote_conflict", "invalid_receipt"})


def retry_delay(attempts, error, retry_after=None):
    base = min(300.0, 5.0 * 2 ** min(max(0, attempts - 1), 6))
    if error in _SLOW_ERRORS:
        base = max(60.0, base)
    delay = max(5.0, min(300.0, base * random.uniform(0.8, 1.2)))
    if type(retry_after) is int:
        delay = max(delay, max(5.0, min(300.0, retry_after)))
    return delay


def _failure(error):
    if isinstance(error, ConfigurationError):
        return "config_unavailable", None
    if isinstance(error, load_transport().DeliveryFailure):
        return (error.code if error.code in DELIVERY_ERRORS else "transport_failed"), error.retry_after
    if isinstance(error, wire.ProtocolError):
        return "invalid_receipt", None
    return "remote_unavailable", None


class RemoteSecurityEventDispatcher:
    """One thread/async loop per app; the final lifespan stop joins all work.

    Database operations run synchronously in the owned thread and complete
    before awaiting network I/O. Cancellation cannot detach a database writer.
    Two independent tasks keep heartbeats moving during a stalled event batch.
    """

    def __init__(self, database, *, config_file=None, interval=5.0, heartbeat_interval=30.0, batch_limit=20):
        if any(type(value) not in (int, float) or not math.isfinite(value) or not 0.01 <= value <= 300
               for value in (interval, heartbeat_interval)):
            raise ValueError("Invalid remote security delivery interval.")
        if type(batch_limit) is not int or not 1 <= batch_limit <= 20:
            raise ValueError("Invalid remote security delivery batch limit.")
        self.database, self.config_file = database, config_file
        self.interval, self.heartbeat_interval, self.batch_limit = float(interval), float(heartbeat_interval), batch_limit
        self._lifecycle, self._state = Lock(), Lock()
        self._thread = self._stopping = self._loop = self._async_stop = None
        self._users = 0
        self._last_cycle = self._last_delivery = self._last_heartbeat = None
        self._last_result = None
        self._delivery_error = self._heartbeat_error = None
        self._configured = False
        self._failures = self._consecutive_failures = 0

    def start(self):
        with self._lifecycle:
            self._users += 1
            if self._thread is not None:
                return
            stopping = Event()
            self._stopping = stopping
            with self._state:
                self._thread = Thread(target=self._run, args=(stopping,), name="westbridge-security-remote", daemon=True)
            try:
                self._thread.start()
            except BaseException:
                with self._state:
                    self._thread = None
                self._users -= 1
                self._stopping = None
                raise

    def stop(self):
        with self._lifecycle:
            if not self._users:
                return
            self._users -= 1
            if self._users:
                return
            self._stopping.set()
            with self._state:
                loop, stop = self._loop, self._async_stop
            if loop is not None and stop is not None:
                try:
                    loop.call_soon_threadsafe(stop.set)
                except RuntimeError:
                    pass  # The owned loop already finished; join still verifies exit.
            self._thread.join()
            with self._state:
                self._thread = self._loop = self._async_stop = None
            self._stopping = None

    def snapshot(self):
        # This function never touches the DB or waits for a lifecycle join.
        with self._state:
            return {"running": self._thread is not None and self._thread.is_alive(),
                    "configured": self._configured, "interval_seconds": self.interval,
                    "heartbeat_interval_seconds": self.heartbeat_interval, "batch_limit": self.batch_limit,
                    "last_cycle_at": self._last_cycle, "last_delivery_at": self._last_delivery,
                    "last_heartbeat_at": self._last_heartbeat,
                    "delivery_error": self._delivery_error, "heartbeat_error": self._heartbeat_error,
                    "last_result": dict(self._last_result) if self._last_result is not None else None,
                    "failed_cycles_since_start": self._failures, "consecutive_failed_cycles": self._consecutive_failures,
                    "resets_on_process_restart": True}

    def _destination(self):
        with self.database.readonly_snapshot() as connection:
            row = connection.execute("SELECT * FROM security_destinations WHERE kind='https' AND state='active'").fetchone()
            if row is None:
                return None
            identity = source_identity(connection)
            descriptor = DestinationDescriptor(row["destination_id"], row["collector_id"], row["endpoint"], row["config_revision"])
        return identity["source_id"], descriptor

    async def _deliver_once(self, stopping):
        selected = self._destination()
        if selected is None:
            return {"configured": False, "delivered": 0, "failed": 0, "pending": 0, "error": None}
        source_id, descriptor = selected
        configuration, configuration_error = None, None
        try:
            configuration = load_delivery_configuration(self.config_file, source_id=source_id, descriptor=descriptor)
        except ConfigurationError:
            configuration_error = "config_unavailable"
        with self.database.transaction() as connection:
            batch = prepare_event_batch(connection, descriptor.destination_id, limit=self.batch_limit)
        delivered = failed = 0
        for attempt in batch:
            if stopping.is_set():
                break
            error, retry_after = configuration_error, None
            if error is None:
                try:
                    if (attempt.source_id != source_id or attempt.config_revision != descriptor.config_revision
                            or attempt.endpoint != descriptor.endpoint or attempt.collector_id != descriptor.collector_id):
                        raise ConfigurationError()
                    body = await configuration.transport.post(attempt.request)
                    with self.database.transaction() as connection:
                        delivered += int(acknowledge_event(connection, attempt, body))
                except Exception as exception:
                    error, retry_after = _failure(exception)
            if error is not None:
                with self.database.transaction() as connection:
                    fail_event(connection, attempt, error,
                               retry_at=time.time() + retry_delay(attempt.attempts, error, retry_after))
                failed += 1
        with self.database.readonly_snapshot() as connection:
            status = destination_status(connection, descriptor.destination_id)
            row = connection.execute(
                "SELECT last_error FROM security_delivery_obligations WHERE destination_id=? "
                "AND acknowledged_at IS NULL AND last_error IS NOT NULL ORDER BY event_id LIMIT 1",
                (descriptor.destination_id,),
            ).fetchone()
        return {"configured": True, "destination_id": descriptor.destination_id,
                "delivered": delivered, "failed": failed, "pending": status["pending"],
                "error": configuration_error or (row[0] if row is not None else None)}

    async def _heartbeat_once(self):
        selected = self._destination()
        if selected is None:
            return None
        source_id, descriptor = selected
        configuration = load_delivery_configuration(self.config_file, source_id=source_id, descriptor=descriptor)
        with self.database.transaction() as connection:
            row = connection.execute(
                "SELECT last_error FROM security_delivery_obligations WHERE destination_id=? "
                "AND acknowledged_at IS NULL AND last_error IS NOT NULL ORDER BY event_id LIMIT 1",
                (descriptor.destination_id,),
            ).fetchone()
            heartbeat = allocate_heartbeat(connection, descriptor.destination_id, delivery_error=row[0] if row else None)
        fields = json.loads(heartbeat.data)
        expected = {key: fields[key] for key in ("collector_id", "destination_id", "source_id", "sequence")}
        expected["sha256"] = heartbeat.sha256
        body = await configuration.transport.post(heartbeat.data, heartbeat=True)
        receipt = wire.parse_heartbeat_receipt(body, expected)
        # A config/cutover concurrent with I/O cannot report a current success.
        if self._destination() != selected:
            raise ConfigurationError()
        return receipt.fields["received_at"]

    def _record_cycle(self, result, error=None):
        failed = error is not None or result is not None and result["error"] is not None
        now = time.time()
        with self._state:
            previous = self._consecutive_failures > 0
            self._last_cycle, self._last_result = now, result
            self._configured = result["configured"] if result is not None else True
            self._delivery_error = error or (result["error"] if result is not None else "remote_unavailable")
            if result is not None and result["delivered"]:
                self._last_delivery = now
            if failed:
                self._failures = min(MAX_COUNTER, self._failures + 1)
                self._consecutive_failures = min(MAX_COUNTER, self._consecutive_failures + 1)
            else:
                self._consecutive_failures = 0
        if failed and not previous:
            LOGGER.error("Remote security-event delivery failed; inspect durable destination status.")
        elif previous and not failed:
            LOGGER.info("Remote security-event delivery resumed; inspect remaining obligations separately.")

    async def _delivery_loop(self, stopping):
        while not stopping.is_set():
            try:
                result = await self._deliver_once(stopping)
            except Exception:
                self._record_cycle(None, "remote_unavailable")
            else:
                self._record_cycle(result)
            await asyncio.sleep(self.interval)

    async def _heartbeat_loop(self, stopping):
        while not stopping.is_set():
            error, received = None, None
            try:
                received = await self._heartbeat_once()
            except Exception as exception:
                error, _ = _failure(exception)
            with self._state:
                self._heartbeat_error = error
                if received is not None:
                    self._last_heartbeat = received
            await asyncio.sleep(self.heartbeat_interval)

    async def _serve(self, stopping):
        stop = asyncio.Event()
        with self._state:
            self._loop, self._async_stop = asyncio.get_running_loop(), stop
        if stopping.is_set():
            return
        tasks = [asyncio.create_task(self._delivery_loop(stopping)), asyncio.create_task(self._heartbeat_loop(stopping))]
        stop_wait = asyncio.create_task(stop.wait())
        try:
            completed, _ = await asyncio.wait([*tasks, stop_wait], return_when=asyncio.FIRST_COMPLETED)
            if stop_wait not in completed:
                raise RuntimeError("An owned remote security worker stopped unexpectedly.")
        finally:
            for task in (*tasks, stop_wait):
                task.cancel()
            await asyncio.gather(*tasks, stop_wait, return_exceptions=True)

    def _run(self, stopping):
        try:
            asyncio.run(self._serve(stopping))
        except Exception:
            self._record_cycle(None, "remote_unavailable")
        finally:
            with self._state:
                self._loop = self._async_stop = None
