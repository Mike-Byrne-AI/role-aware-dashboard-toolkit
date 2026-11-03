"""Separate bounded alert transport; a receipt never impersonates human review."""

import asyncio
from functools import partial
import logging
from pathlib import Path
import sqlite3

import anyio

from .event_wire import load_transport, wire
from .private_files import check_private_file, private_directory
from .service import ERRORS
from .storage import ServiceError, verifier

LOGGER = logging.getLogger("security_event_collector.notifications")


class Notifier:
    def __init__(self, service, *, token_file=None, ca_file=None):
        self.service = service
        self.token_file = Path(token_file) if token_file is not None else None
        self.ca_file = Path(ca_file) if ca_file is not None else None
        if any(path is not None and not path.is_absolute() for path in (self.token_file, self.ca_file)):
            raise ValueError("Use absolute private notification credential and CA paths.")

    def _transport(self):
        transport = load_transport()
        try:
            with self.service.store.read() as connection:
                row = connection.execute("SELECT endpoint FROM alert_destination WHERE id=1").fetchone()
            if row is None or row[0] is None or self.token_file is None:
                raise ValueError("Missing notification configuration.")
            private_directory(self.token_file.parent)
            path = check_private_file(self.token_file)
            if path.stat().st_size > 256:
                raise ValueError("Invalid notification credential file.")
            token = path.read_text(encoding="ascii").strip()
            verifier(token)
            if self.ca_file is not None:
                private_directory(self.ca_file.parent)
                check_private_file(self.ca_file)
            return transport.HttpsTransport(row[0], token, ca_file=str(self.ca_file) if self.ca_file else None)
        except (OSError, ValueError, ServiceError, UnicodeError):
            raise transport.DeliveryFailure("config_unavailable") from None

    async def dispatch_once(self, stop=None):
        transport_module = load_transport()
        completed = 0
        pending = await anyio.to_thread.run_sync(self.service.pending_alerts, abandon_on_cancel=False)
        for item in pending:
            if stop is not None and stop.is_set():
                break
            delivery = await anyio.to_thread.run_sync(self.service.begin_alert_attempt, item.alert_id, item.number, abandon_on_cancel=False)
            if delivery is None:
                continue
            try:
                transport = await anyio.to_thread.run_sync(self._transport, abandon_on_cancel=False)
                # No SQLite context exists across this bounded network wait.
                receipt = await transport.post(delivery.body)
                await anyio.to_thread.run_sync(self.service.ack_alert, delivery.alert_id, delivery.number, receipt, abandon_on_cancel=False)
                completed += 1
            except wire.ProtocolError:
                await anyio.to_thread.run_sync(self.service.fail_alert, delivery.alert_id, delivery.number, "invalid_receipt", abandon_on_cancel=False)
                LOGGER.warning("Alert delivery failed: invalid_receipt")
            except transport_module.DeliveryFailure as error:
                code = error.code if error.code in ERRORS else "transport_failed"
                persist_failure = partial(self.service.fail_alert, delivery.alert_id, delivery.number, code, retry_after=error.retry_after)
                await anyio.to_thread.run_sync(persist_failure, abandon_on_cancel=False)
                LOGGER.warning("Alert delivery failed: %s", code)
        return completed

    async def run(self, stop):
        while not stop.is_set():
            try:
                await self.dispatch_once(stop)
            except (ValueError, OSError, ServiceError, sqlite3.Error):
                LOGGER.warning("Alert delivery state unavailable; obligations remain pending.")
            try:
                await asyncio.wait_for(stop.wait(), timeout=5)
            except asyncio.TimeoutError:
                continue
