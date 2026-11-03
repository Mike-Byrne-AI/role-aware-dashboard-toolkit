"""Small bounded ASGI ingress; no cookies, proxy trust or credential reflection."""

import asyncio
import json
import logging
import sqlite3
from threading import BoundedSemaphore, Lock
import time

import anyio

from .event_wire import wire
from .inbox import Inbox
from .pagination import parse_query
from .service import Collector
from .storage import ServiceError, Store, safe_json

LOGGER = logging.getLogger("security_event_collector")


class _Admission:
    """A cancelled waiter cannot release a slot while its callback still runs."""
    def __init__(self, gate):
        self.gate, self.lock = gate, Lock()
        self.closed = self.running = self.released = False

    def _release(self):
        if not self.released:
            self.released = True
            self.gate.release()

    def close(self):
        with self.lock:
            self.closed = True
            if not self.running:
                self._release()

    async def run(self, function, *args):
        def invoke():
            with self.lock:
                if self.closed:
                    return None
                self.running = True
            try:
                return function(*args)
            finally:
                with self.lock:
                    self.running = False
                    if self.closed:
                        self._release()
        return await anyio.to_thread.run_sync(invoke, limiter=anyio.CapacityLimiter(1), abandon_on_cancel=False)


class Application:
    def __init__(self, service, *, evaluator=True, notifier=None):
        self.service = service
        self.evaluator = evaluator and isinstance(service, Collector)
        self.notifier = notifier
        self.gates = {"events": BoundedSemaphore(2), "heartbeat": BoundedSemaphore(1), "operator": BoundedSemaphore(1)}

    async def _evaluate(self, stop):
        while not stop.is_set():
            try:
                await anyio.to_thread.run_sync(self.service.evaluate_alerts, abandon_on_cancel=False)
            except (ValueError, ServiceError, sqlite3.Error, OSError):
                LOGGER.warning("Collector alert evaluation unavailable; independent monitoring is required.")
            try:
                await asyncio.wait_for(stop.wait(), timeout=10)
            except asyncio.TimeoutError:
                continue

    async def _lifespan(self, receive, send):
        stop, tasks = asyncio.Event(), []
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                if self.evaluator:
                    tasks.append(asyncio.create_task(self._evaluate(stop)))
                if self.notifier is not None:
                    tasks.append(asyncio.create_task(self.notifier.run(stop)))
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                stop.set()
                for task in tasks:
                    await task
                await send({"type": "lifespan.shutdown.complete"})
                return

    @staticmethod
    def _headers(scope, *, body_required):
        values = {}
        for name, value in scope.get("headers", []):
            name = name.lower()
            if name in {b"authorization", b"content-type", b"content-length", b"content-encoding"}:
                if name in values or len(value) > 256:
                    raise ServiceError("unauthenticated" if name == b"authorization" else "invalid_message", 401 if name == b"authorization" else 400)
                values[name] = value
        authorization = values.get(b"authorization", b"")
        if not authorization.startswith(b"Bearer ") or len(authorization) != 50:
            raise ServiceError("unauthenticated", 401)
        try:
            token = authorization[7:].decode("ascii")
        except UnicodeError:
            raise ServiceError("unauthenticated", 401) from None
        if body_required and values.get(b"content-type", b"") != b"application/json":
            raise ServiceError("unsupported_media", 415)
        if values.get(b"content-encoding", b"identity") != b"identity":
            raise ServiceError("unsupported_media", 415)
        length = values.get(b"content-length")
        if length is not None:
            if not length or len(length) > 10 or not length.isdigit():
                raise ServiceError("invalid_message", 400)
            length = int(length)
        return token, length

    @staticmethod
    async def _body(receive, limit, declared):
        if declared is not None and declared > limit:
            raise ServiceError("body_too_large", 413)
        data = bytearray()
        async def read_body():
            while True:
                # Buffered or empty chunks can make receive() return without
                # suspending. Let the total deadline and cancellation run even
                # while the transport has immediately available messages.
                await anyio.lowlevel.checkpoint()
                message = await receive()
                if message["type"] != "http.request":
                    raise ServiceError("invalid_message", 400)
                chunk = message.get("body", b"")
                if len(chunk) > limit - len(data):
                    raise ServiceError("body_too_large", 413)
                data.extend(chunk)
                if not message.get("more_body", False):
                    return
        try:
            await asyncio.wait_for(read_body(), timeout=5)
        except asyncio.TimeoutError:
            raise ServiceError("deadline_exceeded", 408) from None
        if declared is not None and len(data) != declared:
            raise ServiceError("invalid_message", 400)
        return bytes(data)

    def _operator(self, token, method, path, body, pagination=None):
        if method == "GET":
            if isinstance(self.service, Collector) and path == "/v1/operator/alerts":
                return safe_json(self.service.page_alerts(token, **(pagination or {})))
            if isinstance(self.service, Collector) and path == "/v1/operator/status":
                return safe_json(self.service.status(token))
            if isinstance(self.service, Inbox) and path == "/v1/operator/messages":
                return safe_json(self.service.page_messages(token, **(pagination or {})))
        if method == "POST":
            # The separate operator protocol accepts just the exact revision.
            # Duplicate keys/noncanonical spellings cannot hide another action.
            try:
                value = json.loads(body)
            except (ValueError, UnicodeError, RecursionError):
                raise ServiceError("invalid_message", 400) from None
            if not isinstance(value, dict) or set(value) != {"number"} or type(value["number"]) is not int or value["number"] < 1 or safe_json(value) != body:
                raise ServiceError("invalid_message", 400)
            parts = path.split("/")
            if isinstance(self.service, Collector) and len(parts) == 6 and parts[1:4] == ["v1", "operator", "alerts"] and parts[5] in {"ack", "resolve"}:
                self.service.acknowledge_alert(token, parts[4], value["number"], resolve=parts[5] == "resolve")
                return safe_json({"ok": True})
            if isinstance(self.service, Inbox) and len(parts) == 7 and parts[1:4] == ["v1", "operator", "messages"] and parts[6] == "ack":
                self.service.acknowledge_message(token, parts[4], parts[5], value["number"])
                return safe_json({"ok": True})
        raise ServiceError("unavailable", 404)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self._lifespan(receive, send)
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        status, result, gate = 200, b"", None
        try:
            method, path = scope["method"], scope["path"]
            pagination = {}
            if scope.get("query_string", b""):
                list_route = (isinstance(self.service, Collector) and path == "/v1/operator/alerts"
                              or isinstance(self.service, Inbox) and path == "/v1/operator/messages")
                if method != "GET" or not list_route:
                    raise ServiceError("invalid_message", 400)
                pagination = parse_query(scope["query_string"])
            if method == "GET" and path == "/healthz":
                result = safe_json({"status": "alive"})
            else:
                namespace = "heartbeat" if path == "/v1/heartbeat" else "operator" if path.startswith("/v1/operator/") else "events"
                selected = self.gates[namespace]
                if not selected.acquire(blocking=False):
                    raise ServiceError("capacity_busy", 429)
                gate = _Admission(selected)
                token, length = self._headers(scope, body_required=method == "POST")
                role = "operator" if namespace == "operator" else "ingest"
                await gate.run(self.service.store.authenticate, token, role)
                await gate.run(self.service.store.reserve_intake, namespace)
                body = await self._body(receive, 2048 if namespace != "events" else 4096, length)
                if namespace == "operator":
                    result = await gate.run(self._operator, token, method, path, body, pagination)
                elif method == "POST" and path == "/v1/events" and isinstance(self.service, Collector):
                    result = await gate.run(self.service.ingest_event, token, body)
                elif method == "POST" and path == "/v1/heartbeat" and isinstance(self.service, Collector):
                    result = await gate.run(self.service.accept_heartbeat, token, body)
                elif method == "POST" and path == "/v1/alerts" and isinstance(self.service, Inbox):
                    result = await gate.run(self.service.ingest_alert, token, body)
                else:
                    raise ServiceError("unavailable", 404)
        except ServiceError as error:
            status, result = error.status, safe_json({"v": 1, "error": error.code})
        except wire.ProtocolError:
            status, result = 400, safe_json({"v": 1, "error": "invalid_message"})
        except (ValueError, sqlite3.Error, OSError):
            LOGGER.warning("Collector request refused by a storage or state control.")
            status, result = 503, safe_json({"v": 1, "error": "unavailable"})
        except Exception:
            LOGGER.error("Collector request failed unexpectedly; private operational investigation is required.")
            status, result = 503, safe_json({"v": 1, "error": "unavailable"})
        finally:
            if gate is not None:
                gate.close()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(result)).encode("ascii")),
            (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"),
        ]})
        await send({"type": "http.response.body", "body": result})


def create_app(directory, *, clock=time.time, evaluator=True, notification_token_file=None, notification_ca_file=None):
    from .notifications import Notifier
    store = Store(directory, clock=clock)
    service = Collector(directory, clock=clock) if store.settings["kind"] == "collector" else Inbox(directory, clock=clock)
    notifier = Notifier(service, token_file=notification_token_file, ca_file=notification_ca_file) if isinstance(service, Collector) else None
    return Application(service, evaluator=evaluator, notifier=notifier)
