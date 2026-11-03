"""Actual disposable TLS peers exercise bounded delivery, not mocked HTTPX."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
from pathlib import Path
import ssl
import sys
import time

import pytest

cryptography = pytest.importorskip("cryptography")
pytest.importorskip("httpx")
from cryptography import x509  # noqa: E402 -- optional dependencies are checked before importing
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

PATH = Path(__file__).resolve().parents[1] / "examples/security_event_wire/transport.py"
SPEC = importlib.util.spec_from_file_location("_security_transport_test", PATH)
transport = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport
SPEC.loader.exec_module(transport)
TOKEN = "A" * 43  # Synthetic scoped bearer, never an existing service credential.


@pytest.fixture
def tls_files(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable transport fixture")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "tls.pem", tmp_path / "tls-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return cert_file, key_file


@asynccontextmanager
async def peer(tls_files, responder):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*map(str, tls_files))
    tasks, requests = set(), []

    async def handle(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            headers = await reader.readuntil(b"\r\n\r\n")
            length = next(int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                          if line.lower().startswith(b"content-length:"))
            body = await reader.readexactly(length)
            # Assert auth on the peer; omit it from recorded requests/assertion output.
            if not any(line.split(b":", 1)[0].lower() == b"authorization"
                       and line.split(b":", 1)[1].strip() == b"Bearer " + TOKEN.encode()
                       for line in headers.split(b"\r\n")[1:] if b":" in line):
                raise AssertionError("The expected synthetic scoped bearer was not received.")
            requests.append((headers.split(b"\r\n", 1)[0], body))
            await responder(writer)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass
            tasks.discard(task)

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"https://127.0.0.1:{port}/v1/events", requests
    finally:
        server.close()
        await server.wait_closed()
        remaining = tuple(tasks)
        for task in remaining:
            task.cancel()
        await asyncio.gather(*remaining, return_exceptions=True)


def reply(body=b'{"receipt":true}', *, status=200, extra=b"", length=True):
    async def respond(writer):
        header = b"HTTP/1.1 " + str(status).encode() + b" Result\r\nContent-Type: application/json\r\n"
        if length:
            header += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        writer.write(header + extra + b"Connection: close\r\n\r\n" + body)
        await writer.drain()
    return respond


def test_tls_copies_bytes_and_ignores_proxy_and_ca_environment(tls_files, monkeypatch):
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(key, "http://127.0.0.1:1")
    monkeypatch.setenv("SSL_CERT_FILE", "does-not-exist.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "does-not-exist")

    async def run():
        async with peer(tls_files, reply()) as (endpoint, requests):
            sender = transport.HttpsTransport(endpoint, TOKEN, ca_file=str(tls_files[0]))
            assert TOKEN not in repr(sender)
            assert await sender.post(b'{"v":1}') == b'{"receipt":true}'
            assert await sender.post(b'{"v":2}', heartbeat=True) == b'{"receipt":true}'
            assert requests == [(b"POST /v1/events HTTP/1.1", b'{"v":1}'),
                                (b"POST /v1/heartbeat HTTP/1.1", b'{"v":2}')]
    asyncio.run(run())


@pytest.mark.parametrize("mutation", ["untrusted", "hostname"])
def test_wrong_tls_authority_or_hostname_fails_without_http(tls_files, mutation):
    async def run():
        async with peer(tls_files, reply()) as (endpoint, requests):
            if mutation == "hostname":
                endpoint = endpoint.replace("127.0.0.1", "localhost")
            sender = transport.HttpsTransport(endpoint, TOKEN, ca_file=None if mutation == "untrusted" else str(tls_files[0]))
            with pytest.raises(transport.DeliveryFailure) as failed:
                await sender.post(b"{}")
            assert failed.value.code == "tls_failed"
            assert TOKEN not in str(failed.value)
            assert not requests
    asyncio.run(run())


@pytest.mark.parametrize("status,extra,body,length,code", [
    (302, b"Location: https://127.0.0.1:1/v1/events\r\n", b"{}", True, "invalid_receipt"),
    (202, b"", b"{}", True, "invalid_receipt"),
    (401, b"", b"{}", True, "remote_auth_failed"),
    (403, b"", b"{}", True, "remote_auth_failed"),
    (409, b"", b"{}", True, "remote_conflict"),
    (429, b"Retry-After: 99999999\r\n", b"{}", True, "remote_throttled"),
    (503, b"", b"{}", True, "remote_unavailable"),
    (507, b"", b"{}", True, "remote_capacity"),
    (200, b"Content-Encoding: gzip\r\n", b"{}", True, "invalid_receipt"),
    (200, b"Content-Type: text/html\r\n", b"{}", True, "invalid_receipt"),
    (200, b"", b"x" * 2049, True, "invalid_receipt"),
    (200, b"", b"x" * 2049, False, "invalid_receipt"),
    (400, b"", b"x" * 257, False, "invalid_receipt"),
    (200, b"", b"", True, "invalid_receipt"),
], ids=["redirect", "accepted-only", "unauthorized", "forbidden", "conflict", "throttled",
        "unavailable", "capacity", "compression", "duplicate-media", "large-declared", "large-stream",
        "large-error", "empty"])
def test_failures_never_return_delivery_receipts(tls_files, status, extra, body, length, code):
    async def run():
        async with peer(tls_files, reply(body, status=status, extra=extra, length=length)) as (endpoint, requests):
            sender = transport.HttpsTransport(endpoint, TOKEN, ca_file=str(tls_files[0]))
            with pytest.raises(transport.DeliveryFailure) as failed:
                await sender.post(b"{}")
            assert failed.value.code == code
            assert failed.value.retry_after == (300 if status == 429 else None)
            assert len(requests) == 1
    asyncio.run(run())


def test_total_deadline_terminates_a_trickling_response(tls_files):
    async def trickle(writer):
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n")
        await writer.drain()
        for _ in range(70):
            writer.write(b" ")
            await writer.drain()
            await asyncio.sleep(0.1)

    async def run():
        async with peer(tls_files, trickle) as (endpoint, _):
            sender = transport.HttpsTransport(endpoint, TOKEN, ca_file=str(tls_files[0]))
            started = time.monotonic()
            with pytest.raises(transport.DeliveryFailure, match="transport_failed"):
                await sender.post(b"{}")
            assert 4.8 <= time.monotonic() - started < 6.5
    asyncio.run(run())


@pytest.mark.parametrize("endpoint", [
    "http://127.0.0.1/v1/events", "https://user:secret@example.test/v1/events",
    "https://example.test/v1/events?token=secret", "https://example.test/v1/events#fragment",
    "https://example.test/v1/other", "https://example.test:0/v1/events",
    "https://example.test/v1/%65vents", "https://example.test\\evil/v1/events",
    "https://example.test/\nv1/events", "https://example.test/v1/events?", "https://example.test/v1/events#",
])
def test_unregistered_or_ambiguous_endpoint_is_rejected(endpoint):
    with pytest.raises(transport.DeliveryFailure, match="config_unavailable"):
        transport.HttpsTransport(endpoint, TOKEN)


def test_oversize_body_and_heartbeat_on_inbox_are_rejected_before_io():
    async def run():
        sender = transport.HttpsTransport("https://127.0.0.1:1/v1/alerts", TOKEN)
        for body, heartbeat in ((b"x" * 4097, False), (b"{}", True), (b"", False), ("{}", False)):
            with pytest.raises(transport.DeliveryFailure, match="config_unavailable"):
                await sender.post(body, heartbeat=heartbeat)
    asyncio.run(run())
