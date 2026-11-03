"""Optional bounded HTTPS delivery for the two example-owned writers.

Requires HTTPX; the wire codec and its bootstrap remain dependency-free.
This module neither retries nor acknowledges delivery. Callers must validate
the returned receipt against their persisted obligation before acknowledging.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import re
import ssl
from urllib.parse import urlsplit, urlunsplit

import httpx

MAX_REQUEST_BYTES = 4096
MAX_RECEIPT_BYTES = 2048
MAX_ERROR_BYTES = 256
TOTAL_SECONDS = 5.0
MAX_RETRY_AFTER = 300
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class DeliveryFailure(ValueError):
    """A fixed diagnostic code; never contains credentials or remote content."""

    def __init__(self, code, *, retry_after=None):
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after


def endpoint_origin(endpoint):
    """Accept only an operator-registered fixed intake URL, with no URL secrets."""
    if (not isinstance(endpoint, str) or not endpoint.isascii() or len(endpoint) > 2048
            or any(ord(char) <= 32 or ord(char) == 127 for char in endpoint)
            or "\\" in endpoint or "%" in endpoint):
        raise DeliveryFailure("config_unavailable")
    try:
        parts = urlsplit(endpoint)
        valid = (parts.scheme == "https" and parts.hostname and parts.netloc
                 and parts.username is None and parts.password is None
                 and not parts.query and not parts.fragment and parts.port != 0
                 and parts.path in ("/v1/events", "/v1/alerts") and parts.geturl() == endpoint)
    except ValueError:
        valid = False
    if not valid:
        raise DeliveryFailure("config_unavailable")
    return urlunsplit(("https", parts.netloc, "", "", "")), parts.path


def _tls_failure(error):
    # HTTPX/httpcore wrap certificate errors. Inspect exception types without
    # serializing messages, URLs, headers or peer-provided response bodies.
    visited = set()
    while error is not None and id(error) not in visited:
        visited.add(id(error))
        if isinstance(error, ssl.SSLError) and not isinstance(error, (ssl.SSLWantReadError, ssl.SSLWantWriteError)):
            return True
        error = error.__cause__ or error.__context__
    return False


def _retry_after(response):
    values = response.headers.get_list("retry-after")
    if len(values) != 1 or not re.fullmatch(r"[0-9]{1,10}", values[0]):
        return None
    return min(int(values[0]), MAX_RETRY_AFTER)


@dataclass(frozen=True, repr=False)
class HttpsTransport:
    """A fixed destination and scoped token; each attempt has its own client.

    Independent clients avoid cookies, ambient authentication and shared
    connection state. A heartbeat uses the same registered events origin.
    Cancellation closes the response/client and never marks an event delivered.
    """

    endpoint: str
    token: str
    ca_file: str | None = None

    def __post_init__(self):
        endpoint_origin(self.endpoint)
        if not isinstance(self.token, str) or not _TOKEN.fullmatch(self.token):
            raise DeliveryFailure("config_unavailable")
        if self.ca_file is not None and (not isinstance(self.ca_file, str) or not self.ca_file):
            raise DeliveryFailure("config_unavailable")

    def __repr__(self):
        return "HttpsTransport(<protected configuration>)"

    async def post(self, body, *, heartbeat=False):
        if type(body) is not bytes or not 0 < len(body) <= MAX_REQUEST_BYTES or type(heartbeat) is not bool:
            raise DeliveryFailure("config_unavailable")
        origin, path = endpoint_origin(self.endpoint)
        if heartbeat and (path != "/v1/events" or len(body) > MAX_RECEIPT_BYTES):
            raise DeliveryFailure("config_unavailable")
        endpoint = origin + "/v1/heartbeat" if heartbeat else self.endpoint
        try:
            # Explicit CA construction avoids SSL_CERT_FILE/SSL_CERT_DIR from
            # changing transport trust. The configured private CA file, when
            # present, is intentionally the complete trust store for this hop.
            if self.ca_file:
                context = ssl.create_default_context(cafile=self.ca_file)
            else:
                import certifi

                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.load_verify_locations(cafile=certifi.where())
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            return await asyncio.wait_for(self._exchange(endpoint, body, context), timeout=TOTAL_SECONDS)
        except DeliveryFailure:
            raise
        except (asyncio.TimeoutError, httpx.TimeoutException):
            raise DeliveryFailure("transport_failed") from None
        except (OSError, ValueError, httpx.HTTPError, asyncio.TimeoutError) as error:
            code = "tls_failed" if _tls_failure(error) else "transport_failed"
            raise DeliveryFailure(code) from None

    async def _exchange(self, endpoint, body, context):
        async with httpx.AsyncClient(
            verify=context, trust_env=False, follow_redirects=False, http2=False,
            timeout=httpx.Timeout(TOTAL_SECONDS), limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        ) as client:
            async with client.stream("POST", endpoint, content=body, headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity",
            }) as response:
                maximum = MAX_RECEIPT_BYTES if response.status_code == 200 else MAX_ERROR_BYTES
                encodings = response.headers.get_list("content-encoding")
                media = response.headers.get_list("content-type")
                lengths = response.headers.get_list("content-length")
                if (encodings not in ([], ["identity"]) or len(media) != 1
                        or media[0].lower() != "application/json" or len(lengths) > 1
                        or (lengths and (not re.fullmatch(r"[0-9]{1,10}", lengths[0]) or int(lengths[0]) > maximum))):
                    raise DeliveryFailure("invalid_receipt")
                received = bytearray()
                async for chunk in response.aiter_raw():
                    if len(chunk) > maximum - len(received):
                        raise DeliveryFailure("invalid_receipt")
                    received.extend(chunk)
                if response.status_code != 200:
                    code = {401: "remote_auth_failed", 403: "remote_auth_failed", 409: "remote_conflict",
                            429: "remote_throttled", 503: "remote_unavailable", 507: "remote_capacity"}.get(
                                response.status_code, "invalid_receipt")
                    raise DeliveryFailure(code, retry_after=_retry_after(response))
                if not received:
                    raise DeliveryFailure("invalid_receipt")
                return bytes(received)
