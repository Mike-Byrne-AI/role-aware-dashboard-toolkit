"""Explicit private delivery configuration; never consult ambient host settings."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import ssl

from .db import SOURCE_ROOTS, check_private_file, validate_data_dir
from .event_destinations import DestinationDescriptor
from .event_wire import load_transport

MAX_CONFIG_BYTES = 16384
MAX_CA_BYTES = 65536
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_FIELDS = frozenset({"v", "source_id", "collector_id", "destination_id", "endpoint", "token_file", "ca_file"})


class ConfigurationError(ValueError):
    def __init__(self):
        super().__init__("Private security delivery configuration is unavailable or invalid.")


@dataclass(frozen=True, repr=False)
class RemoteConfiguration:
    source_id: str
    descriptor: DestinationDescriptor
    transport: object

    def __repr__(self):
        return "RemoteConfiguration(<protected configuration>)"


def _private_file(value, maximum):
    if not isinstance(value, (str, Path)) or not value:
        raise ConfigurationError()
    path = Path(value)
    if not path.is_absolute():
        raise ConfigurationError()
    resolved = path.resolve()
    if any(resolved == root or root in resolved.parents for root in SOURCE_ROOTS):
        raise ConfigurationError()
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ConfigurationError()
        if item.is_dir() and os.path.lexists(item / ".git"):
            raise ConfigurationError()
    validate_data_dir(path.parent)
    check_private_file(path)
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ConfigurationError()
    return resolved, data


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError()
        result[key] = value
    return result


def _invalid_number(_):
    raise ConfigurationError()


def load_delivery_configuration(config_file, *, source_id, descriptor):
    """Validate credentials and TLS trust before activation or remote I/O."""
    try:
        if not isinstance(descriptor, DestinationDescriptor) or not re.fullmatch(r"[0-9a-f]{32}", source_id):
            raise ConfigurationError()
        _, data = _private_file(config_file, MAX_CONFIG_BYTES)
        # This is a small operator file, not a permissive settings overlay.
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_invalid_number)
        if (type(value) is not dict or set(value) != _FIELDS or type(value["v"]) is not int or value["v"] != 1
                or value["source_id"] != source_id or value["collector_id"] != descriptor.collector_id
                or value["destination_id"] != descriptor.destination_id or value["endpoint"] != descriptor.endpoint):
            raise ConfigurationError()
        _, token_bytes = _private_file(value["token_file"], 45)
        token = token_bytes.decode("ascii")
        if token.endswith("\r\n"):
            token = token[:-2]
        elif token.endswith("\n"):
            token = token[:-1]
        if not _TOKEN.fullmatch(token):
            raise ConfigurationError()
        ca_file = None
        if value["ca_file"] is not None:
            path, pem = _private_file(value["ca_file"], MAX_CA_BYTES)
            ssl.create_default_context(cadata=pem.decode("ascii"))
            ca_file = str(path)
        transport = load_transport().HttpsTransport(descriptor.endpoint, token, ca_file=ca_file)
        return RemoteConfiguration(source_id, descriptor, transport)
    except (OSError, ValueError, TypeError, RecursionError):
        raise ConfigurationError() from None
