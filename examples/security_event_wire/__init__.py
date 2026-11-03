"""Shared example-private wire core; optional HTTP transport is not imported."""

from . import protocol

_WIRE_READY = True

__all__ = ["protocol"]
