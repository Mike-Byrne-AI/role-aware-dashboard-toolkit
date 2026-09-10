"""Explicit command entry point; normal package imports remain quiet."""
import sys

from .cli import main

if __name__ == "__main__":
    # Pipe output uses the same UTF-8 encoding as bundled guide/example files.
    for stream in (sys.stdout, sys.stderr):
        if callable(getattr(stream, "reconfigure", None)):
            stream.reconfigure(encoding="utf-8")
    raise SystemExit(main())
