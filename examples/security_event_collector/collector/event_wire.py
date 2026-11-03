"""Resolve the sibling example-private wire implementation from reviewed source."""

from pathlib import Path
import runpy

_bootstrap = Path(__file__).resolve().parents[2] / "security_event_wire" / "bootstrap.py"
if not _bootstrap.is_file():
    raise ImportError("The shared security wire source package is missing.")
_loader = runpy.run_path(str(_bootstrap))
wire = _loader["load_wire"]()
load_transport = _loader["load_transport"]
