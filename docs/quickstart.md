# Quickstart

This walkthrough uses the dependency-free core. It creates a control registry,
captures a profile, records a run checkpoint, and exports a validated packet.

## Install

From a source checkout:

```bash
python -m pip install -e .
```

After publication:

```bash
python -m pip install role-aware-dashboard-toolkit
```

## Build a registry and state

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register(
    "Request timeout",
    kind="number",
    key="request_timeout_seconds",
    min_value=1,
    max_value=120,
    default=30,
)
registry.register(
    "Maintenance mode",
    kind="toggle",
    key="maintenance_mode",
    default=False,
)

state = {}
registry.ensure_defaults(state)
```

## Capture a profile

```python
profile = radt.build_profile(
    "baseline",
    registry,
    state,
    role="Operator",
    source="quickstart",
)
```

`build_profile()` is side-effect free. Use `save_profile()` with an explicit
store when you want persistence.

## Record a run and checkpoint

```python
run = radt.build_run(
    state,
    run_id="quickstart_run",
    role="Operator",
    source_profile_id=profile["profile_id"],
    source="quickstart",
)

updated_state = dict(state)
updated_state["maintenance_mode"] = True

run = radt.append_checkpoint(
    run,
    updated_state,
    label="maintenance enabled",
    reason="scheduled maintenance",
    role="Operator",
    source="quickstart",
)
```

Role-Aware Dashboard Toolkit returns new record dictionaries rather than mutating the input run in
place.

## Export a packet

```python
packet = radt.build_run_packet(run, source_version=radt.__version__)
raw_json = radt.export_packet_json(packet)
print(raw_json)

restored = radt.load_packet_json(raw_json)
assert restored["packet_type"] == "run"
```

Packet export validates the envelope, redacts local paths by default, and
rejects non-finite JSON numbers.

## Run the checked-in example

```bash
python -m examples.core_library
```

For the Streamlit UI path, continue with
[dashboard_tools.md](dashboard_tools.md).
