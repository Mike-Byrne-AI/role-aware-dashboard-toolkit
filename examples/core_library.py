from __future__ import annotations

import role_aware_dashboard_toolkit as radt


def build_registry() -> radt.ControlRegistry:
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
    return registry


def main() -> None:
    registry = build_registry()
    state: dict[str, object] = {}
    registry.ensure_defaults(state)

    profile = radt.build_profile(
        "baseline",
        registry,
        state,
        role="Operator",
        source="example",
    )
    run = radt.build_run(
        state,
        run_id="example_run",
        role="Operator",
        source_profile_id=profile["profile_id"],
        source="example",
    )

    updated_state = dict(state)
    updated_state["maintenance_mode"] = True
    run = radt.append_checkpoint(
        run,
        updated_state,
        label="maintenance enabled",
        reason="scheduled maintenance",
        role="Operator",
        source="example",
    )

    packet = radt.build_run_packet(run, source_version=radt.__version__)
    print(radt.export_packet_json(packet))


if __name__ == "__main__":
    main()
