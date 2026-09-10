# Dashboard tools

Role-Aware Dashboard Toolkit separates dashboard state from dashboard rendering. You can define and
test controls, roles, profiles, audit behavior, and configuration with the core
install; Streamlit is imported only when `render()` is called.

## Install

For the local source candidate:

```powershell
python -m pip install -e ".[workbench,dev]"
```

Only after a separate PyPI release, install the core library or the Streamlit extra:

```powershell
python -m pip install role-aware-dashboard-toolkit
python -m pip install "role-aware-dashboard-toolkit[workbench]"
```

## Define controls

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register(
    "Request timeout",
    kind="slider",
    key="request_timeout_seconds",
    group="Operations",
    min_value=1,
    max_value=120,
    step=1,
    default=30,
)
registry.register(
    "Maintenance mode",
    kind="toggle",
    key="maintenance_mode",
    group="Safeguards",
    default=False,
)
```

Supported control kinds are `slider`, `toggle`, `number`, `select`, `text`, and
`color`. Keys must be unique. Numeric bounds, select options, defaults, and
callbacks live on the `ControlDef`, not in the renderer.

Controls whose name or key looks sensitive are marked sensitive automatically;
you can also pass `sensitive=True`. Sensitive values are omitted from durable
profiles and redacted from audit and API response surfaces.

## Configure the dashboard

```python
config = radt.DashboardConfig(
    title="Service controls",
    subtitle="Changes are explicit and auditable.",
    registry=registry,
    audit=radt.AuditLog(),
    layout="columns",
    columns_per_row=2,
)

context = radt.render(config)
```

`render()` returns a `SecurityContext` containing the active role, permissions,
and current write-policy state.

Useful `DashboardConfig` collaborators include:

- `profile_store` for custom profile persistence
- `plugins` for trusted sidebar and panel hooks
- `observability` for telemetry sampling
- `run_store` for run/checkpoint panels
- explicit team, decision, memory, case, and governance stores
- `auth_hook` for binding the displayed role to a trusted identity

The optional record stores are module-level APIs; see
[the public API reference](public_api.md).

## Roles and write policy

Each control declares a permission key, defaulting to
`can_edit_controls`. A write requires both:

1. the active role grants the control's permission; and
2. the dashboard write-policy switch is enabled.

```python
custom_roles = {
    "Release Lead": radt.RoleDef(
        name="Release Lead",
        description="Can update controls and manage profiles.",
        perms={
            "can_edit_controls": True,
            "can_view_audit": True,
            "can_save_profiles": True,
            "can_load_profiles": True,
            "can_view_metrics": True,
        },
    )
}
```

Dashboard roles are authorization context, not authentication. A shared
deployment must supply an `auth_hook` backed by trusted identity, and should be
protected by authenticated TLS ingress. Do not authorize a user solely from the
visible role selector.

## Profiles

Profiles persist the registry's non-sensitive values. Use in-memory stores for
tests and embedded applications, or a file store for trusted local storage.

```python
store = radt.InMemoryProfileStore()
state: dict[str, object] = {}
registry.ensure_defaults(state)

radt.save_profile(
    "baseline",
    registry,
    state,
    role="Release Lead",
    store=store,
)

loaded = radt.load_profile("baseline", registry, state, store=store)
```

Loading a profile restores only registered, persistable values and reports how
many stale or out-of-range values were corrected.
Dashboard profile loading requires `can_load_profiles`, an enabled write-policy
switch, and each restored control's declared permission. All controls are checked
before any live value changes; a denied control rejects the entire load.
Checkpoint replay follows the same rule with `can_replay_runs` as its action
permission.

Packet export does not override visibility permissions. Full run and checkpoint
packet previews require `can_export_packets`, `can_view_metrics`, and
`can_view_audit`; replay previews require export and metrics access.

## Audit

`AuditLog` always keeps bounded in-memory history. It can also use the
file-backed audit store for JSONL persistence.

Audit permissions are intentionally split: `can_view_audit` permits inspection,
while `can_manage_audit` permits clearing the in-memory log and changing the
JSONL writer lifecycle. The built-in `Admin` role is the only role granted
`can_manage_audit`; custom roles must opt in explicitly.

```python
audit = radt.AuditLog()
audit.log_control_change(
    "maintenance_mode",
    False,
    True,
    role="Release Lead",
)
print(audit.recent(10))
```

Persistence failures remain visible through writer status and runtime
diagnostics; in-memory events stay available.

## Plugins

Plugins are trusted in-process Python:

```python
plugins = radt.PluginRegistry()
plugins.register(
    radt.DashboardPlugin(
        name="status-card",
        version="1.0.0",
        capabilities=["panel"],
        render_panel=lambda context: context["st"].success("Service ready"),
    )
)
```

See [plugins.md](plugins.md) for discovery, lifecycle, and failure isolation.

## Observability

An `ObservabilityConfig` samples an application callback and keeps bounded
history in session state:

```python
observability = radt.ObservabilityConfig(
    enabled=True,
    telemetry_hook=lambda: {
        "metrics": {"queue_depth": 2, "latency_ms": 18.4},
        "health": {"status": "ok"},
        "source": "service",
    },
    history_limit=30,
)
```

Install `role-aware-dashboard-toolkit[pandas]` only if you want dataframe-backed history tables.
The telemetry contract is documented in
[telemetry_contract.md](telemetry_contract.md).

## Run the complete example

```bash
python -m streamlit run examples/dashboard_admin_controls_app.py
```

That example is the canonical visual smoke test for controls, roles, profiles,
audit history, and plugins.
