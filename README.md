# Role-Aware Dashboard Toolkit

Role-Aware Dashboard Toolkit is a Python library for operator dashboards. It provides typed controls, role policy, profiles, audit history,
plugins, observability, run checkpoints, replay previews, and neutral JSON
packets without imposing an application framework on the rest of your system.

The core package has no required third-party dependencies. Streamlit, FastAPI,
and pandas support are isolated behind optional extras.

## Why Role-Aware Dashboard Toolkit

Operator interfaces often need the same hard parts:

- validated control definitions and predictable state defaults
- explicit role and write-permission checks
- profile save, load, diff, and redaction behavior
- append-only audit history with visible persistence diagnostics
- trusted in-process plugin hooks
- inspectable runs, checkpoints, comparisons, ledgers, and replay previews
- a stable packet envelope for exporting application evidence

Role-Aware Dashboard Toolkit keeps those concerns reusable and local-first. It does not execute
hidden actions, authenticate users on your behalf, or replace your deployment
security boundary.

## Install

From a source checkout:

```bash
python -m pip install -e .
```

After publication:

```bash
python -m pip install role-aware-dashboard-toolkit
```

After publication, choose the optional capability you need:

```bash
python -m pip install "role-aware-dashboard-toolkit[workbench]"  # Streamlit rendering
python -m pip install "role-aware-dashboard-toolkit[api]"        # FastAPI routes
python -m pip install "role-aware-dashboard-toolkit[pandas]"     # Tabular history views
python -m pip install "role-aware-dashboard-toolkit[full]"       # All supported runtime extras
```

## Five-minute dashboard

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register(
    "Request timeout",
    kind="slider",
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

config = radt.DashboardConfig(
    title="Service controls",
    registry=registry,
    audit=radt.AuditLog(),
)

radt.render(config)
```

Save the file as `app.py`, install the workbench extra, and run:

```bash
python -m streamlit run app.py
```

For a complete dashboard with custom roles and a plugin panel:

```bash
python -m streamlit run examples/dashboard_admin_controls_app.py
```

The dependency-free library example exercises controls, profiles, runs, and
packet export:

```bash
python -m examples.core_library
```

## Public surface

The package root intentionally stays small. Stable dashboard, control, profile,
audit, security, runtime, packet, and runbook APIs are available from
`role_aware_dashboard_toolkit`. Less common operator-record and release helpers remain explicit
module imports.

See:

- [Documentation index](docs/README.md)
- [Quickstart](docs/quickstart.md)
- [Dashboard tools](docs/dashboard_tools.md)
- [Public API reference](docs/public_api.md)
- [Plugin contract](docs/plugins.md)
- [API security](docs/api_security.md)
- [Protocol overview](docs/protocol/overview.md)
- [Distribution model](docs/distribution.md)
- [Architecture scope](ARCHITECTURE_SCOPE.md)

## Design boundaries

- Dashboard roles are authorization context, not user authentication.
- Plugins run in-process and must be treated as trusted code.
- Replay helpers build previews from recorded state; they do not perform
  external mutations.
- File-backed stores are intended for trusted local or mounted storage, not
  distributed consensus.
- Custom packet types must use the `x_` namespace.

These boundaries are deliberate. Product-specific adapters and application
integrations belong outside the OSS core.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check role_aware_dashboard_toolkit examples tests --no-cache
```

Before a release, follow [the release checklist](docs/release_checklist.md) and
[publication runbook](docs/release_runbook.md).

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Role-Aware Dashboard Toolkit is licensed under the [MIT License](LICENSE).
