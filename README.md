# Role-Aware Dashboard Toolkit

Role-Aware Dashboard Toolkit is a Python toolkit for building AI operator
dashboards with consistent permissions, saved configurations and traceable runs.

Use it to give people controls for an AI application: adjust settings, restore
named configurations, inspect what changed, and review recorded runs. Define
your controls and role policy once, then reuse the supplied dashboard workflows
for profiles, audit history, checkpoints, comparisons and replay previews.

The core package has no required third-party dependencies. Streamlit, FastAPI,
and pandas support are isolated behind optional extras.

This is an early beta. The authenticated starter is intended for a single-host
dashboard with an external sign-in provider and explicit role assignments.
Evaluate it with synthetic data, then complete the deployment acceptance checks
before admitting private data or real users. Tests and example deployments have
limited scope; they do not establish a security certification or comparative
advantage over other dashboard tools. See the [security and update policy](SECURITY.md).

## Why Role-Aware Dashboard Toolkit

The toolkit is useful when several operator workflows need to follow the same
rules. Its supplied UI and API check permissions before applying a whole profile;
a denied restore leaves controls unchanged. Sensitive controls are omitted from
saved profiles and masked in audit history. Deferred UI replay checks current
permissions again before applying recorded settings.

The reusable building blocks include:

- validated control definitions and predictable state defaults
- explicit role and write-permission checks
- profile save, load, diff, and redaction behavior
- append-only audit history with visible persistence diagnostics
- trusted in-process plugin hooks
- inspectable runs, checkpoints, comparisons, ledgers, and replay previews
- a stable packet envelope for exporting application evidence

The installed package also includes a capability report, offline guides, a
starter and diagnostics that help a coding assistant discover the available
APIs. These provide reusable implementation and technical guidance; they do not
add model reasoning or connect external services automatically.

Your application supplies the data, calculations, model calls and actions behind
the controls. Images and charts use the renderer's existing capabilities. A
simple card with a few sliders may need only Streamlit; this toolkit is intended
for applications that also need the shared control and review workflows above.

There is no established development-time speedup claim. The value to evaluate
is how much repeated implementation and verification these workflows remove
from your own applications.

## Project links

- [Source repository](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit)
- [Issue tracker](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/issues)
- [Documentation](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/blob/main/docs/README.md)

This release is distributed as GitHub source. Package-index publication is a
separate release decision.

## Install

From an unpacked source release or source checkout:

```powershell
python -m pip install .
```

For the styled starter, install the renderer in the same environment:

```powershell
python -m pip install ".[workbench]"
```

Then work in your own application directory. A regular installation includes
the toolkit's Python source, offline guides and starter; the source checkout is
not needed to run the installed guide or create a consumer project. The supported
Streamlit baseline is 1.65.0. For verified login, install `.[auth]` and follow the
[authentication guide](role_aware_dashboard_toolkit/resources/guides/authentication.md),
then the [single-host deployment guide](role_aware_dashboard_toolkit/resources/guides/deployment.md),
including isolated dependency and browser-session acceptance checks. The toolkit
does not supply managed hosting or an identity provider. A source test run does
not establish that a particular shared deployment is ready for private data.

Only after a separate PyPI release:

```bash
python -m pip install role-aware-dashboard-toolkit
```

Only after a separate PyPI release, choose the optional capability you need:

```bash
python -m pip install "role-aware-dashboard-toolkit[workbench]"  # Streamlit rendering
python -m pip install "role-aware-dashboard-toolkit[auth]"       # OIDC login and role grants
python -m pip install "role-aware-dashboard-toolkit[api]"        # FastAPI routes
python -m pip install "role-aware-dashboard-toolkit[pandas]"     # Tabular history views
python -m pip install "role-aware-dashboard-toolkit[full]"       # All supported runtime extras
```

## Build with your assistant

The installed package includes offline guidance and a complete starter. After
installing the toolkit, use the same Python environment for these commands:

```powershell
python -m role_aware_dashboard_toolkit inspect --format json
python -m role_aware_dashboard_toolkit guide start
python -m role_aware_dashboard_toolkit init my-dashboard --dry-run
python -m role_aware_dashboard_toolkit init my-dashboard
Set-Location my-dashboard
python -m streamlit run app.py
```

The starter uses the supported Streamlit baseline, 1.65.0 or later.
The guide and inspection commands work with the dependency-free core.
`init` creates a new directory containing editable application code, a theme,
a README and an `AGENTS.md` pointer to the installed handbook. It refuses an
existing destination. For an existing project, read `guide` and
`example starter --format json`, then integrate the pieces you need.

Ask your assistant to read the project's instructions and run `inspect` and
`guide start` before customizing the dashboard. The shipped guidance describes
this installed version; your instructions and project policy remain authoritative.
The package does not assume an assistant automatically reads files inside
site-packages. Imports stay quiet, and only the explicit `init` command creates
project files. Guide topics cover controls, appearance, sections, plugins,
permissions, profiles, runs, telemetry, API configuration and troubleshooting.
Runtime diagnostics include stable codes, operation/effect information and a
command for the matching installed guide. `inspect --format json` lists the
complete diagnostic catalog.

## Five-minute dashboard

```python
import streamlit as st
import role_aware_dashboard_toolkit as radt

if "service_controls_audit" not in st.session_state:
    st.session_state["service_controls_audit"] = radt.AuditLog()

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
    audit=st.session_state["service_controls_audit"],
)

radt.render(config)
```

The audit object stays in this browser session across reruns; a new session or
server restart starts a new in-memory history. Control definitions can rebuild
on each rerun. Choose a persistent audit store when records must survive restarts.

Save the file as `app.py`, install the workbench extra, and run:

```bash
python -m streamlit run app.py
```

For a complete dashboard with custom roles and a plugin panel:

```bash
python -m streamlit run examples/dashboard_admin_controls_app.py
```

To try a complete operator review, run [Operator Review Lab](examples/operator_review/README.md)
from the repository root:

```powershell
python -m streamlit run examples/operator_review/app.py --server.address 127.0.0.1
```

Save a baseline, adjust synthetic AI settings, compare recorded outcomes, record
a human decision and export a standalone readable report. The example uses
deterministic teaching formulas and session-local stores; it makes no model
calls or performance claims.

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

- Default/demo roles are self-selected workflow context. For shared dashboards,
  use `init my-dashboard --auth` and the [authentication guide](role_aware_dashboard_toolkit/resources/guides/authentication.md).
  Authenticated mode binds verified identity to server-owned grants, permits only
  assigned role choices, and checks the shared freeze before protected writes.
- Plugins run in-process and must be treated as trusted code.
- Custom callbacks and direct use of core state helpers require the host to
  enforce authorization; the supplied UI/API checks do not cover arbitrary code.
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
