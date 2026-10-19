# Role-Aware Dashboard Toolkit examples

The examples use the retained library surface. Start with a small recipe or
explore a complete fictional application to see how the pieces fit together.

## Run a complete business dashboard

[Westbridge business dashboard](business_dashboard/README.md) is a reusable
business workspace with a password-free public board, private employee schedule
and messages, and admin analytics, outreach, publishing and access controls.
It runs locally on Windows, Linux and macOS with separate private runtime data.

[Cedar & Stone Landscaping](landscaping/README.md) combines real local password
sign-in with a shared five-person crew schedule and message board. Admins manage
accounts, jobs, assignments, rescheduling, completion/cancellation and history,
with separate customer, audit/telemetry and business-metrics pages.

This source example uses the toolkit's access policy and protected-change
recipe. Its FastAPI server, password sessions, SQLite database and browser UI
belong to the demo. The guide covers setup, fresh fictional accounts, restart
and the Windows WSL path. Runtime data stays in a private folder outside the
checkout; no account passwords or saved databases are included.

## Start with an editable dashboard

[Run your first dashboard](../docs/first_dashboard.md) walks through generating
Project Pulse with the installed `init` command, opening it in a browser, and
restarting it later. The starter includes a light theme, overview and progress
views, grouped controls, profiles and an audit history. Use it to build a small
dashboard without copying an entire application.

## Connect protected host operations

[Host integration](host_integration/README.md) is a dependency-free example of
connecting a host-verified identity to private records and deferred writes.
It demonstrates actor-scoped data, live grants, shared freeze, and rejecting an
old action after an account change. Its synthetic identity setup is explicitly
a local demonstration; the host supplies real authentication and persistence.

## Edit records and verify protected changes

[Record workflows](record_workflows/README.md) demonstrates a host-owned SQLite
transaction connecting live permissions, record revisions, validated changes and
durable history. Its reusable action helper supports rescheduling and status
changes; its acceptance runner checks actual effects and expected denials. The
[implementation recipes](../docs/record_workflows.md) explain date editing,
assignment selection, confirmations, stale edits and browser acceptance.

The example uses synthetic identities. Copy and adapt its helpers from the
matching source distribution; they are not new stable core APIs or a login service.

## A/B/C access and admin protection

[A/B/C Access Lab](section_access/README.md) demonstrates four assigned roles:
Admin sees A/B/C, AOnly sees A, AB sees A/B, and COnly sees C. Protected reads
and the admin action recheck server-owned grants. The authenticated entry point
requires OIDC and explicit provisioning; the separate simulation lets you try
all roles with invented records. From the repository root, in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m streamlit run examples/section_access/demo.py --server.address 127.0.0.1
```

In bash or zsh:

```bash
.venv/bin/python -m streamlit run examples/section_access/demo.py --server.address 127.0.0.1
```

The simulation's account selector is deliberately open and must stay local.
Use `app.py` and the linked setup instructions for actual authenticated access.

## Complete operator workflow

[Operator Review Lab](operator_review/README.md) connects a saved baseline,
synthetic AI settings, timestamped outcome comparisons, an explicit human
decision, and a portable read-only HTML report. It requires no model account or
external service. Start here to see the control and review pieces work together.
In PowerShell:

```powershell
.\.venv\Scripts\python.exe -m streamlit run examples/operator_review/app.py --server.address 127.0.0.1
```

In bash or zsh:

```bash
.venv/bin/python -m streamlit run examples/operator_review/app.py --server.address 127.0.0.1
```

Its metrics are teaching formulas, not performance measurements. Role selection
is a local policy demonstration; shared applications supply trusted identity.

## Dependency-free library example

`core_library.py` demonstrates controls, profiles, runs, checkpoints, and packet
export without Streamlit or file persistence:

```bash
python -m examples.core_library
```

## Streamlit dashboard

`dashboard_admin_controls_app.py` demonstrates:

- grouped controls
- a custom role
- the write-policy switch
- profile and audit panels
- a trusted plugin panel

Install the workbench extra in your active environment and run it from the
repository root. The demo needs no development tooling:

```shell
python -m pip install ".[workbench]"
python -m streamlit run examples/dashboard_admin_controls_app.py
```

Named profiles are saved in `profiles/` relative to the launch directory and
survive app restarts. Audit history is session-local unless you enable its file
writer. The role selector demonstrates permissions; shared deployments need
[verified sign-in and assigned roles](../role_aware_dashboard_toolkit/resources/guides/authentication.md).

![Dashboard Admin Controls screenshot](../docs/assets/dashboard_admin_controls_app.png)

## Studio Dispatch

[Studio Dispatch](studio_dispatch/README.md) is a synthetic studio-planning
dashboard with six control types, named profiles, Viewer permissions, freeze,
Workload/Notes navigation, and a configurable chart. It includes a complete dark
theme and behavior tests in the repository.

## Plugin template

`plugin_template.py` returns a minimal `DashboardPlugin` with sidebar and panel
hooks. Import `build_plugin()` from your application and register the result on
a `PluginRegistry`.

Examples are source-distribution material, not modules installed into the
`role_aware_dashboard_toolkit` package. Copy the relevant example into your application and adapt
its controls and policy to your own domain.
