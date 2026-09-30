# Role-Aware Dashboard Toolkit examples

The examples are intentionally small and use only the retained generic library
surface.

## Complete operator workflow

[Operator Review Lab](operator_review/README.md) connects a saved baseline,
synthetic AI settings, timestamped outcome comparisons, an explicit human
decision, and a portable read-only HTML report. It requires no model account or
external service. Start here to see the control and review pieces work together:

```powershell
.\.venv\Scripts\python.exe -m streamlit run examples/operator_review/app.py --server.address 127.0.0.1
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

Install the workbench dependencies and run it from the repository root:

```bash
python -m pip install -e ".[workbench,dev]"
python -m streamlit run examples/dashboard_admin_controls_app.py
```

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
