# Project Pulse

A local dashboard with editable planning controls, a progress chart, profiles
and audit history. It uses the installed Role-Aware Dashboard Toolkit package.

## Run

The starter needs Streamlit 1.44 or newer for its sidebar theme. If the rendering
dependency is missing, install it in the environment that contains the toolkit:

```powershell
python -m pip install "streamlit>=1.44"
python -m streamlit run app.py
```

Run from this directory so Streamlit reads `.streamlit/config.toml`. The server
binds to loopback. The core toolkit can be installed from a local wheel; this
starter does not assume that a toolkit PyPI release already exists.

## Try it

1. Change Weekly target and Completion. The three summary values update.
2. Select Progress in the sidebar; change Chart color to recolor the chart.
3. Switch to Planner. Planning controls remain editable; Intake open is locked.
4. Turn Controls Writable off. All registered controls freeze.
5. Switch back to Admin and turn writable on. Save a profile, change values,
   then select and load that profile.
6. To enable runs and checkpoints, change `runbook=False` to `runbook=True`
   in `build_dashboard_config()`, save the file and rerun.

The role selector is an explicit local demo and permits choosing Admin. For
shared access control, use `init NEW-DIRECTORY --auth` and read
`python -m role_aware_dashboard_toolkit guide authentication`.
Profiles, audit and runs use in-memory stores kept through reruns in the same
session. A new browser session or server restart starts fresh. The application
does not automatically write these records to disk.

## Customize

| Change | Edit location |
|---|---|
| Fields, labels, defaults, bounds and groups | `build_controls()` |
| Permissions and custom roles | `build_roles()` |
| Sidebar menu | `render_view_menu()` |
| Metrics and chart | `render_project_panel()` |
| Card fills, layout and built-in sections | `build_dashboard_config()` |
| Page, sidebar, input, text and accent colors | `.streamlit/config.toml` |
| Data-store lifetime and durability | `session_resources()` |

Keep stable field keys when renaming labels. The chart color field affects the
chart only. Group overrides use exact group names.

```powershell
python -m role_aware_dashboard_toolkit guide
python -m role_aware_dashboard_toolkit guide appearance
python -m role_aware_dashboard_toolkit inspect --format json
```

These commands read installed resources offline. For an existing project,
`example starter --format json` returns the source files for selective reuse;
`init` only creates a new destination and never merges into an existing project.
