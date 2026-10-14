# Project Pulse

A local dashboard with editable planning controls, a progress chart, profiles
and audit history. It uses the installed Role-Aware Dashboard Toolkit package.

## Run

Install the toolkit's `workbench` extra in the environment that will run this
dashboard. It applies the supported Streamlit and server dependency requirements.
From this application directory, replace the example path below with the absolute
path to your reviewed toolkit source checkout. In PowerShell on Windows:

```powershell
python -m pip install "C:\path\to\role-aware-dashboard-toolkit[workbench]"
python -m pip check
python -m streamlit run app.py
```

In bash or zsh on macOS or Linux:

```bash
python -m pip install "/path/to/role-aware-dashboard-toolkit[workbench]"
python -m pip check
python -m streamlit run app.py
```

`python` means the environment's interpreter; without an active environment,
use its path (for example `.venv/bin/python` or `.\.venv\Scripts\python.exe`).

Alternatively, pass the absolute filename of your reviewed local toolkit wheel
with `[workbench]` appended to the same `pip install` command. Both forms apply
the extra's dependency requirements when the core toolkit is already installed.

Run from this directory so Streamlit reads `.streamlit/config.toml`. The server
binds to loopback. This starter does not assume that a toolkit PyPI release
already exists.

## Try it

1. A new session starts as Viewer, which can only read. Select Admin in the
   sidebar, then change Weekly target and Completion. The three summary
   values update.
2. Select Progress in the sidebar; change Chart color to recolor the chart.
3. Switch to Planner. Planning controls remain editable; Intake open is locked.
4. Switch back to Admin, the role here that can change Controls Writable, and
   turn it off. All registered controls freeze, for Admin too.
5. Turn writable on again. Save a profile, change values, then select and load
   that profile.
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

```shell
python -m role_aware_dashboard_toolkit guide
python -m role_aware_dashboard_toolkit guide appearance
python -m role_aware_dashboard_toolkit inspect --format json
```

These commands read installed resources offline. For an existing project,
`example starter --format json` returns the source files for selective reuse;
`init` only creates a new destination and never merges into an existing project.
