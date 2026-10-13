# Studio Dispatch

A synthetic creative-studio dashboard demonstrating the toolkit's six control
types, grouped cards, profiles, roles and a session freeze switch.

## Run

Install the project using the [development environment setup](../../CONTRIBUTING.md#development-setup).
This installs the supported Streamlit baseline, 1.65.0 or newer. Then, from the
repository root:

```powershell
Push-Location examples\studio_dispatch
..\..\.venv\Scripts\python.exe -m streamlit run app.py --server.port 8524
Pop-Location
```

If using an activated environment instead, replace the interpreter path with
`python`. Run from this example directory so Streamlit reads
`.streamlit/config.toml`. The server binds to loopback and uses no external
services. Stop it with Ctrl+C. Choose another port if 8524 is occupied.

## Use

- A new session starts as Viewer, which can only read. Select Admin in the
  sidebar to edit controls and profiles.
- Adjust weekly hours and completion percentage to update the workload metrics
  and chart. Priority, project name, intake availability and chart color are
  independently configurable.
- Switch between Workload and Notes without losing settings.
- Save a named profile, select it and click Load to restore all six controls.
  Selecting a profile alone previews it. Save/Delete update menu membership
  immediately.
- Select Viewer for read-only controls and profile actions. Turn Controls
  Writable off to freeze controls and prevent profile restores. Admin may still
  save or delete snapshots while frozen.

Roles here are a local authorization demonstration, not authentication. Profiles,
audit records and runs stay in the browser session through reruns; a new session
or server restart starts fresh. Use a trusted auth hook and an appropriate store
when a host application actually needs authentication or durable data.

## Customize and verify

Edit `build_controls`, `build_roles`, `render_view_menu`, `render_project_panel`,
or `build_dashboard_config` in `app.py`. Colors for the page and sidebar live in
`.streamlit/config.toml`. Keep field keys stable to preserve profile identity.
Read `guide controls`, `guide appearance`, `guide profiles`, or `guide permissions`
through `python -m role_aware_dashboard_toolkit` for matching offline reference.

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_studio_dispatch_example.py -q
```

The tests drive real Streamlit widgets, inspect chart data, exercise profile
round trips and immediate menu updates, and check Viewer/freeze boundaries.
Tests are retained in the Git repository; the source distribution includes the
runnable example, theme and this README.
