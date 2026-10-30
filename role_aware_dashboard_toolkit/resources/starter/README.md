# Project Pulse

A local dashboard with a focused overview, editable planning controls, a
progress chart, profiles and audit history. It uses the installed Role-Aware
Dashboard Toolkit package and Streamlit's native, responsive widgets.

## Run

Install the toolkit's `workbench` extra in a Python 3.11 or later environment
that will run this dashboard. It applies the supported Streamlit and server dependency requirements.
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

1. A new session starts as Viewer on **Overview**. The four cards show the
   weekly target, calculated completed and remaining tasks, and completion rate.
   These are local planning figures, not live project measurements.
2. Select **Plan** under Show. Viewer can inspect the controls but cannot edit
   them. Select Admin in the sidebar, then change Weekly target and Completion.
   Return to Overview to see the updated cards; your values survive navigation.
3. Select **Progress** to see the chart. To recolor it, change Chart color in
   Plan, then return to Progress. Select **Activity** to inspect Audit Log.
4. In Plan, switch to Planner. Planning controls remain editable; Intake open
   is locked. The sidebar explains the current access level.
5. Switch back to Admin, the role here that can change Controls Writable, and
   turn it off. All registered controls freeze, for Admin too. The sidebar
   shows **Changes paused**, while read-only views remain available.
6. Turn writable on again. Save a profile, change values, then select and load
   that profile. Check Overview and Plan to confirm the restoration.
7. To enable runs and checkpoints, change `runbook=False` to `runbook=True`
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
| Sidebar views and access explanations | `VIEWS` and `render_view_menu()` |
| Metrics and chart | `render_project_panel()` |
| Card fills, layout and sections shown in each view | `build_dashboard_config()` |
| Page, sidebar, input, text and accent colors | `.streamlit/config.toml` |
| Data-store lifetime and durability | `session_resources()` |

Keep stable field keys when renaming labels. The chart color field affects the
chart only. Group overrides use exact group names. The starter's cream page,
sage sidebar and forest accent use official Streamlit configuration; no custom
HTML, browser JavaScript, external fonts or private CSS selectors are needed.

Keep the overview short and move editing and detailed history into named views.
Use native containers, columns and metrics so Streamlit can adapt the layout.
Use plain-text rendering for user-authored names; headings and instructions
can remain fixed application copy. Preserve the permission checks in callbacks
when adding views: hiding a section does not authorize its data or actions.

After changing presentation, inspect the actual browser at desktop and phone
widths. Open the phone sidebar, navigate to Plan, and confirm that field labels
and actions remain usable without horizontal page scrolling. Test keyboard
editing, profile restoration, Viewer/Planner restrictions and the frozen state;
an attractive screenshot alone does not establish those behaviors.

```shell
python -m role_aware_dashboard_toolkit guide
python -m role_aware_dashboard_toolkit guide appearance
python -m role_aware_dashboard_toolkit inspect --format json
```

These commands read installed resources offline. For an existing project,
`example starter --format json` returns the source files for selective reuse;
`init` only creates a new destination and never merges into an existing project.
