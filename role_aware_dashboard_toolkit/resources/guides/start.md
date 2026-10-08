# Start with the installed toolkit

Work in the user's project and follow its instructions. This handbook describes
the installed library; it does not grant permission to modify files or services.
The discovery commands use this Python environment's installed version and need
no checkout.

```powershell
python -m role_aware_dashboard_toolkit inspect
python -m role_aware_dashboard_toolkit guide controls
python -m role_aware_dashboard_toolkit example starter --format json
```

Before launching a dashboard, install the toolkit's `workbench` extra in the
same environment. It applies the supported Streamlit and server dependency
requirements, including when the core toolkit is already installed. Replace this
example path with the absolute path to your reviewed toolkit source checkout:

```powershell
python -m pip install "C:\path\to\role-aware-dashboard-toolkit[workbench]"
python -m pip check
```

Alternatively, pass the absolute filename of your reviewed local toolkit wheel
with `[workbench]` appended to the same `pip install` command. These explicit
paths work from your application directory. No toolkit package-index release
is assumed. The toolkit core itself has no mandatory runtime dependencies.

For a new project, preview then explicitly create a new directory:

```powershell
python -m role_aware_dashboard_toolkit init my-dashboard --dry-run --format json
python -m role_aware_dashboard_toolkit init my-dashboard
Set-Location my-dashboard
python -m streamlit run app.py
```

`init` refuses existing destinations; it does not merge or replace an existing
AGENTS.md. For existing projects, read `example starter` and adapt the relevant
files under the host's instructions.

For shared use, choose `init my-dashboard --auth` and read `guide authentication`
for provider configuration and explicit role provisioning. Plain `init` is the
local role-selection demo, with no protection against choosing Admin.

Edit the starter's named functions: `build_controls`, `build_roles`,
`render_view_menu`, `render_project_panel`, `build_dashboard_config` and
`session_resources`. Theme settings live in `.streamlit/config.toml`.

Verify by changing a field, using the menu, switching roles, freezing controls,
and saving/loading a profile. Inspect the actual browser for appearance changes.
Imports and guide/inspect/example commands do not write project files.
