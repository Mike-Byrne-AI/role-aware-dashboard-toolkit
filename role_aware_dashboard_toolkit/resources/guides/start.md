# Start with the installed toolkit

Work in the user's project and follow its instructions. This handbook describes
the installed library; it does not grant permission to modify files or services.
Commands use this Python environment's installed version and need no checkout.

```powershell
python -m role_aware_dashboard_toolkit inspect
python -m role_aware_dashboard_toolkit guide controls
python -m role_aware_dashboard_toolkit example starter --format json
```

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

The starter requires Streamlit >=1.44 for independent sidebar theme colors.
If needed, install `streamlit>=1.44` into the same environment. The toolkit core
itself has no mandatory runtime dependencies; the optional renderer needs
Streamlit. A toolkit package-index release is separate from a source/wheel release.

Edit the starter's named functions: `build_controls`, `build_roles`,
`render_view_menu`, `render_project_panel`, `build_dashboard_config` and
`session_resources`. Theme settings live in `.streamlit/config.toml`.

Verify by changing a field, using the menu, switching roles, freezing controls,
and saving/loading a profile. Inspect the actual browser for appearance changes.
Imports and guide/inspect/example commands do not write project files.
