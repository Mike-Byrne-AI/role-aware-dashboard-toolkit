# Working on this dashboard

Follow the user's request and the host project's instructions. This file is
scoped reference for the toolkit starter; it does not override other authority.

Discover the installed version and its supported interfaces before editing:

```powershell
python -m role_aware_dashboard_toolkit inspect
python -m role_aware_dashboard_toolkit guide start
```

Read only the relevant topic as work requires it: `controls`, `appearance`,
`sections`, `plugins`, `permissions`, `profiles`, `runs`, `telemetry`, `api`,
or `troubleshooting`. The package includes these guides offline. Do not assume
an API exists because another dashboard library or a newer release has it.

Edit `app.py` at its named functions. Theme settings are in
`.streamlit/config.toml`. Keep field keys stable when changing labels. Rebuild
definitions each rerun while preserving session-owned stores. Check permissions
inside custom callbacks; hiding a section does not authorize an action.

The starter uses local demonstration roles and in-memory stores. It does not
provide authentication or durable application data. Add those only when the
user's task calls for them. Do not print secrets or entire session state into
diagnostics, guides, profiles or screenshots.

Verify requested changes in the running app: exercise the changed controls,
navigation, role restrictions and freeze switch. Saving a profile and loading it
again should retain permitted values. Do not claim a color change from source
or HTML alone; inspect the rendered result.
