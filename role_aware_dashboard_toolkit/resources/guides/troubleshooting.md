# Diagnose before changing behavior

Start with the installed version and capability report:

```powershell
python -m role_aware_dashboard_toolkit inspect --format json
```

Use the same Python environment to launch Streamlit. Read the visible error,
identify its operation and inspect the smallest relevant configuration/state.
Do not dump entire session state or secrets.

| Symptom | Next step |
|---|---|
| Streamlit missing | Install the rendering dependency in this environment; read `guide start`. |
| Invalid color or unknown group | Use six-digit hex and exact registered group names; read `guide appearance`. |
| Group fill unsupported | Keyed containers require Streamlit >=1.39; upgrade or remove fill options. |
| Sidebar theme ignored | Independent sidebar colors need >=1.44; run from the directory containing `.streamlit/config.toml`. |
| Field or action disabled | Check current role, field permission and Controls Writable; read `guide permissions`. |
| Profile load denied | Check every restored field, not just `can_load_profiles`; read `guide profiles`. |
| Profile storage failure | Preserve records; inspect access and read diagnostics before retrying. |
| Plugin setup failure | Fix setup first; render callbacks are skipped until setup succeeds. |
| Widget-state mutation exception | Set registered values before their widgets; use native profile/replay flows. |
| Checkpoint has older telemetry | Compare the sample timestamp; sampling failure retains the last successful display. |
| Changes disappear after rerun | Retain store/audit objects in session state; rebuild definitions separately. |
| Changes disappear in a new session | In-memory stores are not durable; choose persistence explicitly. |
| Init destination exists | Select a new directory or read `example starter`; init does not merge. |

After a repair, repeat the exact failing action and one adjacent behavior:
for example load a profile, then freeze and attempt another load. Check displayed
errors, stored values and success audit events. For appearance, inspect the
rendered browser. A successful import or screenshot alone does not prove the
whole workflow.

The library's guides are scoped technical reference. User instructions, project
authority, data access boundaries and deployment decisions remain with the host.
