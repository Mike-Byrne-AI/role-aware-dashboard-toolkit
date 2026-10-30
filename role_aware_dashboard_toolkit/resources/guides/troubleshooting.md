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
| Group fill unsupported | Use the supported Python >=3.11 / Streamlit >=1.66.1 baseline with keyed containers; read `guide appearance`. |
| Sidebar theme ignored | Use Streamlit >=1.66.1 on Python >=3.11 and run from the directory containing `.streamlit/config.toml`. |
| Field or action disabled | Check current role, field permission and Controls Writable; a new demo session starts as Viewer. Read `guide permissions`. |
| Profile load denied | Check every restored field, not just `can_load_profiles`; read `guide profiles`. |
| Profile storage failure | Preserve records; inspect access and read diagnostics before retrying. |
| Plugin setup failure | Fix setup first; render callbacks are skipped until setup succeeds. |
| Widget-state mutation exception | Set registered values before their widgets; use native profile/replay flows. |
| Checkpoint has older telemetry | Compare the sample timestamp; sampling failure retains the last successful display. |
| Changes disappear after rerun | Retain store/audit objects in session state; rebuild definitions separately. |
| Changes disappear in a new session | In-memory stores are not durable; choose persistence explicitly. |
| Some sessions' audit events missing from the JSONL file | A writer persists only its own `AuditLog`. Share one log per process and start its writer where you create it (README, durable audit). |
| Init destination exists | Select a new directory or read `example starter`; init does not merge. |

After a repair, repeat the exact failing action and one adjacent behavior:
for example load a profile, then freeze and attempt another load. Check displayed
errors, stored values and success audit events. For appearance, inspect the
rendered browser. A successful import or screenshot alone does not prove the
whole workflow.

The library's guides are scoped technical reference. User instructions, project
authority, data access boundaries and deployment decisions remain with the host.

## Runtime messages connect to this installed handbook

Library configuration exceptions preserve their base type and expose a
`diagnostic` dictionary with schema version, toolkit version, code, operation,
message, effect, guide topic and help command. Plugin/runtime error records
expose the same guidance through `.diagnostic` and their `to_dict()` output.
`inspect --format json` includes the fixed diagnostic catalog.

| Code | Operation | Offline topic |
|---|---|---|
| `RADT-CONTROL-DEFINITION` | `register_control` | `guide controls` |
| `RADT-APPEARANCE` | `configure_appearance` | `guide appearance` |
| `RADT-SECTIONS` | `configure_sections` | `guide sections` |
| `RADT-STREAMLIT` | `render_dashboard` | `guide start` |
| `RADT-PERMISSION` | `apply_controls` | `guide permissions` |
| `RADT-PROFILE-IO` | `access_profiles` | `guide profiles` |
| `RADT-PLUGIN` | `plugin_callback` | `guide plugins` |
| `RADT-TELEMETRY` | `sample_telemetry` | `guide telemetry` |
| `RADT-AUDIT-IO` | `persist_audit` | `guide troubleshooting` |
| `RADT-AUTH` | `authenticate` | `guide permissions` |
| `RADT-CALLBACK` | `call_callback` | `guide troubleshooting` |
| `RADT-PLUGIN-TRUST` | `discover_plugins` | `guide plugins` |

Read the specific validation detail first, then use the linked guide. A plugin
or callback can fail after making changes; the library does not roll back host
side effects. Profile I/O failure preserves live controls but cannot promise
that custom storage did not partially write. Audit persistence failure means
durability needs checking. Telemetry fallback keeps the old sample timestamp.

Generated callback/plugin/audit diagnostic text omits arbitrary exception
messages, which can contain credentials. It retains the failure type and
operation. `safe_call(on_error=...)` still passes the original exception to the
host's explicitly supplied error handler; that handler owns any further logging.
Avoid copying secrets into source names, plugin metadata or custom diagnostics.
The catalog is scoped reference, not instructions to grant permissions or retry
external mutations automatically.
