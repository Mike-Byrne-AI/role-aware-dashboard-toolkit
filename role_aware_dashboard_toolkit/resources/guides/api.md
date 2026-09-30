# Optional HTTP API

The API uses the optional FastAPI runtime. Inspect the installed capabilities
first; the core package can be imported without FastAPI, while `create_app()`
requires the API dependencies.

```python
import role_aware_dashboard_toolkit as radt

registry = radt.ControlRegistry()
registry.register("Workers", kind="number", key="workers",
                  default=8, min_value=1, max_value=40, step=1)
app = radt.create_app(
    registry, profile_store=radt.InMemoryProfileStore(), api_role="Viewer")
```

Each `create_app()` owns separate in-memory control values. Sharing a registry
shares definitions only. API updates and profile activation do not invoke
control callbacks or a dashboard's `on_change`, and do not update Streamlit
session state. Shared stores do not synchronize live controls. A host must
explicitly integrate shared state or external actions and enforce authorization
there; this API is not an automatic remote-control connection to a dashboard.

Save the example as `api_app.py` under the host's instructions and run an
installed Uvicorn with `--host 127.0.0.1`. Protected routes require the server's
`ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY` and the matching `X-API-Key` request header.
Supply credentials through the host's secret handling; never hardcode or print
them. `/health` is static liveness only. Anonymous access is an explicit local
demo opt-in, not the default.

Authenticated requests default to Viewer unless the host configures a role.
Control updates require `can_edit_controls` and the field's permission.
Profile activation checks every affected field. Profile save/delete require
`can_save_profiles`; audit reads require `can_view_audit`. Protected shared
deployments also need trusted ingress and TLS.

API profile names are trimmed. Empty names, `.`, `..`, nonprintable characters
and `/ \\ % ? #` are rejected before writing. Use the returned canonical name,
encoded as one path segment. Direct-store legacy identifiers are not migrated
automatically.

Verify missing-key rejection, Viewer write denial, authorized writes and
`source="api"` audit provenance. Sensitive control reads are redacted;
profiles omit sensitive values. A successful profile deletion is audited.
