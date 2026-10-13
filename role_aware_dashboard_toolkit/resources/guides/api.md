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

Request bodies over 1 MiB receive HTTP 413; pass `max_body_bytes=` to
`create_app()` to change the limit. JSON nested more than 32 levels deep in a
control value or a profile's `extra` receives HTTP 422.

State-changing requests (`POST`, `PATCH`, `DELETE`) without an `X-API-Key`
header must send `Content-Type: application/json`, including bodyless profile
activation and deletion; otherwise they receive HTTP 415. This stops another web
site from making a browser change an anonymous demo API.

Request bodies are exact. `PATCH /controls` takes `{"values": {"key": value}}`;
a body without `values`, or with any other field, is refused with HTTP 422.
`POST /profiles` accepts `profile_id`, `role` and `extra` only. It saves the API
instance's current live values, so a `values` field is refused rather than
ignored.

Authenticated requests default to Viewer unless the host configures a role.
Control updates require `can_edit_controls` and the field's permission.
Their response keeps its normal shape but uses `value: "<redacted-secret>"`
without `can_view_metrics`; the authorized update still completes. A control's
`sensitive` flag continues to describe its definition, independently of the
caller's read grant.

Control updates are exact: each value is stored as sent, or the whole request
is refused with HTTP 422 naming the control, before any value or audit event
changes. The API never substitutes a default or clamps a value.

- `number` and `slider`: a finite JSON number, or a numeric string, within the
  control's bounds. A `number` control whose default, step and bounds are all
  whole numbers takes whole numbers only.
- `toggle`: `true` or `false`, `0` or `1`, or the strings `true`/`false`,
  `yes`/`no`, `on`/`off`, `1`/`0`.
- `select`: one of the configured options.
- `text`: a string; a number is stored as its text.
- `color`: `#RRGGBB`; surrounding spaces are removed.
- `null` is never a value.

Profile activation is different: like the dashboard, it repairs stale saved
values to the control's current bounds, options or default.
Profile activation checks every affected field. Profile save/delete require
`can_save_profiles`; audit reads require `can_view_audit`. Protected shared
deployments also need trusted ingress and TLS.

Reading profile values requires both `can_load_profiles` and `can_view_metrics`.
Saving or activating a profile does not grant read authority: these actions
return an empty `values` object when metrics access is denied. Profile metadata
listings remain available with `can_load_profiles`. Audit reads
also hide historical values for controls that are now sensitive.

A stored profile that exists but cannot be read is never reported as missing:
reads and activation return HTTP 500, a save over it returns HTTP 409, and
`GET /profiles` lists the readable records with an `X-Unreadable-Records` count
header. Nothing changes in any of these cases; repair or delete the record. This
applies to stores that record `read_errors`, including `FileProfileStore` and the
default `profile_dir` store.

API profile names are trimmed. Empty names, `.`, `..`, nonprintable characters
and `/ \\ % ? #` are rejected before writing. Use the returned canonical name,
encoded as one path segment. Direct-store legacy identifiers are not migrated
automatically.

Verify missing-key rejection, Viewer write denial, authorized writes and
`source="api"` audit provenance. Sensitive control reads are redacted;
profiles omit sensitive values. A successful profile deletion is audited.

Existing profile reads expose only registered public controls. Historical
sensitivity flags and nested secret-named fields also exclude a saved control
from API responses and activation, preserving its current live value. This
projection does not rewrite the saved record. Core profile helpers remain
host-controlled; this additional projection belongs to the HTTP boundary.

Profile activation refuses with HTTP 422 a public text/color value it would
stringify from nested secret fields, including a nested default selected by its
repair, before any values or audit events change. An ordinary public
replacement remains allowed; explicitly sensitive controls remain write-only and
structured select responses still redact secret fields.

Single-control reads support keys containing `/`, including automatically
derived keys such as `requests/second`. Append the URL-encoded complete key to
`/controls/`, for example `urllib.parse.quote(key, safe="")`.
