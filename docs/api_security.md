# Role-Aware Dashboard Toolkit API security

Role-Aware Dashboard Toolkit's optional FastAPI surface is secure by default. Protected routes require `ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY` and the request must send the same value in the `X-API-Key` header.
The key is read on each request. When `create_app()` runs with neither the key
nor anonymous access configured, it logs a warning that every protected route
will return HTTP 401; the key value is never logged.
Dashboard setup and first-run control flows are documented in `docs/dashboard_tools.md`; this page focuses on API trust boundaries and permissions.

API keys must contain only ASCII characters. When a key is configured, non-ASCII
request keys receive the same generic HTTP 401 as an incorrect key. A nonempty
non-ASCII configured key also denies protected requests until corrected; it
never enables anonymous access. Valid ASCII keys retain constant-time comparison.

Demo dashboard roles are self-selected workflow context. Shared dashboards can
use the [authenticated starter](../role_aware_dashboard_toolkit/resources/guides/authentication.md)
with verified OIDC identity, server-owned grants and shared freeze. The existing
`auth_hook` remains a host-managed integration. Use TLS and restrict storage
access. **Dashboard OIDC and freeze do not secure this separate FastAPI surface**;
configure its API-key and role policy independently.

Sensitive controls are write-only through the API response surface: updates are
accepted into in-memory state, while reads and update responses return
`<redacted-secret>` and mark the control as `sensitive: true`. Structured public
control responses also redact nested secret-named fields, preserving ordinary
siblings and the original live values.

Control updates are exact. The API stores each submitted value as sent, or
refuses the whole request with HTTP 422 naming the control before any state or
audit changes; it never substitutes a default or clamps a value and records that
as the caller's change. The rules for each kind are in
`python -m role_aware_dashboard_toolkit guide api`. Refusal messages name the
control and the rule, never the submitted value. Because text controls accept
only strings (and numbers), a structured value cannot be stringified into a
public text control through an update.

Profile activation still repairs stale saved values to the control's current
bounds, options or default, as the dashboard does. A public text/color value
that activation would stringify from a nested secret field receives HTTP 422
before any state or audit changes, including a nested default selected by that
repair. Replace the value with an ordinary public value or explicitly configure
a write-only sensitive control; structured select values retain their existing
redacted responses. Profile endpoints
omit sensitive values. Reads of existing profiles expose only currently registered
public controls, and honor historical sensitivity flags. A control containing
nested secret-named fields is omitted as a whole, before any text coercion.
API activation leaves those omitted controls at their current values; the
stored profile is not rewritten. Role-Aware Dashboard Toolkit profiles
are not a credential store; use environment injection or a secret manager.

`role_aware_dashboard_toolkit.api` is importable from a core install even when FastAPI and
Pydantic are absent. Calling `create_app()` still requires the `api` extra and
raises an install hint if those optional dependencies are missing.

The key is scoped to a Role-Aware Dashboard Toolkit role. Set `ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE` or pass `api_role=` to `create_app()`; if neither is set, authenticated API requests use the built-in read-only `Viewer` role.

`/health` is static liveness only and does not expose control, profile, or audit counts. Operational data routes remain protected by the API-key and role checks below.

Anonymous local/demo access is opt-in only. Use `create_app(..., allow_anonymous=True)` or set `ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS=true`. The default anonymous scope can read controls only; pass `anonymous_role=` only for trusted local demos.

## Request limits

Request bodies larger than `max_body_bytes` (an argument to `create_app()`,
1 MiB by default) receive HTTP 413 before a route reads them; a streamed body
without `Content-Length` is counted as it arrives. JSON values nested more than
32 levels deep in a control update or a profile's `extra` receive HTTP 422. Both
refusals happen before any state or audit change. Raise `max_body_bytes` only
for trusted clients that need it; a reverse proxy can enforce its own limit too.
Malformed request bodies receive HTTP 422 listing each error's `type`, `loc`
and `msg`; unlike FastAPI's default, the response does not repeat the submitted
values.

## Cross-site requests

Every state-changing route (`POST`, `PATCH`, `DELETE`) refuses a request that
carries neither an `X-API-Key` header nor `Content-Type: application/json` (or
another `application/*+json` type) with HTTP 415, before any state or audit
change. Another web site can make a visitor's browser send a form or `text/plain`
POST without asking first, but a browser sends a custom header or a JSON content
type across sites only after a CORS preflight, and this API answers no
preflight. This matters when anonymous access is enabled: without it, a page the
operator visits during a local demo could activate a profile on the demo API.
Clients that send `X-API-Key` need no change. Anonymous clients send
`Content-Type: application/json`, also on bodyless requests such as profile
activation and deletion. A host that adds a CORS policy allowing other origins
removes this protection for those origins.

The content-type check alone does not stop DNS rebinding: a page whose own name
the attacker re-points at 127.0.0.1 is same-origin to the browser, so its JSON
requests need no preflight. With anonymous access on and no API key set, every
state-changing request must therefore name a loopback host (`localhost`,
`127.0.0.1` or another `127.x` address, or `[::1]`) in its `Host` header, or it
receives HTTP 403 before any state or audit change; the rebinding page's
requests carry its own name. Address an anonymous demo API as `localhost` or
`127.0.0.1`, or set an API key to serve it under another name. Reads are not
host-checked, so anonymous reads expose control values to such a page: keep
anonymous access to synthetic local data.

Public bind examples such as `--host 0.0.0.0` are deployment-only. Keep them
behind trusted network controls (private network segments, ingress auth, and
TLS termination) rather than exposing the API directly to the open internet.

Route permissions follow the existing role map:

- control reads require `can_view_metrics`
- control updates require both `can_edit_controls` and the target control's
  declared permission
- profile value reads require both `can_load_profiles` and `can_view_metrics`;
  profile metadata listings require `can_load_profiles`.
  Activation requires `can_load_profiles` and each
  restored control's declared permission, including controls changed by
  sanitization. Permission checks complete before any live values or audit
  events change. Unknown and sensitive profile values are not restored.
- profile save/delete require `can_save_profiles`
- audit reads require `can_view_audit`

Control update responses retain their normal fields but contain
`value: "<redacted-secret>"` when the caller lacks `can_view_metrics`. The
`sensitive` flag continues to describe the control definition; a false flag
does not grant read permission. The authorized update still completes.

Profile save and activation responses contain `values: {}` when the caller lacks
`can_view_metrics`; the authorized action still completes. This prevents a
save/load combination from exposing live controls through a newly saved profile.
Existing clients that read profile values with a custom load-only role must
receive an explicit metrics grant or use only metadata and action responses.
Audit responses reapply current control sensitivity to historical events, so
marking a control sensitive also hides its earlier values. Stored evidence is
not rewritten by these response filters.

Plugin loading is a separate trust boundary from API auth. Dashboard plugins are
in-process trusted code, not sandboxed extensions. When using entry-point
discovery, prefer explicit allowlists (`trusted_entry_points=[...]`) and avoid
loading unreviewed third-party plugins into production dashboards.

## Application state and callbacks

Each `create_app()` instance owns its own in-memory control values. Sharing a
`ControlRegistry` shares definitions, not live values. API updates and profile
activation update that API instance's state and audit records; they do not call
control callbacks, the dashboard's `on_change`, or a running Streamlit session.
The API is therefore not an automatic remote-control connection to a dashboard.

A host that needs shared UI/API state or external actions must supply its own
integration and enforce authorization at the action boundary. Shared profile or
audit stores do not synchronize live controls. The toolkit does not provide a
shared-state adapter or cross-process coordination.

## Control keys

Single-control reads accept slash-containing keys, including a key derived from
a label such as `Requests/second`. URL-encode the complete key when appending it
to `/controls/`, for example `urllib.parse.quote(key, safe="")`. Registration
does not need a different key to use the API.

## Profile identifiers and audit provenance

The API removes surrounding spaces from `profile_id` before saving. The POST
response, stored record, profile listing and audit events use that same canonical
identifier. Empty names, the exact names `.` and `..`, nonprintable characters,
and `/`, `\`, `%`, `?` or `#` are rejected with HTTP 422 before a store write or
success audit event. Dots within names, internal spaces and printable Unicode
are supported. Encode the returned identifier as one URL path segment when
reading, activating or deleting it; for example, Python clients can use
`urllib.parse.quote(profile_id, safe="")`.

These rules apply to API-created profiles. Existing records written directly
through a store or an earlier version are not renamed or silently removed from
listings. If such a record has an unaddressable identifier, migrate it through
its store adapter to an identifier satisfying the API rules before using the
HTTP routes.

A stored profile that exists but cannot be read (truncated, empty or otherwise
invalid JSON in a file store) is reported, not treated as missing. Reads and
activation return HTTP 500 with a fixed message naming the profile, a save that
would replace it returns HTTP 409, and `GET /profiles` returns the readable
records with an `X-Unreadable-Records` header counting the skipped ones. None of
these change state or write audit events, and messages never include store
paths or exception text; inspect the store's `read_errors` on the server.
Deleting the record remains available as a repair, except for a file that
holds a different record's id (for example a wrong backup): the store refuses
to delete it and `DELETE` returns HTTP 409, so repair that file on the server.
Stores without `read_errors`
cannot report this and keep returning 404 for a record they cannot load.

API control updates, profile saves, activations and successful deletions record
`source="api"` with the request's authorized role. API-created profiles also
persist `source="api"`. A profile's `role` remains descriptive metadata and does
not change the request's authorized role. Missing, unauthorized or failed
profile deletions produce no successful `profile_delete` event; failed saves
likewise produce no successful `profile_save` event.
