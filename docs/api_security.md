# Role-Aware Dashboard Toolkit API security

Role-Aware Dashboard Toolkit's optional FastAPI surface is secure by default. Protected routes require `ROLE_AWARE_DASHBOARD_TOOLKIT_API_KEY` and the request must send the same value in the `X-API-Key` header.
Dashboard setup and first-run control flows are documented in `docs/dashboard_tools.md`; this page focuses on API trust boundaries and permissions.

Selectable dashboard roles are workflow context, not authentication. For shared
dashboard deployments, configure `DashboardConfig(auth_hook=...)` to bind roles
to trusted identities and keep the dashboard behind trusted ingress
authentication and TLS. Never authorize actions from the role selector alone.

Sensitive controls are write-only through the API response surface: updates are
accepted into in-memory state, while reads and update responses return
`<redacted-secret>` and mark the control as `sensitive: true`. Profile endpoints
omit sensitive values. Role-Aware Dashboard Toolkit profiles
are not a credential store; use environment injection or a secret manager.

`role_aware_dashboard_toolkit.api` is importable from a core install even when FastAPI and
Pydantic are absent. Calling `create_app()` still requires the `api` extra and
raises an install hint if those optional dependencies are missing.

The key is scoped to a Role-Aware Dashboard Toolkit role. Set `ROLE_AWARE_DASHBOARD_TOOLKIT_API_ROLE` or pass `api_role=` to `create_app()`; if neither is set, authenticated API requests use the built-in read-only `Viewer` role.

`/health` is static liveness only and does not expose control, profile, or audit counts. Operational data routes remain protected by the API-key and role checks below.

Anonymous local/demo access is opt-in only. Use `create_app(..., allow_anonymous=True)` or set `ROLE_AWARE_DASHBOARD_TOOLKIT_API_ALLOW_ANONYMOUS=true`. The default anonymous scope can read controls only; pass `anonymous_role=` only for trusted local demos.

Public bind examples such as `--host 0.0.0.0` are deployment-only. Keep them
behind trusted network controls (private network segments, ingress auth, and
TLS termination) rather than exposing the API directly to the open internet.

Route permissions follow the existing role map:

- control reads require `can_view_metrics`
- control updates require both `can_edit_controls` and the target control's
  declared permission
- profile reads require `can_load_profiles`; activation also requires each
  restored control's declared permission, including controls changed by
  sanitization. Permission checks complete before any live values or audit
  events change. Unknown and sensitive profile values are not restored.
- profile save/delete require `can_save_profiles`
- audit reads require `can_view_audit`

Plugin loading is a separate trust boundary from API auth. Dashboard plugins are
in-process trusted code, not sandboxed extensions. When using entry-point
discovery, prefer explicit allowlists (`trusted_entry_points=[...]`) and avoid
loading unreviewed third-party plugins into production dashboards.

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

API control updates, profile saves, activations and successful deletions record
`source="api"` with the request's authorized role. API-created profiles also
persist `source="api"`. A profile's `role` remains descriptive metadata and does
not change the request's authorized role. Missing, unauthorized or failed
profile deletions produce no successful `profile_delete` event; failed saves
likewise produce no successful `profile_save` event.
