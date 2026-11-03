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
configure its API-key and role policy independently, or explicitly pass
`authentication=APIAuthentication(...)` as described below.

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
1 MiB by default) receive HTTP 413 before a toolkit route reads them; a streamed
body without `Content-Length` is counted as it arrives. JSON values nested more than
32 levels deep in a control update or a profile's `extra` receive HTTP 422. Both
refusals happen before any state or audit change. Raise `max_body_bytes` only
for trusted clients that need it; a reverse proxy can enforce its own limit too.
Malformed request bodies receive HTTP 422 listing each error's `type`, `loc`
and `msg`; unlike FastAPI's default, the response does not repeat the submitted
values. These limits and error formats cover the routes `create_app()` creates.
Routes a host adds to the returned app keep FastAPI's defaults, so the host sets
their limits.

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

By default each `create_app()` instance owns its own in-memory control values. Sharing a
`ControlRegistry` shares definitions, not live values. API updates and profile
activation update that API instance's state and audit records; they do not call
control callbacks, the dashboard's `on_change`, or a running Streamlit session.
The API is therefore not an automatic remote-control connection to a dashboard.

A host that needs shared UI/API state or external actions must supply its own
integration and enforce authorization at the action boundary. Shared profile or
audit stores do not synchronize live controls. The toolkit does not provide a
automatic UI/API synchronization. Opt-in `state_store=` provides versioned API
control persistence as described below.

## Per-request identity and organization isolation

```python
from role_aware_dashboard_toolkit.api import create_app
from role_aware_dashboard_toolkit.api_access import APIAuthentication

# verify_request_credentials is supplied by the host. It verifies the token or
# session and returns Identity(issuer, subject, expires_at), or None.
authentication = APIAuthentication(verify_request_credentials, access_store, identity_key)
app = create_app(registry, authentication=authentication,
                 profile_store=organization_profiles, audit=organization_audit)
```

The resolver is a synchronous trusted host adapter, not a parser for unverified
claims. Verify signature/session, issuer, audience and expiry, and apply the
host's CSRF policy for cookie authentication. Verification failures deny with
401; there is no shared-key or anonymous fallback. `X-Dashboard-Role` selects
only among the principal's current grants; absent selection uses its first
assigned role. The live identity, grants and freeze are rechecked at protected
boundaries. Every mutation, including profile activation/save/delete, obeys
freeze. Audit writes bind the opaque principal and a fresh request identifier;
that identifier is not a persistent login-session identifier. The resolver must
not cache stale identities or expose credentials in exceptions/logs.

Use one organization per isolated app/store. Provision independent access
stores and identity keys, profile stores/directories, audit logs and state
backends. Per-user authentication requires an explicitly supplied profile store
or directory; it never uses the legacy shared `profiles` directory implicitly.
Separate deployments and OS credentials offer stronger isolation than
mounting apps inside one trusted Python process. Mount paths and tenant headers
are routing inputs, never membership proof. Reusing a store or audit log across
organizations breaks the isolation contract; the toolkit does not automatically
partition shared stores. Test two apps with identical resource names and role
names: an account granted Admin in one must receive no access to the other until
independently provisioned there. Include reads, writes, profiles and audit.

## Durable live state and conflicting writes

```python
from role_aware_dashboard_toolkit.state_store import SQLiteStateStore

# Trusted operator provisioning, once, in an OS-protected directory outside Git:
# SQLiteStateStore.create(state_path)
state = SQLiteStateStore(state_path)  # opens existing valid state only
app = create_app(registry, authentication=authentication,
                 profile_store=organization_profiles, audit=organization_audit,
                 state_store=state)
```

`GET /controls` and `GET /controls/{key}` return an `ETag` such as `"0"`.
Send that exact value in `If-Match` for `PATCH /controls` and
`POST /profiles/{id}/activate`. Explicit backend mode requires it (428 if
missing); stale values or concurrent replacements return 409 without a success
audit event. Refresh and review the new values before retrying. Successful
mutations return the new ETag. Response bodies retain their previous shape.
Legacy in-memory apps may optionally use the same precondition but do not have
to. `InMemoryStateStore` provides the explicit versioned contract without disk
durability. Write-only roles need a host-authorized way to obtain revisions;
this API does not grant read access merely to obtain an ETag.

Snapshots contain public JSON-compatible control values. Explicit backend mode
refuses secret-control writes and structured secret fields; use the host secret
backend for secrets. Sensitive defaults remain host configuration and are never
persisted. Missing, unreadable or schema-incompatible state denies live-state
operations with 503 rather than resetting values. A changed control definition
may require an explicit state migration; do not delete the database to repair it.

Each app serializes its synchronous endpoint operations. SQLite transactions
and revision checks prevent two local processes committing the same state
revision. Profile save takes the current snapshot; profiles and audit are
separate stores, not part of the state transaction. File profiles still require
one writer process. A crash after state commit can precede audit persistence;
state persistence is not a durable transactional audit trail. Authorization and
state commit are also separate transactions: revocation denies the next check,
but cannot cancel work already in progress. Hosts requiring atomic revocation,
business writes and audit must supply one transactional action boundary.
Use local disk, protect files/backups with OS permissions, and rehearse restart
and restore. Restore can roll back values and revisions: close access, reconcile
current authority and effects, and invalidate old clients before reopening.

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
not change the request's authorized role. Missing, unauthorized or storage-refused
profile deletions produce no successful `profile_delete` event; a save rejected
before storage likewise produces no successful `profile_save` event.

Audit recording follows the state or profile operation. If an audit adapter
raises after the operation commits, the API returns HTTP 500 explicitly saying
that the operation committed but audit recording failed. Control writes and
profile activation include the committed state `ETag`; profile save/delete
failures do not include one. The API does not undo or retry the committed
operation. Refresh the state/profile and inspect audit diagnostics before
deciding whether any further action is needed; a batch may already have some
audit events. The built-in audit writer can also fail asynchronously or drop
queued events, so a successful HTTP response does not guarantee durable audit
persistence. State and audit remain separate transaction boundaries.
