# Shared Project Pulse

This starter requires verified sign-in and a server-assigned role before rendering
the dashboard. It starts frozen and gives no visitor access automatically.
Planning controls are synthetic; profiles and audit use session-local memory.

This is the `init --auth` starter. Plain `init` creates a local demonstration
whose role selector does not verify identity; do not use that demonstration as
authentication for a shared app. This starter defaults to `127.0.0.1`, so only
the host computer can reach it directly. Shared hosting needs the guide's
provider, HTTPS and deployment checks before access is opened to other users.

Read the installed setup guide:

```powershell
python -m role_aware_dashboard_toolkit guide authentication
python -m role_aware_dashboard_toolkit guide deployment
```

Follow its provider registration, protected directory, provisioning and launch
steps. Use Python 3.11 or later and install the toolkit's `auth` extra from its
reviewed source checkout or a local wheel; it requires `streamlit[auth]>=1.66.1`,
`Pillow>=13.0.0` and patched authentication and server dependencies.
No package-index publication is assumed. First validate a
separate environment without system site packages, run `python -m pip check`
and a dependency audit, and verify callback/session rejection before changing
an existing launcher. Keep the previous environment for rollback.

Launch Streamlit from this generated application's directory, using the guide's
external `--secrets.files` argument. The working directory matters: launching
elsewhere can omit this application's `.streamlit/config.toml` defaults.
Restart the server after changing its environment or provider secrets.

The app requires `RADT_ACCESS_DIRECTORY`, `RADT_OIDC_ISSUER` and
`RADT_OIDC_AUDIENCE` from trusted host configuration. `RADT_OIDC_PROVIDER` is
optional for a named Streamlit provider. The directory must be outside this
application tree and contains `identity.key` and `access.sqlite3`. Keep provider
secrets outside the repository too, selected with Streamlit's `--secrets.files`.

Only a trusted local operator grants roles using
`python -m role_aware_dashboard_toolkit.access_cli`; the dashboard offers no
self-enrollment. Users with multiple grants may select only their assigned
roles. Admin can change the shared freeze switch. Grants and freeze persist
across restarts, while demo plan values remain local to each session.
Saved sample profiles and audit history also end with the session. A shared URL
does not make these records durable or synchronize users' planning values.

`build_access_policy()` reads host configuration. `build_controls()` defines
the plan. `prepare_access(config)` runs before account-specific resources and
clears session state on account changes. Add permission checks at each custom
data-read or mutation boundary; do not cache an authorization result.
If access configuration becomes unavailable, `clear_authenticated_state(st)`
discards private session state before the error is displayed. It retains a
pending sign-out request so configuration recovery cannot silently cancel it.

The generated `.streamlit/config.toml` intentionally sets
`client.disableDataExport = true`. This hides native CSV downloads from
`st.dataframe`, `st.data_editor` and chart table views, and disables clipboard
copy from read-only tables. `st.data_editor` copy/paste remains available.
This default removes convenient native spreadsheet export paths for unreviewed
data; it does not sanitize formula cells, restrict custom download buttons or
prevent access to data already sent to the browser. It is not a data-protection
or authorization boundary. Before opting in to native exports by setting it to
`false`, review data sensitivity and spreadsheet-formula behavior for every
displayed dataset, and test the resulting CSV in the intended spreadsheet
clients. Custom exports need their own authorization and data handling.

The config also sets `client.showErrorDetails = "none"`, so unexpected errors
show a generic browser message. The operator console can still contain full
exception details and must stay private. For "Access configuration is
unavailable", the operator should check the required environment variables,
external key/database paths and permissions against the setup guide. For an
access denial after sign-in, check the account's server-assigned grants and the
guide's expiry/recovery steps; changing browser state cannot grant access.

Token expiry and a one-hour maximum issued-token age are enforced. If you also
require recent credential entry, configure OIDC `max_age` and set
`require_auth_time=True` in the resolver. Streamlit logout ends the current
session, clears its identity/token cookies and attempts provider OIDC logout
when supported. Register and test the exact post-logout callback with the
provider. Other existing dashboard sessions may remain; server-side grant
revocation prevents their next protected action. Provider-side revocation
needs a host integration. Streamlit also retains ID/access tokens in a signed
browser cookie; follow the guide's data-handling and HTTPS/cookie requirements.
The Sign out button calls `sign_out_and_stop(st)` before the next access check.
If logout fails or is still pending, this session remains denied until Streamlit
reports signed-out; this local latch does not revoke other sessions.

Before sharing, run the guide's two-account acceptance checks against the actual
provider and deployment. A passing synthetic test does not prove provider setup.
