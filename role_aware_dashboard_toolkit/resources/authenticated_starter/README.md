# Shared Project Pulse

This starter requires verified sign-in and a server-assigned role before rendering
the dashboard. It starts frozen and gives no visitor access automatically.
Planning controls are synthetic; profiles and audit use session-local memory.

Read the installed setup guide:

```powershell
python -m role_aware_dashboard_toolkit guide authentication
```

Follow its provider registration, protected directory, provisioning and launch
steps. Install the toolkit's `auth` extra from its reviewed source checkout or a
local wheel; it requires `streamlit[auth]>=1.65.0` and patched authentication and
server dependencies. No package-index publication is assumed. First validate a
separate environment without system site packages, run `python -m pip check`
and a dependency audit, and verify callback/session rejection before changing
an existing launcher. Keep the previous environment for rollback.

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

`build_access_policy()` reads host configuration. `build_controls()` defines
the plan. `prepare_access(config)` runs before account-specific resources and
clears session state on account changes. Add permission checks at each custom
data-read or mutation boundary; do not cache an authorization result.

Token expiry and a one-hour maximum issued-token age are enforced. If you also
require recent credential entry, configure OIDC `max_age` and set
`require_auth_time=True` in the resolver. Streamlit logout ends the current
session, clears its identity/token cookies and attempts provider OIDC logout
when supported. Register and test the exact post-logout callback with the
provider. Other existing dashboard sessions may remain; server-side grant
revocation prevents their next protected action. Provider-side revocation
needs a host integration. Streamlit also retains ID/access tokens in a signed
browser cookie; follow the guide's data-handling and HTTPS/cookie requirements.

Before sharing, run the guide's two-account acceptance checks against the actual
provider and deployment. A passing synthetic test does not prove provider setup.
