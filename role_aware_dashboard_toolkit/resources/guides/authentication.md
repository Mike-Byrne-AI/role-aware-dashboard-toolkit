# Verified sign-in, assigned roles and shared freeze

For the single-host HTTPS reference configuration and installed-artifact
acceptance sequence, read `python -m role_aware_dashboard_toolkit guide deployment`
after completing this identity and grant setup.

For a shared dashboard, create the authenticated starter:

```powershell
python -m role_aware_dashboard_toolkit init shared-dashboard --auth --dry-run
python -m role_aware_dashboard_toolkit init shared-dashboard --auth
Set-Location shared-dashboard
```

`example authenticated --format json` reads its files without writing. Plain
`init` preserves the local demonstration starter with explicit `auth_mode="demo"`;
its role selector is not access control. The older `auth_hook` remains a trusted
host integration hook; it does not provide the persistent grants in this guide.

## Configure the host

Use Python 3.10 or later and install the toolkit's `auth` extra, which includes
the required server and authentication dependency floors. Validate a separate
environment without system site packages before changing an existing launcher.
From a reviewed toolkit source checkout (not the generated app directory), use
an unused environment directory; choose another name if `.venv-auth` exists:

```powershell
python -m venv .venv-auth
.\.venv-auth\Scripts\python.exe -m pip install --upgrade pip setuptools
.\.venv-auth\Scripts\python.exe -m pip install -e ".[auth]"
.\.venv-auth\Scripts\python.exe -m pip check
```

A reviewed local wheel with its `[auth]` extra is also supported; package-index
publication is not assumed. Run the remaining commands with that environment's interpreter or
activate it first. Do not upgrade global Python or an active environment in place.
Keep the previous environment and launcher configuration until acceptance passes.

The supported Streamlit baseline is `streamlit[auth]>=1.65.0`, using its maintained
Starlette session implementation. The toolkit also requires these reviewed floors:

| Dependency | Minimum | Primary advisory |
| --- | --- | --- |
| Starlette | 1.3.1 | [Form limits](https://github.com/Kludex/starlette/security/advisories/GHSA-82w8-qh3p-5jfq) |
| AnyIO | 4.14.2 | [TLS hostname handling](https://github.com/agronholm/anyio/security/advisories/GHSA-82r6-8w77-94w6) |
| python-multipart | 0.0.31 | [Content-Length parsing](https://github.com/Kludex/python-multipart/security/advisories/GHSA-v9pg-7xvm-68hf) |
| h11 | 0.16.0 | [Chunked encoding](https://github.com/python-hyper/h11/security/advisories/GHSA-vqfr-h8mv-ghfj) |
| urllib3 | 2.8.0 | [Chunked response handling](https://github.com/urllib3/urllib3/security/advisories/GHSA-vxq7-64xx-v4gw) |
| Authlib | 1.6.11 | [OAuth state binding](https://github.com/authlib/authlib/security/advisories/GHSA-jj8c-mmj3-mmgv) |
| cryptography | 50.0.0 | [PKCS#7 decryption](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5) |
| joserfc | 1.7.4 | [Empty signature arrays](https://github.com/authlib/joserfc/security/advisories/GHSA-4pp3-559j-c5c2) |

These floors exclude reviewed affected ranges; an advisory match alone does not
establish reachability in a host application. Floors are not a reproducible lock
or a guarantee about future resolutions. Audit the complete resolved environment,
including installer/build tools, and retain its exact versions and package hashes
with private acceptance evidence. `pip check` checks dependency compatibility,
not known vulnerabilities. For example, install and run `pip-audit` inside the new
environment; investigate findings and packages it cannot audit. An unpublished
local toolkit may be skipped and still needs source review. Do not put host locks,
credentials or private evidence in the public source tree.

Register an OIDC application with your identity provider and obtain its exact
issuer, client ID, client secret and discovery URL. Register the exact callback
URL, such as `http://localhost:8501/oauth2callback` for local testing; use HTTPS
for a shared deployment. Streamlit and Authlib handle token signature, state and
nonce verification. Streamlit's [Starlette callback implementation](https://github.com/streamlit/streamlit/blob/1.65.0/lib/streamlit/web/server/starlette/starlette_auth_routes.py)
uses the initiating browser session for OAuth state. This adapter consumes only
their verified `st.user` result; it is not a parser or verifier for arbitrary
tokens or browser-supplied claims.

When provider metadata advertises `end_session_endpoint`, Streamlit also attempts
OIDC logout. Register the exact callback URL as a permitted
`post_logout_redirect_uri` with that provider and verify its sign-out flow. The
logout request may include an ID token as `id_token_hint`; redact those URLs from
logs and evidence. Provider support and logout policy must be checked explicitly.

Create an application-specific protected directory outside every repository.
On Windows, restrict its NTFS permissions to the app service account and trusted
operators before writing credentials; Python chmod does not establish Windows
ACL privacy. For a local single-user example, create a new directory and grant
only the current account and SYSTEM (review service-account needs before using
the same command on a shared host):

```powershell
$accessDirectory = Join-Path $env:LOCALAPPDATA "RoleAwareDashboard\shared-dashboard"
New-Item -ItemType Directory -Path $accessDirectory
$operatorAccount = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $accessDirectory /inheritance:r /grant:r "${operatorAccount}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
```

On POSIX, use a directory with mode 0700. Provisioning and key-loading helpers
reject broad POSIX permissions, a directory or key owned by another account
(other than root), and every link or reparse point except root-owned POSIX
system links (such as macOS /var and /tmp) whose directories only root can
change.
Direct SQLite store use checks the database file; the host must also protect its
directory and ancestors. Windows directory permissions remain
the operator's responsibility. Files, journals and backups need the same access
restriction; SQLite is for a single application on a local disk, not network
storage or a distributed deployment.

Create the key and empty database once:

```powershell
python -m role_aware_dashboard_toolkit.access_cli init --directory $accessDirectory
```

This generates a random 32-byte `identity.key` and `access.sqlite3`. Existing
files are refused. New stores are frozen and have no grants. A failed init may
leave partial files: inspect the protected directory instead of deleting or
resetting an existing store. Do not put this command in dashboard startup.

Use a protected editor or your secret manager to put the provider configuration
in `secrets.toml` inside that directory. This is a placeholder shape, not real
credentials; use a separate strong random cookie secret:

```toml
[auth]
redirect_uri = "http://localhost:8501/oauth2callback"
cookie_secret = "REPLACE_WITH_A_SEPARATE_RANDOM_SECRET"
client_id = "YOUR_REGISTERED_CLIENT_ID"
client_secret = "YOUR_PROVIDER_CLIENT_SECRET"
server_metadata_url = "https://YOUR_PROVIDER/.well-known/openid-configuration"
client_kwargs = { scope = "openid" }
```

The minimal `openid` scope avoids requesting names/email unless your provider
requires additional claims. Do not expose access or ID tokens. Configure the
non-secret host environment (use your actual issuer and client ID):

```powershell
$env:RADT_ACCESS_DIRECTORY = $accessDirectory
$env:RADT_OIDC_ISSUER = "https://YOUR_PROVIDER"
$env:RADT_OIDC_AUDIENCE = "YOUR_REGISTERED_CLIENT_ID"
```

## Provision explicitly

Obtain the intended account's stable OIDC `sub` from an authenticated provider
administrative workflow; do not substitute an email address, display name, URL
parameter or a subject claimed by an unverified requester. Confirm the issuer
and client context, because pairwise subjects can differ between applications.

Provision the first administrator from a trusted local terminal:

```powershell
python -m role_aware_dashboard_toolkit.access_cli grant --directory $accessDirectory --issuer $env:RADT_OIDC_ISSUER --role Admin
```

The utility privately prompts for the verified subject. It never prints that
subject or accepts it as a command-line argument. If no-echo input is unavailable,
it fails instead of using visible input. The application never enrolls the first
visitor and unknown users remain denied. Repeat for a second account with
`--role Viewer`. Repeating `--role` grants a choice among exactly those roles:

```powershell
python -m role_aware_dashboard_toolkit.access_cli grant --directory $accessDirectory --issuer $env:RADT_OIDC_ISSUER --role Operator --role Viewer
python -m role_aware_dashboard_toolkit.access_cli revoke --directory $accessDirectory --issuer $env:RADT_OIDC_ISSUER
```

`grant` replaces the account's complete assignment set; `revoke` removes all its
roles. Both can use `--principal` with an existing opaque principal ID instead
of prompting for a subject. These are trusted operator commands, never web
endpoints. Built-in roles are supported here; custom-role provisioning can use
the store API with an explicit allowed-role list.

## Launch and enforce boundaries

```powershell
python -m streamlit run app.py --secrets.files "$accessDirectory\secrets.toml"
```

The starter calls `prepare_access(config)` before loading account-specific state
or protected data, then renders assigned-role selection and shared freeze.
Account changes clear session state before host resources are rebuilt. Admin
has `can_manage_freeze`; other roles cannot change the shared switch. Freeze
blocks protected mutations, including Admin mutations, while its administrator
can still unfreeze. It does not block permitted reads and is not a maintenance
access barrier. UI state, imported profiles and role-name inputs do not
override server grants or freeze. Stale freeze submissions require a refresh.

Use `has_perm(ctx, permission)` immediately before private reads and
`can_write(ctx, permission)` immediately before mutations. These re-resolve the
current identity, assignments and freeze; do not cache their results. Host
callbacks, external services and custom plugins must enforce their own actual
action boundary. This does not cancel work already in flight or make a check
and an unrelated external write one atomic transaction. It does not secure the
optional HTTP API automatically; configure that API's own trusted identity.

The resolver checks exact issuer and audience, stable subject, token `exp`,
`iat`, optional `nbf`, and optional `auth_time`. Its default maximum token age is
one hour; expiry is the earliest applicable deadline. To require recent actual
authentication, request OIDC `max_age` and set `require_auth_time=True`.
Provider-specific support must be verified; issuance time alone does not prove
recent credential entry.

Streamlit's cookies can outlive token expiry; the adapter denies expired claims
on each check. Logging out ends the current Streamlit session and clears its
identity/token cookies. Streamlit also attempts provider OIDC logout when a usable
`end_session_endpoint` is available; otherwise it redirects back to the app.
This does not guarantee termination of other already-open dashboard sessions.
Server-side grant revocation denies their next checked action.
Provider-side account/session revocation is not
polled here; add that host integration when required.

The signed-out page shows a neutral sign-in prompt. If a provider session exists
but dashboard access cannot be confirmed, recovery offers **Sign out**, then a
fresh sign-in with an assigned account. The message does not guess whether the
cause is expiry, changed grants, or unavailable access services. Contact the
administrator if retrying does not restore access; signing in again cannot
restore a revoked grant. Denial still clears protected session state and stops
before host data is loaded.
Recovery sign-out runs before the next access check, so restoring a grant while
the denied page is open does not discard the user's sign-out click.

Custom Streamlit OIDC apps should use the same session boundaries as the starter:

```python
from role_aware_dashboard_toolkit.streamlit_auth import (
    clear_authenticated_state, sign_out_and_stop,
)

# Render this after the access gate. The callback runs before the next gate.
st.button("Sign out", on_click=sign_out_and_stop, args=(st,))

# In an application configuration-failure handler, before stopping:
# clear_authenticated_state(st)
# st.error("Access configuration is unavailable. Contact the administrator.")
# st.stop()
```

`clear_authenticated_state(st)` removes all application session values while
retaining a pending sign-out denial. It does not clear provider cookies or grant
access. `sign_out_and_stop(st)` clears application state, requests provider logout
and stops execution. If provider logout fails, the current Streamlit session stays
denied across reruns until signed-out state is confirmed. This cannot revoke a
provider cookie, a new Streamlit session, or another browser's session. Treat an
unconfirmed logout as an operational failure and resolve it with the provider;
do not describe it as global revocation. Using a plain `session_state.clear()` in
an error handler would erase this pending denial marker, so use the helper.
Custom identity hosts own their provider logout and new-session recovery. An
unrelated Streamlit signed-out status cannot release a custom host's pending
denial.

## Data handling and acceptance checks

The database stores keyed opaque principal IDs, role names, and current freeze
revision/actor. The HMAC key is separate; neither raw subject, email, password
nor token is written to this database. Opaque IDs are still linkable personal data,
not anonymization. Protect the database, key and backups, retain them only as
needed, and keep them out of profiles and exports. Key rotation changes every
principal ID and requires reprovisioning. Backup restoration can restore revoked
grants and old freeze state. Keep the dashboard offline throughout restoration
and grant reconciliation. Before reopening access, reconcile every restored
grant against the current protected record of grants and revocations, enable
freeze, and verify revoked accounts cannot read protected data. If that record
is missing or incomplete, keep access closed until the intended grants can be
established. Freeze alone still permits reads. The current freeze row is not a
complete administrative audit history.

Streamlit itself retains provider claims in a signed browser identity cookie and
session memory. Version 1.65.0 also stores returned ID/access tokens in a separate
signed browser token cookie, even though this adapter reads only `st.user`.
Signing prevents undetected modification; it is not encryption. Review provider
claims and token scopes, request minimal access, and exclude cookies/tokens from
application displays, exports and logs. The database minimization above does not
remove the identity provider's or Streamlit's own data handling.

In Streamlit 1.65.0, identity/token cookies are HttpOnly and SameSite=Lax but do
not set Secure; its session middleware enables `https_only` from
`server.sslCertFile`. Do not assume HTTPS at a reverse proxy establishes the
required cookie policy. Inspect the actual deployment's cookies and resolve
transport protection and cookie policy before production use, including when
TLS terminates outside Streamlit. Local HTTP tests do not prove these properties.

Test two separately authenticated accounts and the actual provider redirect:
Admin can unfreeze; Viewer cannot self-promote, edit controls or unfreeze; a
profile cannot grant a role; an unassigned account receives no protected data.
Grant only Viewer to the already-open Admin account and verify its next protected
action is denied. Revoke all roles and verify access is denied. Switch accounts
and confirm old account state is gone. Change freeze in one session and verify
the other cannot submit a stale unfreeze. Confirm expired identities are denied.
Synthetic tests prove library behavior, not your provider or deployment setup.

Before switching an existing launcher, test the actual callback implementation:
legitimate sign-in succeeds; a callback without the initiating browser session,
with a different session, or with tampered session cookies is rejected without
an identity cookie. Reused state/callbacks must be rejected, including replay of
an old session cookie with a consumed authorization code. Verify forged and
expired tokens, wrong issuer/audience/nonce, and tampered identity cookies are
denied. An import failure in a probe for obsolete framework internals is not a
passing test. Use synthetic accounts, separate browser contexts and bounded local
tests, then repeat legitimate sign-in, sign-out and role checks with the actual
host and provider. Switch only after these checks pass and verify the new process
uses the intended interpreter. Retain a reversible launcher change.

Production additionally needs the chosen provider and administrator MFA policy,
verified HTTPS/callback/logout/cookie settings, protected storage and secret
rotation, and a durable protected history of grants, revocations and administrator actions.
Define logout and provider revocation across sessions. If immediate emergency
cancellation is required, use atomic backend authorization/mutation or explicit
cancellation semantics. Enforce authorization in real loaders, tenant queries,
downloads, APIs and trusted plugins. A local HTTP identity provider and successful
synthetic checks do not satisfy these production requirements.

Primary references: [Streamlit authentication](https://docs.streamlit.io/develop/concepts/connections/authentication),
[Streamlit secrets](https://docs.streamlit.io/develop/concepts/connections/secrets-management),
and [OIDC ID-token claims](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
