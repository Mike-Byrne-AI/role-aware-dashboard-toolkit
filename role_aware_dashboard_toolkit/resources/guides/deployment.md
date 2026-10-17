# Deploy one authenticated dashboard

This recipe covers one dashboard process, one local access database and a Caddy
HTTPS reverse proxy on the same host, with an existing Keycloak OIDC provider.
A server operator must control the domain, certificates, service account and
provider. The toolkit supplies the dashboard and permission checks; it does not
operate these services. Multiple people can use separate browser sessions.

Complete [authentication](authentication.md) first. Generate with `init --auth`;
plain `init` creates a local demo whose role selector is not authentication.
Use a maintained Python runtime and the exact reviewed toolkit wheel with its
`[auth]` extra in a fresh virtual environment. Record the wheel SHA-256 and the
installed dependency versions. Do not install an unreviewed update into a running
environment. Retain the previous artifact and environment for rollback.

This is a reference configuration, not evidence that your deployment has passed.
Run the acceptance sequence below against the actual host, provider and artifact
before inviting users. Keep the resulting private evidence outside repositories.

## 1. Register a dedicated OIDC client

Use a dedicated Keycloak realm and a confidential OpenID Connect client for this
dashboard. Enable client authentication and the standard authorization-code flow.
Disable implicit flow, direct password grants and service accounts for this client.
Use an exact HTTPS callback such as
`https://dashboard.example.com/oauth2callback`, without wildcard redirect URIs.
Register that same exact URL as the allowed post-logout redirect for Streamlit.
Set the web origin to the dashboard's exact HTTPS origin.

Use the realm's discovery document and its exact `issuer` value; do not guess a
provider URL or use an account email as the OIDC subject. Create separate test
accounts for Admin, Viewer and an unassigned visitor. Verify each account's stable
subject in the provider's administrative interface before provisioning grants.
The identity provider's account enrollment, MFA and recovery policies are separate
from dashboard roles. Never use a Keycloak administrator account as a dashboard
test user.

Keep the client secret, a separate random cookie secret, access key and database
in the protected directory from the authentication guide. In its `secrets.toml`,
use the real values in this shape:

```toml
[auth]
redirect_uri = "https://dashboard.example.com/oauth2callback"
cookie_secret = "REPLACE_WITH_A_SEPARATE_RANDOM_SECRET"
client_id = "YOUR_REGISTERED_CLIENT_ID"
client_secret = "YOUR_PROVIDER_CLIENT_SECRET"
server_metadata_url = "https://YOUR_PROVIDER/realms/YOUR_REALM/.well-known/openid-configuration"
client_kwargs = { scope = "openid" }
```

Do not save this file beside application code or commit it. Request only the claims
the dashboard needs. Preserve the authentication guide's explicit provisioning;
the first visitor never becomes Admin automatically.

## 2. Keep the application private behind the proxy

Run the generated application from its own directory, using the reviewed
environment, explicit protected secrets path and loopback listener. A PowerShell
operator session, after setting the guide's environment variables, uses:

```powershell
Set-Location 'C:\dashboard\app'
$dashboardPython = 'C:\dashboard\venv\Scripts\python.exe'
& $dashboardPython -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --secrets.files "$env:RADT_ACCESS_DIRECTORY\secrets.toml"
```

Use the equivalent service configuration on the chosen host. The service must
start in the generated app directory so its `.streamlit/config.toml` is applied.
Keep CORS and XSRF protection enabled, detailed browser errors disabled and native
exports disabled until reviewed. Do not put the app port on a public interface.
Run the service with access only to its required data and protected runtime files.
A production operator should supervise and restart the service; an open terminal
is not a service-management or backup strategy.

The starter persists grants and freeze in SQLite, but sample plan values, profiles
and audit are session-local. Add appropriately scoped persistent application stores
before promising shared or durable team records. SQLite belongs on the host's
local disk; this recipe does not cover network filesystems or multiple replicas.

## 3. Terminate HTTPS and secure every upstream cookie

Install a reviewed Caddy release through its official distribution, then configure
a real DNS hostname. Caddy needs the network/domain access required to obtain and
renew the certificate. Keep its administrative endpoint on loopback. The example
below assumes Caddy and the dashboard run on the same host.

```caddyfile
dashboard.example.com {
    header {
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
        Cache-Control "no-store"
    }
    reverse_proxy 127.0.0.1:8501 {
        header_down Set-Cookie "^(.*)$" "$1; Secure"
    }
}
```

Replace the example hostname. Validate the file with `caddy validate --config
Caddyfile --adapter caddyfile` before reloading the service. Confirm that plain
HTTP redirects to HTTPS and that the certificate is valid in an ordinary browser,
without disabling certificate verification. Expose only the intended proxy ports;
the backend listener and provider administration interfaces remain restricted.

The cookie rewrite deliberately adds `Secure` to every upstream cookie, including
the temporary OAuth session cookie and Streamlit identity/token cookies. Streamlit
1.65.0 does not set that flag on all authentication cookies by itself. Adding it
at this boundary addresses transport; it does not encrypt a signed cookie, reduce
token scopes, shorten lifetime or revoke another session. Check actual responses
after every framework/proxy upgrade. A proxy configuration file alone is not
proof that the browser received these flags.

Do not enable access logs that retain authorization codes, state, cookies or logout
token hints. If request logging is needed, configure and test redaction first.
Protect service logs and backups. Avoid logging complete provider exceptions,
claims or callback URLs in application code.

## 4. Verify the installed artifact through separate browser sessions

Use separate browser profiles for the three synthetic accounts. Do not substitute
changing a role widget for actually signing in as a different account.

1. With missing host configuration, the app denies access and shows no private
   data or exception details. With valid configuration, the unassigned account
   still receives no dashboard data or control access.
2. Admin signs in, sees the assigned role and can manage shared freeze. Viewer
   signs in independently and cannot edit protected controls or unfreeze.
3. Admin's saved profile or submitted widget values cannot give Viewer a new role.
   Test the application's real data/action adapters directly too: hiding a button
   does not enforce a backend permission.
4. Downgrade an already-open Admin session to Viewer, then attempt a protected
   action. Revoke its grants and repeat. Both must obey the new server assignments.
5. Sign out, change accounts and verify old private state is absent. Test another
   open tab: logout is not a promise of global revocation. If logout fails, confirm
   the same session stays denied, and resolve the provider failure.
6. Confirm the login and callback reject a missing/different initiating session,
   tampered cookies, consumed authorization codes, and invalid token claims.
   Use a separate test client/realm for protocol fault injection. Do not alter a
   team's provider signing keys or weaken its policy to conduct this test.
7. Inspect the real login, callback and logout responses: authentication cookies
   must be Secure and HttpOnly with the intended SameSite policy and paths.
   Check session expiry and that tokens/codes are absent from app output and logs.
8. Verify access and stored data after a normal restart and a controlled failure.
   Confirm the backup/restore procedure does not silently restore revoked grants.
   Record which data is intentionally session-local.

Record artifact hash, Python/dependency versions, provider/proxy configuration
versions, the performed checks and failures. Redact credentials, cookies, tokens,
subjects and callback query strings. A failed or unperformed check is incomplete
acceptance; a large source-test count does not replace it.

## 5. Operate and update

Name the person responsible for provider accounts, grants, incident response,
backups and updates. Keep a protected record of grant/revocation changes; the
current access database row and session-local audit are not a complete durable
administrative history. Keep the dashboard offline throughout backup restoration
and grant reconciliation: an older backup can restore revoked grants and an
unfrozen state. Before reopening access, reconcile every restored grant against
that current protected record, enable freeze, and verify revoked accounts cannot
read protected data. If the record is missing or incomplete, keep access closed
until the intended grants can be established. Freeze blocks protected mutations;
it does not block permitted reads and is not a maintenance access barrier.

Monitor availability and storage failures. Test updates
in a separate environment with the same sequence before switching the live
service. Remove access explicitly when a teammate leaves.

Freeze and revocation protect subsequent checked actions. Already-authorized work
may finish; sensitive external effects need their own transactional authorization
or cancellation design. File/profile/cache/export scope and optional APIs/plugins
remain application responsibilities.

Primary references: [Keycloak OIDC clients](https://www.keycloak.org/docs/latest/server_admin/index.html#assembly-managing-clients_server_administration_guide),
[Keycloak production configuration](https://www.keycloak.org/server/configuration-production),
[Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy),
[Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https),
and [Streamlit authentication](https://docs.streamlit.io/develop/concepts/connections/authentication).
