# A / B / C Access Lab

This mock dashboard has three independently protected sections and four access
roles. Its records are invented. The normal [app.py](app.py) entry point requires
verified sign-in and operator-assigned roles. The separate [demo.py](demo.py)
entry point lets you explore the screens locally without provider credentials.

| Assigned access role | Section A | Section B | Section C | Manage freeze / admin action |
| --- | --- | --- | --- | --- |
| `Admin` | Read | Read | Read | Yes |
| `AOnly` | Read | Denied | Denied | No |
| `AB` | Read | Read | Denied | No |
| `COnly` | Denied | Denied | Read | No |
| No assignment | Denied | Denied | Denied | No |

An **access role** answers what an authenticated account may do. A toolkit
**profile** is a saved set of dashboard settings; loading or renaming one cannot
grant access. This example hides settings-profile controls to make that
distinction clear. Each account normally receives one of the four roles above.
An account assigned multiple roles may select only among its current grants;
permissions come from the active role, rather than a union of all assigned roles.

## Explore the local mock

Use the [development setup](../../CONTRIBUTING.md#development-setup), then run from
the repository root:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m streamlit run examples/section_access/demo.py --server.address 127.0.0.1 --server.port 8517
```

Open `http://127.0.0.1:8517`. Change **Simulated account** in the sidebar and try
every section. The Admin account can unfreeze changes and click **Run admin
action**, which increments a harmless session counter. Reads remain available
while frozen; restricted roles cannot run the action or change freeze. Choosing
**Unassigned** denies the dashboard. Switching accounts clears session data.

**The simulation is not sign-in.** Anyone who can reach it can choose Admin,
including through its demonstration query parameter. Keep it on loopback and
use synthetic data only. Its grants and shared freeze live in process memory;
restarting the server discards them. `app.py` does not import the simulation or
accept its account selector as identity.

## Set up actual administrator access

These are operator steps, not commands run by dashboard visitors. Real provider
configuration, verified account subjects, filesystem permissions and HTTPS
deployment are prerequisites for shared use. The mock alone does not establish
that those deployment requirements have passed.

### 1. Configure the identity provider

Install the authentication extra in this checkout's environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[auth]"
```

Register an OIDC application with your chosen identity provider. Obtain its
exact issuer, client ID, client secret and discovery URL. Register the exact
callback `http://localhost:8501/oauth2callback` for this local example; shared
hosting needs its actual HTTPS callback. Configure the provider's account and
MFA policy, particularly for administrators. Streamlit handles sign-in through
the provider and exposes the verified user to the app.
See [Streamlit authentication](https://docs.streamlit.io/develop/concepts/connections/authentication).

### 2. Protect an external directory before writing secrets

For a new, single-user Windows development directory, grant the current Windows
account and SYSTEM access. Run these steps from a trusted PowerShell terminal:

```powershell
$accessDirectory = Join-Path $env:LOCALAPPDATA "RoleAwareDashboard\section-access"
if (Test-Path -LiteralPath $accessDirectory) { throw "Choose a new directory; do not reset existing access data." }
New-Item -ItemType Directory -Path $accessDirectory -ErrorAction Stop | Out-Null
$operatorAccount = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $accessDirectory /inheritance:r /grant:r "${operatorAccount}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"
if ($LASTEXITCODE -ne 0) { throw "ACL setup failed. Do not provision secrets." }
icacls $accessDirectory
```

Inspect that final ACL listing before proceeding. On a shared host, use the
actual service account and designated trusted operators, and remove unintended
access. Disabling inheritance removes inherited entries; it does not remove
unrelated explicit entries. Python `chmod` does not establish equivalent Windows
protection. See [Microsoft's icacls reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls).
Keep the key, database, journal files and backups outside every source checkout
with the same protection. The built-in store expects a local disk on one host.

Initialize once; this creates a random private key and an empty, frozen database:

```powershell
.\.venv\Scripts\python.exe -m role_aware_dashboard_toolkit.access_cli init --directory $accessDirectory
```

Existing files are refused. If initialization fails, inspect the protected
directory; do not delete or recreate a live store. There is no automatic first
administrator and no access is granted to the first visitor.

### 3. Store provider secrets outside the checkout

Using a protected editor or secret manager, create `secrets.toml` inside
`$accessDirectory`. Replace these placeholders with your registered values and a
separate strong random cookie secret; do not reuse `identity.key`:

```toml
[auth]
redirect_uri = "http://localhost:8501/oauth2callback"
cookie_secret = "REPLACE_WITH_A_SEPARATE_RANDOM_SECRET"
client_id = "YOUR_REGISTERED_CLIENT_ID"
client_secret = "YOUR_PROVIDER_CLIENT_SECRET"
server_metadata_url = "https://YOUR_PROVIDER/.well-known/openid-configuration"
client_kwargs = { scope = "openid" }
```

The minimal scope avoids requesting optional profile/email information unless
your provider requires it. Keep credentials out of command arguments, repository
files and logs. See [Streamlit secrets management](https://docs.streamlit.io/develop/concepts/connections/secrets-management).
Set the non-secret host configuration in the terminal used to provision and
launch the app:

```powershell
$env:RADT_ACCESS_DIRECTORY = $accessDirectory
$env:RADT_OIDC_ISSUER = "https://YOUR_PROVIDER"
$env:RADT_OIDC_AUDIENCE = "YOUR_REGISTERED_CLIENT_ID"
```

Use the issuer exactly, including any provider-specific path or trailing slash.
The audience must be the same registered client ID as in `secrets.toml`. If
using a named `[auth.provider_name]` configuration instead, also set
`RADT_OIDC_PROVIDER` to that provider name.

### 4. Grant the four accounts explicitly

Get each intended account's verified stable OIDC subject (`sub`) from a trusted
provider administrative workflow for this exact client. Do not use email,
display name or a subject submitted by an unverified requester. The issuer and
subject jointly identify an account; pairwise subjects can vary between clients.
See [OIDC claim stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).

Run each command and privately enter a **different intended account's subject**
when prompted:

```powershell
.\.venv\Scripts\python.exe -m examples.section_access.provision grant --role Admin
.\.venv\Scripts\python.exe -m examples.section_access.provision grant --role AOnly
.\.venv\Scripts\python.exe -m examples.section_access.provision grant --role AB
.\.venv\Scripts\python.exe -m examples.section_access.provision grant --role COnly
```

These commands require trusted filesystem access. The no-echo prompt fails if
the terminal cannot hide input. Subjects are never accepted as command-line
arguments, printed, or stored in the access database. The store records keyed
opaque principal IDs and role/freeze metadata. Those IDs are still linkable
pseudonymous data. Protect the key and backups; rotating the key requires
reprovisioning all assignments.

The example's helper is necessary because these custom role names are outside
the built-in access CLI's grant choices. `grant` **replaces all assignments** for
the entered account. To allow that account to choose between roles, repeat
`--role`, for example `grant --role Admin --role AOnly`. Downgrade an Admin to
`AOnly` by running the AOnly command for that Admin's subject. Revoke all roles:

```powershell
.\.venv\Scripts\python.exe -m examples.section_access.provision revoke
```

An application's Admin role allows freeze management and the sample action;
it does not expose grant provisioning in the browser. A Windows/server
administrator or attacker who can modify trusted app code or the grants
database can change policy; dashboard permissions cannot defend against that
host compromise.

### 5. Launch and check the real sign-in

```powershell
.\.venv\Scripts\python.exe -m streamlit run examples/section_access/app.py --server.address 127.0.0.1 --server.port 8501 --secrets.files "$accessDirectory\secrets.toml"
```

Open `http://localhost:8501` to match the registered callback. Missing access
configuration stops the app before section data is loaded. For shared hosting,
place this authenticated entry point behind your configured HTTPS endpoint;
keep the internal listener private and repeat acceptance with the actual URL.
The command uses Streamlit's configurable
[secrets file location](https://docs.streamlit.io/develop/api-reference/configuration/config.toml).

## Where the protection happens

[verified] In this implementation, [policy.py](policy.py) defines explicit server-owned
permissions for each role. [app.py](app.py) constructs `AccessPolicy` with the
OIDC resolver, protected SQLite store and private key. `prepare_access` runs
before protected data. The selected browser role must be in the account's live
server assignments; loading a settings profile or changing a URL cannot add it.

Hiding a navigation choice is only presentation. `read_section` checks live
authorization **before calling the section loader**, including when invoked
directly or from a stale context. `run_admin_action` checks the Admin permission
and shared freeze immediately before its callback. Keep those boundaries when
replacing synthetic loaders/actions with real backend work. A permission check
and an unrelated database write are not one atomic transaction; the host must
provide transaction or cancellation behavior for its own backend.

[verified] In the adapter implementation, the OIDC adapter checks exact issuer,
audience and subject, token expiry and issuance time on every resolution. This
example caps claim age at one hour. Live grant revocation blocks the next
protected check, including in an existing tab; it cannot erase data already
displayed or cancel work already running. Provider-side account revocation is
not polled. Add provider integration if that immediate response is required.

Streamlit logout clears the current session's identity/token cookies and
attempts provider OIDC logout when supported. Register and verify the exact
post-logout callback with the provider. Other existing dashboard sessions can
remain signed in. Server grant revocation is therefore the control used to
remove this dashboard's authority across sessions. Streamlit 1.66.1 stores
returned ID/access tokens in a separate signed browser cookie. Follow the
[authentication guide](../../role_aware_dashboard_toolkit/resources/guides/authentication.md)
for token handling and actual HTTPS/cookie acceptance before sharing the app.
See [Streamlit session behavior](https://docs.streamlit.io/develop/concepts/connections/authentication).
This example does not start or secure a separate HTTP API, and its session
counter is not a durable administrator audit log.

## Crash-test matrix

Use separately authenticated browser profiles with the real provider for the
deployment checks below. An ordinary second tab may reuse the same login.

| Attempt | Required result |
| --- | --- |
| Open without sign-in or with an unassigned account | No section data or admin action |
| Sign in as each of the four assigned accounts | Exactly the sections in the first table |
| Request another role/section through URL or stale navigation | No extra permission and no denied section loader call |
| Give an AOnly account a settings profile named Admin | No promotion |
| Invoke a denied section/action callback directly | Denied before its loader/action executes |
| Admin unfreezes and runs the sample action | Session count increments once |
| Freeze, then submit the admin action from another open session | Denied on the next check |
| Restricted account attempts freeze management | Denied |
| Downgrade an open Admin account to AOnly | Next B/C read and admin action denied |
| Revoke every role from an already-open account | Next protected check denied |
| Expire identity or present wrong issuer/audience | Denied |
| Switch accounts after an Admin action | Old account's session counter/state cleared |
| Remove access configuration or make the store unavailable | Stop/deny; no permissive fallback |
| Restore a backup | Review restored grants and freeze before allowing traffic |

Run the regression tests from the repository root:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -c "import role_aware_dashboard_toolkit as r; print(r.__file__)"
.\.venv\Scripts\python.exe -m pytest tests/test_section_access_example.py tests/test_section_access_provision.py -q
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache
```

The printed import path must resolve inside this checkout. Synthetic tests and
local browser demonstrations cover code behavior; they do not certify a real
provider, host ACLs, TLS, backups or release readiness. Follow the
[release checklist](../../docs/release_checklist.md) for a release candidate and
the [authentication guide](../../role_aware_dashboard_toolkit/resources/guides/authentication.md)
for the toolkit's full host contract.
