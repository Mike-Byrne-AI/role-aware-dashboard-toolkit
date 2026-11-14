# Your editable web host

This generated FastAPI application uses the installed toolkit for branding and
live access policy. You own `app.py`, `host/` and `static/`; edit them directly.
The application has persistent SQLite records, assigned work, status changes,
rescheduling, shared freeze and transactional history. It starts empty and frozen.

## Run locally

Use the environment that contains `role-aware-dashboard-toolkit[api]`. From this
generated directory in PowerShell, choose a **new private directory outside the
application** for its database and identity key:

```powershell
$env:RADT_DATA_DIR = Join-Path $env:LOCALAPPDATA 'my-web-host-data'
python manage.py init --data-dir $env:RADT_DATA_DIR
python manage.py issue-token --data-dir $env:RADT_DATA_DIR --subject owner --role Manager
python -m uvicorn app:create_app --factory --host 127.0.0.1 --port 8093 --no-proxy-headers --no-access-log
```

On macOS/Linux, set `export RADT_DATA_DIR="$HOME/.local/share/my-web-host-data"`
after creating the parent directory, and pass `"$RADT_DATA_DIR"` to the same
commands. Initialization creates a new directory only; it refuses existing
storage. Inspect any partial failure and choose a new directory for a retry.

Open `http://127.0.0.1:8093`, paste the printed access token into the sign-in form,
then enable writes as the manager. Create a record assigned to an account ID.
Tokens expire after one hour by default; `--lifetime` accepts 60 to 86400 seconds.
Issue an Operator token for that ID to work only on its assigned records, or a
Viewer token for read-only access to all records:

```powershell
python manage.py issue-token --data-dir $env:RADT_DATA_DIR --subject alex --role Operator
python manage.py issue-token --data-dir $env:RADT_DATA_DIR --subject observer --role Viewer
python manage.py grant --data-dir $env:RADT_DATA_DIR --subject alex --role Viewer
python manage.py revoke --data-dir $env:RADT_DATA_DIR --subject alex
```

These commands run locally as the trusted operator. Issuing a token also assigns
the requested role to that account, affecting its existing tokens. Grant changes
apply at the next request. Revocation removes every token and grant for the
account. Keep tokens out of URLs, source files, screenshots and logs. The browser
keeps its token only in memory, so reload requires sign-in again. There are no
default accounts or passwords, and no public enrollment endpoint.

Stop with Ctrl+C. Restart the same command with the same data directory to retain
records, history, grants, freeze and unexpired tokens. Never reinitialize existing
data. Startup refuses missing files, changed identity keys and unknown schemas.
Key rotation and future migrations require an explicit host-owned procedure.

## Edit the application

| File | Responsibility |
| --- | --- |
| `static/index.html`, `static/app.css`, `static/app.js` | Editable branded interface and request handling |
| `static/theme.css`, `static/web-config.js` | Generated colors, brand and headline |
| `web-presentation.json` | Validated branding configuration used during generation |
| `app.py` | HTTP routes, strict request models, host/origin policy and asset allowlist |
| `host/auth.py` | Local token verification, live roles and record-scope checks |
| `host/service.py` | Record rules, transaction boundary and history |
| `host/actions.py` | Copied revision-checked action recipe |
| `host/storage.py` | Explicit initialization, schema and identity-key binding |
| `manage.py` | Trusted local provisioning and revocation |

The default role policy grants Managers creation, all record changes, freeze and
history. Operators see and edit their assigned records. Viewers see all records
and cannot write. Roles come from the database, never request fields. Edit this
policy deliberately for your application. Use pseudonymous account IDs; the
owner field is visible to users who can read a record. History uses opaque actor
IDs derived with the private identity key.

Record changes take `expected_revision`. A stale or repeated submission returns
409; it does not silently overwrite another change. Cancellation requires a
reason, and a completed/cancelled record must be reopened before another status
change or reschedule. An authorized no-op at the current revision returns
`changed: false` without another history event. Authentication, current grants,
freeze, record changes and history share one SQLite write transaction. This
coordinates cooperating processes on one host; it does not cover external jobs,
emails, a remote identity provider or a distributed database.

## Hosting and verification boundary

The local token adapter is a runnable starting point, not an identity provider.
Before shared hosting, replace or assess it against the application's real
authentication, MFA, account lifecycle and recovery needs. Keep the verification
adapter and its trusted identity claims on the server.

`RADT_PUBLIC_ORIGIN` defaults to `http://127.0.0.1:8093`. Set it to the exact
origin (scheme, hostname and optional port, **no trailing slash**) when changing
ports or hosting. Only loopback origins accept HTTP; other hosts require HTTPS.
Host, scheme and browser Origin mismatches are refused. Configure TLS/proxy
forwarding explicitly for the actual host; trust only the intended proxy's
forwarded headers. Do not accept arbitrary forwarded headers to bypass this
check. This starter supplies no CORS opt-in and no cookie authentication.

Protect the external data directory and its backups. New POSIX directories/files
use 0700/0600 and ordinary mode bits are checked; extended ACLs are not audited.
On Windows, restrict the directory ACL to the service/operator account before
initializing. The code does not establish or verify equivalent Windows privacy.
Do not place data on a network filesystem or under an HTTP static directory.

Validate your modified app from its installed toolkit artifact: authorized
changes, read-only/scoped denials, grant revocation and freeze after loading a
form, stale/repeated submissions, rollback if history fails, restart persistence,
desktop/mobile and keyboard interaction. Retain failed checks separately. Local
checks do not establish public TLS, provider sign-in, Windows ACLs, operational
rate limits, off-host backup custody or restore readiness. Those need acceptance
on the actual deployment before use with private or consequential records.
