# Westbridge business dashboard

A reusable fictional business workspace with a public notice board, password
sign-in for one administrator and five employees, administrator authenticator
codes, a shared staff schedule and
message board, and private administration and outreach pages.

The application uses the toolkit's `AccessPolicy`, live grants, role definitions,
and shared freeze state at the server operation boundary. The FastAPI host owns
password verification, sessions, SQLite transactions and business records. It is
a source example, included in the source distribution but not the toolkit wheel.

## Start on Windows

From the repository root, use the existing development environment. If it does
not exist, create it with `python -m venv .venv` first.

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m pip install -e ".[api]" -r examples/business_dashboard/requirements.txt
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --provision
.\.venv\Scripts\python.exe examples/business_dashboard/run.py
```

Open **http://127.0.0.1:8091**. Provisioning prints the location of a private
`ACCOUNTS.md` file, never passwords. Read that file locally to sign in as `admin`
or one of `alex`, `blair`, `casey`, `drew` and `ellis`. Each account receives a
different randomly generated password. Guest access needs no account.

Administrators also need a six-digit code from an authenticator app. Open the
private `ADMIN_MFA_SETUP.md` file created beside `ACCOUNTS.md` and add its manual
setup key to your authenticator. Never paste the key or setup URI into chat, a
ticket, a screenshot or an online QR generator. Keep a protected offline recovery
copy and remove the setup sheet from the host when enrollment is complete.
Employees leave the authenticator field empty. Each administrator code can be
used only once; wait for the next code if signing in again immediately.

The default storage directory on Windows is `%LOCALAPPDATA%/radt-business-demo`.
Keep that directory private to your Windows account using its directory ACL;
POSIX file modes do not establish Windows access protection. This Windows entry
point is for a loopback demonstration, not public Windows hosting.

Stop with **Ctrl+C**. Start again with the last command to keep accounts,
passwords and saved work. Provisioning is an explicit one-time operation and
refuses existing data. Do not delete a failed workspace to force startup.

## Start on Linux or macOS

From the repository root, using Python 3.10 or later:

```bash
export PYTHONDONTWRITEBYTECODE=1
python3 -m venv .venv  # only if this environment does not exist
.venv/bin/python -m pip install -e ".[api]" -r examples/business_dashboard/requirements.txt
.venv/bin/python examples/business_dashboard/run.py --provision
.venv/bin/python examples/business_dashboard/run.py
```

The default private directory is `~/.local/share/radt-business-demo`.
Provisioning creates owner-only directories and files. The complete database,
original identity key and account sheet belong outside the entire source tree.
Use `--data-dir` for an alternate private directory and `--port` for a different
loopback port. Preserve the full `examples/business_dashboard` layout.

## Explore the workflows

| Account | Available work |
| --- | --- |
| Guest | Read published notices and submit a post for administrator approval without an account |
| Employee | View the team schedule and assignments; read and post staff messages; change own password |
| Admin | Create, edit and archive schedule entries; manage assignments, public notices and outreach contacts; approve or reject guest submissions; review sample financials and audit activity; pause business writes and disable employee access |

The public board and employee message board are separate stores and endpoints.
Draft notices, staff messages, employee schedules, contacts and administration
data require the appropriate signed-in role. A guest visit never grants a staff
identity. Use separate browser profiles to compare these views.

Guests use **Submit a post** on the public board and accept the displayed posting
rules; no name, email or password is collected. On public HTTPS hosts they must
also complete Cloudflare Turnstile verification. Submissions remain in the private admin
review queue until approved. Approval publishes a Community post; rejection
keeps it off the public board. Guests cannot read pending submissions or check
review status. Review the content against the displayed rules before approving
it. The rules and bot challenge do not automatically detect disallowed content.
An administrator can unpublish an approved post, including while work is paused.

Submission limits allow three accepted posts per network address per ten minutes,
thirty in total per hour, and at most one hundred pending posts. The server stores
keyed address hashes, not raw addresses, and does not trust forwarded-address
headers. These are basic demo limits; a public deployment behind a proxy must
review trusted-proxy handling and abuse controls. Pausing workspace changes also
pauses submissions, approvals and ordinary edits. Published posts remain readable
until unpublished. Unpublishing and disabling employee access remain available
as narrow containment operations with current administrator authorization.

Existing version-one and version-two stores upgrade transactionally to schema
three. Accounts, passwords, employee sessions and business records are preserved.
Old administrator sessions are revoked because they did not establish MFA.
Enroll missing administrator authenticators once, using the same private store:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --setup-admin-mfa
```

Use `--data-dir` if the workspace is not at the default location. Keep the database
together with its original identity key; do not reprovision it for this update.
If an authenticator is lost, a trusted local operator can use
`--reset-admin-mfa` to replace administrator enrollment and revoke their sessions.
This explicit command preserves prior setup sheets and prints the location of a
new private sheet. Use it only after a successful command; a failed transaction
may leave an unused sheet. There is no password-only web reset route.

Schedule changes check revisions and reject overlapping employee assignments.
Dates are stored as UTC instants; the interface identifies the display time zone.
Pausing writes preserves reads, and the administrator can resume writes.
Disabling an employee invalidates their sessions. Password changes also sign out
existing sessions. The account sheet records initial passwords, not later changes.

All initial records are fictional. The financial series is seeded sample data;
pipeline values and scheduled hours reflect the saved demo records. Outreach
tracks contacts, stages and notes locally. It sends no email, SMS, invoices or
payments and has no external service connection.

## Adapt the boilerplate

Change the sample company and initial records in `business/seed.py`, visual
tokens in `business/static/styles.css`, and product wording in
`business/static/app.js`. Change role definitions and server permission checks
together when adding a capability. Public posts must retain an explicit public
projection rather than returning private records and hiding fields in JavaScript.

Keep authentication, storage and request validation in their dedicated modules.
Authorization and each protected record mutation share a SQLite transaction so
fresh grants, shared freeze, revisions, saved work and audit stay consistent.
These host modules demonstrate toolkit integration; they are not new stable
library APIs or a replacement for an organization's identity system.

## Verify the example

With the repository's development dependencies installed:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/test_business_dashboard.py tests/test_business_admin_mfa.py tests/test_business_abuse.py tests/test_business_hosting.py
.\.venv\Scripts\python.exe -m ruff check examples/business_dashboard tests/test_business_dashboard.py tests/test_business_admin_mfa.py tests/test_business_abuse.py tests/test_business_hosting.py tools/business_dashboard_browser.py --no-cache
$businessEvidence = Join-Path ([System.IO.Path]::GetTempPath()) ("radt-business-browser-" + [guid]::NewGuid())
.\.venv\Scripts\python.exe tools/business_dashboard_browser.py --browser-channel chrome --output-dir $businessEvidence
```

The browser runner requires Playwright and an installed Chrome. Without
`--browser-channel`, it uses Playwright's installed Chromium. It owns disposable
fictional accounts, data and a loopback server; it does not open your saved demo
workspace. Its output includes screenshots and a secret-free result summary.
The API regressions use isolated storage and exercise permission denials, CSRF,
session invalidation, freeze, stale edits, overlaps and persistence.
They also cover guest moderation, submission limits and preserving an existing
store during the schema upgrade, authenticator replay/reset, mandatory policy
acceptance and provider failures. The browser runner submits two guest posts,
approves one, rejects the other and checks what guests can actually see. It also
signs in with an administrator code and unpublishes a post while paused.
Provider tests use synthetic responses; they do not establish live Cloudflare
or Render configuration. Reusable findings are in
[host security lessons](../../docs/security_lessons.md).

## Hosting boundary

This delivery is a local source example. Public hosting still needs a reviewed
Linux/POSIX service, private persistent disk, HTTPS ingress, backup/restore and
account handoff. The proposed hostname is `example-dashboard.mikebyrne.ai`;
the example does not create DNS records or a hosting service.

Follow [business hosting](HOSTING.md) for the POSIX adapter, Render maintenance
bootstrap, explicit provisioning and normal service commands. The adapter
refuses missing or outdated state before normal startup. The landscaping
launcher and acceptance checker are specific to that app. Use fictional records
for client demonstrations until actual-host acceptance is complete.
