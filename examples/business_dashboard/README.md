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
ticket, a screenshot or an online QR generator. Follow the
[recovery-sheet guide](RECOVERY.md) to create and verify an encrypted copy.
Keep its passphrase separately; remove the host's setup sheet only after
successful enrollment and recovery verification.
Employees leave the authenticator field empty. Each administrator code can be
used only once; wait for the next code if signing in again immediately.

The default storage directory on Windows is `%LOCALAPPDATA%/radt-business-demo`.
Fresh provisioning also creates an independent encryption key at
`%LOCALAPPDATA%/radt-business-demo.secrets/mfa.key`. Preserve that key separately
from database backups; it is required to decrypt administrator MFA enrollment.
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

## Try passkeys locally

Start your existing workspace with the `localhost` hostname for browser passkeys:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --hostname localhost
```

Open **http://localhost:8091**, sign in, and choose **Manage your passkeys** from your
profile. On Linux or macOS, use `.venv/bin/python` with the same arguments.
Keep any existing `--data-dir`, `--mfa-key-file` and `--port` arguments. The
listener still binds only to `127.0.0.1`; the launcher accepts only `localhost`
or `127.0.0.1` as its canonical hostname. The default remains `127.0.0.1`.

Use the selected hostname consistently. A passkey registered for `localhost`
does not work on `127.0.0.1` or your deployed hostname. Local browser checks use
a virtual authenticator; they do not prove physical-device or hosted behavior.

## Explore the workflows

| Account | Available work |
| --- | --- |
| Guest | Read published notices and submit a post for administrator approval without an account |
| Employee | View the team schedule and assignments; read and post staff messages; change own password |
| Admin | Create, edit and archive schedule entries; manage assignments, public notices and outreach contacts; approve or reject guest submissions; review sample financials and audit activity; pause business writes and disable employee access |

The administrator **Overview** includes quick actions for common workspace tasks.
Choose **Explore recent activity** to search the latest 50 returned entries in
the **Recent workspace activity** dialog. This bounded feed is an operational
view, not a complete audit-history search or export.

Open **Security & recovery** for current-session information, password changes,
workspace editing controls, and a guide to the local recovery-file tool. The
page rechecks the signed-in session when opened. Recovery commands run in your
private terminal: the dashboard does not accept recovery files or passphrases,
launch the tool, or report that a backup exists or has been verified. Follow
[the complete recovery procedure](RECOVERY.md) before removing any original.

The public board and employee message board are separate stores and endpoints.
Draft notices, staff messages, employee schedules, contacts and administration
data require the appropriate signed-in role. A guest visit never grants a staff
identity. Use separate browser profiles to compare these views.

Share **`/board`** on your deployed hostname, for example
`https://business.example.com/board`, to open the public board directly. The
**Share board** button provides that link. This is a public page, not an
invitation-only space: anyone can read approved posts and submit for review.
Saved guest messages remain private pending administrator approval.

Visible guest and employee public-board tabs normally refresh published posts
every ten seconds, using only the public feed. Hidden or offline tabs pause
refreshing; failures retain the last loaded posts, show a status message and
retry with backoff. Feed updates preserve an open submission draft and its
verification widget. Administrators use **Refresh board** to update the review
queue; no background authenticated polling renews their idle sessions. This
uses the existing service and database, with no new schema or service to set up.

Guests use **Submit a post** on the public board and accept the displayed posting
rules; no name, email or password is collected. On public HTTPS hosts they must
also complete Cloudflare Turnstile verification. Submissions remain in the private admin
review queue until approved. Approval publishes a Community post; rejection
keeps it off the public board. Guests cannot read pending submissions or check
review status. Review the content against the displayed rules before approving
it. The rules and bot challenge do not automatically detect disallowed content.
An administrator can unpublish an approved post, including while work is paused.

Submission limits allow three accepted posts per socket peer per ten minutes,
thirty in total per hour, and at most one hundred pending posts. Separate attempt
budgets allow ten verification attempts per socket peer and thirty globally in
each sixty-second window. The server commits the attempt before contacting the
provider, so rejected tokens and provider failures still consume this budget.
At most four submission jobs run concurrently; excess work receives 429 with a
one-second retry interval. Successful verification still requires a final pause
and accepted-submission quota check before inserting a pending post.

The server stores keyed peer hashes, not raw addresses, and does not trust
forwarded-address headers. Behind a proxy, several visitors can share the same
socket peer and therefore the same public-submission limits. These demo controls
do not establish visitor identity or denial-of-service resistance. Review actual
ingress behavior before changing the policy. Pausing workspace changes also
pauses submissions, approvals and ordinary edits. Published posts remain readable
until unpublished. Unpublishing and disabling employee access remain available
as narrow containment operations with current administrator authorization.

Known accounts have a persistent login budget of eight failed or in-flight
attempts per five-minute window, shared by wrong passwords and wrong or missing
administrator codes. Password changes have a separate equivalent account budget
shared across that account's sessions. Each operation reserves its attempt before
password hashing; a success removes only its own reservation, leaving prior failures charged until
the window expires. Unknown usernames do not create persistent limiter rows, and
failed logins from a shared socket peer do not impose a cooldown on another
account. Known-account login and password changes share two authentication slots.
Unknown usernames have one separate dummy-hash slot, with two bounded lookup
slots before classification. Excess work receives a nonwaiting 429. Identity
reverification has one separate slot. These pools protect specific work stages;
sustained traffic can still occupy lookup or known-account capacity.

Generic invalid-credential responses do not provide full username-enumeration
resistance: repeated probes can distinguish a known account's 429 cooldown from
an unknown username's 401 response. The fictional usernames in this example are
public. Review this tradeoff before adapting it to a service where account
existence must remain private.

Password hashing and external verification run outside database write
transactions. The server rechecks current credentials, account state and relevant
MFA/session state before committing authentication changes. Concurrency limits
apply per application instance, not across hosts or processes. Targeted failures
can still temporarily lock out an account; ongoing traffic can still consume
available capacity. These bounds do not guarantee availability under sustained
load.

New passwords require 15 to 128 characters and pass an offline common-password
check. The bundled Django list and its narrow repeated-word extension reject
known common choices such as `passwordpassword`. Existing passwords still work
at sign-in. No password or password hash is sent to a screening service. This
is a pinned common-password snapshot, not a comprehensive or current breach
lookup; see its [source and update procedure](business/password_data/SOURCE.txt).
Use a password manager or a unique phrase of unrelated words. Correctable
policy rejections keep the current session and do not charge a failed guess
when the current password was correct.

Schema four added private receipts for safe create retries. Schema five adds
independently keyed MFA encryption and session verification state. Version-three
upgrades preserve accounts, passwords, sessions, MFA, quotas and business records.
Version-one and version-two upgrades also revoke old administrator sessions
because those sessions did not establish MFA. All upgrade steps share one
transaction; unexpected schema objects cause refusal rather than repair.
Keep an application-consistent backup and the matching identity key, stop
writes, and rehearse on a protected copy before upgrading existing hosted data:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --data-dir 'C:\Private\Westbridge' --migrate-storage
```

Replace the example path with the existing private directory. This command
validates and upgrades existing storage, prints no credentials, and opens no
listener. Create the independent MFA encryption key first with
`--create-mfa-key`; use the same data and key paths for migration. Local startup
and hosted preflight require schema five and never migrate automatically.
Do not reprovision.
Existing account login budgets retain their original namespace.
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

Form fields are temporarily disabled while a save is in progress. You can close
an editor, but closing it does not cancel the submitted save; refresh the page
to see its result. A delayed business-record save cannot close a newer editor or
replace a page you have since opened. Validation errors restore the current form
for correction.

For new staff messages, schedule entries, contacts and administrator notices,
an unchanged retry in the same browser tab reuses a random save key. The key
survives a refresh; refill the same details because drafts themselves are not
stored. The browser stores only keys, timestamps and request fingerprints in
session storage. Successful acknowledged saves clear their key so a deliberate
later creation can use identical details. No create is retried automatically.
Changed details start a separate save. Closing the tab, clearing its storage or
switching browsers ends this protection: check saved records before resubmitting.
After 23 hours an unconfirmed browser save requires an explicit check-and-start-
separate-save action rather than silently replacing its key.

The server keeps successful receipts for a 24-hour replay window, scoped to the
account and route, in the same transaction as the write and audit. Current
permissions, session, CSRF and workspace pause are checked before replay. Reusing
a key for different details returns 409. Receipts contain the original response,
which may differ from a record edited later. They are limited to 512 per account
and 4,096 in total, with a 32 KiB response ceiling; new keyed writes return 503
when full rather than evicting an unexpired receipt. Expired bytes are pruned on
the next successful keyed transaction, not erased by a background timer.
API clients may send `Idempotency-Key` (16-128 ASCII letters, digits, `_` or `-`);
use a cryptographically random value and retain it for the unchanged operation.
Clients omitting the header retain ordinary create behavior. This contract
does not cover public guest submissions, password changes, or later edits;
check saved records before retrying those uncertain operations.

Team messages have durable per-account fixed-window limits of 10 accepted posts
per minute and 100 per hour, including administrators. Rejections return 429
with a retry interval and preserve the draft; a replayed saved message does not
spend another quota. At 10,000 stored messages, new posts return 507 and require
operator review. Existing history is not automatically deleted. These defaults
bound posting and message rows, not total database size or all audit activity.

Password changes are different: a confirmed change clears the old account's
session and password fields even if its editor was dismissed. If the connection
or reply fails, the dashboard cannot know whether the change committed. It
returns to sign-in with instructions to try the new password first, then the
previous password if necessary; it never automatically resubmits the change.
This uncertain outcome does not claim that the server session was revoked.
Delayed replies cannot clear a newer login. Session revocation is enforced in
the database; a revoked cookie can remain in the browser until the next login
replaces it or it expires.

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

See the [security lab](SECURITY_LAB.md) for fresh verification, session
revocation, independent MFA key custody, recovery and abuse-control exercises.

## Verify the example

With the repository's development dependencies installed:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/test_business_dashboard.py tests/test_business_admin_mfa.py tests/test_business_abuse.py tests/test_business_hosting.py tests/test_business_auth_limits.py tests/test_business_submission_limits.py tests/test_business_work_limits.py tests/test_business_fuzz.py
.\.venv\Scripts\python.exe -m ruff check examples/business_dashboard tests/test_business_dashboard.py tests/test_business_admin_mfa.py tests/test_business_abuse.py tests/test_business_hosting.py tests/test_business_auth_limits.py tests/test_business_submission_limits.py tests/test_business_work_limits.py tests/test_business_fuzz.py tools/business_dashboard_browser.py tools/business_dashboard_fuzz.py --no-cache
$businessEvidence = Join-Path ([System.IO.Path]::GetTempPath()) ("radt-business-browser-" + [guid]::NewGuid())
.\.venv\Scripts\python.exe tools/business_dashboard_browser.py --browser-channel chrome --output-dir $businessEvidence
```

The browser runner requires Playwright and an installed Chrome. Without
`--browser-channel`, it uses Playwright's installed Chromium. It owns disposable
fictional accounts, data and a loopback server; it does not open your saved demo
workspace. Its output includes screenshots and a secret-free result summary.
The API regressions use isolated storage and exercise permission denials, CSRF,
session invalidation, freeze, stale edits, overlaps and persistence.
The browser runner also checks delayed saves, dismissal and newer-draft protection,
validation recovery, and navigation during a pending save. Use `--save-only` with
the same browser command to run just these checks against intercepted fictional
API responses and the current static assets.
Use `--admin-tools-only` to focus on recovery guidance, command copying,
activity search, responsive admin controls, and session/navigation races with
fictional API responses. The full run also checks the recovery page against the
local server after an administrator signs in with MFA.
Use `--safe-saves-only` for real local lost-reply retries, browser refresh,
expired or unavailable retry storage, message limits and password-choice errors.
API regressions in `test_business_idempotency.py`,
`test_business_storage_upgrade.py`, `test_business_message_limits.py` and
`test_business_password_policy.py` exercise replay authorization, rollback,
concurrent writes, migration failure and offline password screening.
Use `--password-faults-only` for real local-server password changes with dropped
requests, lost or malformed replies, dialog dismissal, multiple tabs and newer
sign-ins. These checks inspect server state as well as the browser result.
The API tests also cover guest moderation, submission limits and preserving an existing
store during the schema upgrade, authenticator replay/reset, mandatory policy
acceptance and provider failures. Attempt-budget regressions cover persistent
account limits, failure charges, shared-peer login behavior, concurrent admission,
state changes during password work, and cancellation. Provider regressions
exercise committed failed-attempt accounting and progress of unrelated routes
during stalled verification. The browser runner submits two guest posts,
approves one, rejects the other and checks what guests can actually see. It also
signs in with an administrator code and unpublishes a post while paused.
Resize checks keep the guest board and populated dialogs open across desktop,
tablet, phone and short windows. They verify usable card widths, accessible
dialog actions, preserved drafts and contained scrolling on the outreach table.
The mobile-menu check also widens an open menu to desktop size and verifies
that the main content becomes interactive again.
An isolated provider-script fixture also exercises the required-verification
browser path, including asynchronous loading, retry and token expiration.
Provider tests use synthetic responses; they do not establish live Cloudflare
or Render configuration. Reusable findings are in
[host security lessons](../../docs/security_lessons.md).
After deployment, use separate guest and administrator browsers to confirm that
real submissions remain private, approved posts appear automatically, and
unpublished posts disappear from the open guest board. Follow the
[actual-host acceptance checks](HOSTING.md#accept-the-actual-hosted-service).

For repeatable randomized API checks, run:

```powershell
.\.venv\Scripts\python.exe -B tools/business_dashboard_fuzz.py --seed 20261019 --cases 500
```

The runner creates fresh fictional accounts and storage in a temporary directory,
uses an in-process HTTPS test client, and mocks the challenge provider without
network requests or real keys. It accepts neither a target URL nor an existing
data directory. A result report is written outside the checkout; pass
`--output-dir` with an empty external directory to choose its location. Reuse the
seed and case count with the same source to reproduce a run, or change the seed
to explore other input combinations. Reports include a source fingerprint to
distinguish code revisions. The defaults are shown above; `--cases` accepts 9
through 10,000.

Checks combine mutated inputs with expected HTTP statuses and stored-state
invariants: a denied request must not grant access or publish a post. Positive
controls exercise legitimate actions, while sequences check authenticator replay,
session invalidation and moderation. This is seeded randomized testing, not
coverage-guided fuzzing or automatic failure minimization. It does not establish
live Render configuration, browser text escaping, provider behavior, or resistance
to overload. Passing these checks does not resolve separately tracked abuse-control
findings.

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
