# Westbridge business dashboard

A reusable fictional business workspace with a public notice board, account
enrollment and password-plus-authenticator or passkey sign-in for one
administrator and five employees, a shared staff schedule and
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
`ACCOUNTS.md` file, never its secrets. Read that file locally for `admin` or one
of `alex`, `blair`, `casey`, `drew` and `ellis`. Each account has a different
single-use enrollment code that expires after 24 hours. It cannot sign in or
access staff data. Fresh storage starts in strict authentication mode with all
accounts pending. Guest access needs no account.

Open account setup from the sign-in dialog and enter the username and enrollment
code. Starting setup consumes that code and gives you at most ten minutes to
choose a new password and prove the current six-digit code from a newly configured
authenticator. Both administrators and employees complete this step. Keep the
displayed authenticator setup key private; never paste it or its setup URI into
chat, a ticket, a screenshot or an online QR generator. Use your authenticator's
protected backup process or the [private-file recovery guide](RECOVERY.md) when
appropriate. An encrypted expired enrollment code cannot restore access.

Completion signs out existing sessions and returns you to sign-in; it does not
log you in automatically. Sign in with the chosen password and a **new**
authenticator code: setup already consumed the current time step. Only the
current 30-second code is accepted, once. After signing in, you can register a
user-verified passkey as an alternative. Password fallback still requires TOTP.
Closing or reloading setup after it starts, losing the start response, or letting it
expire requires an explicit offline reissue. See [enrollment and recovery](#enrollment-migration-and-recovery).
If the final completion response is lost, try sign-in with the chosen password
and a new authenticator code to check whether it committed; do not replay setup
automatically or assume the old credentials still work.

The default storage directory on Windows is `%LOCALAPPDATA%/radt-business-demo`.
Fresh provisioning also creates an independent encryption key at
`%LOCALAPPDATA%/radt-business-demo.secrets/mfa.key`. Preserve that key separately
from database backups; it decrypts account MFA and pending enrollment secrets.
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

## Browser sign-in window and HTTP protocol

Each browser sign-in flow has a fixed eight-hour window. Repeated sign-ins in
that flow share its deadline; signing in near the end gives a shorter session.
The interface displays that deadline. Thirty minutes of inactivity can end the
session earlier. Reverification never extends the absolute deadline. After the
window ends, a deliberate new sign-in establishes a new window.

Nonbrowser clients must follow the same protocol as the interface:

1. Retain cookies and read `GET /api/session`. If it returns a current session,
   use its `csrf` as `X-CSRF-Token` on the next request.
2. Send `POST /api/login/context` with exactly `{}` and the configured `Origin`.
   Retain its HttpOnly flow cookie. Its response contains `csrf` (a short-lived
   login context), `expires_at` (the context deadline), and `flow_expires_at`
   (the fixed browser deadline). A current session requires its ordinary CSRF;
   a stale authenticated claim is rejected without anonymous fallback.
3. Supply that context as `X-Login-CSRF` on `POST /api/login`, or on both
   `/api/passkeys/login/options` and `/api/passkeys/login/verify`. The password
   body is unchanged. Passkey options echo the context in `csrf`; the old
   passkey pre-auth cookie and `X-Passkey-CSRF` are no longer accepted.
4. After success, read `/api/session` using the installed cookie and compare
   `session_id`, `csrf`, and user ID before displaying the result. A 409 requires
   a deliberate new attempt; never automatically replay credentials or a save.

The first successful commit wins each captured context generation. A later
deliberately fetched generation can replace the current session. Delayed earlier
cookies then fail at protected endpoints, although they can leave the browser
needing to sign in again. Only requests sharing a valid flow are correlated:
cleared cookies and genuinely independent first requests can form separate
sessions. Web Locks coordinate cooperating tabs; they are not authorization.
The flow cookie alone cannot authenticate, but its theft plus valid credentials
can replace the flow's current session. Protect the complete cookie jar.

Existing migrated sessions can continue ordinary use. Before password or
passkey reverification, bootstrap a context with the live session's ordinary
CSRF to bind it to a flow. Logout remains available without this bootstrap.

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
authenticator codes when required. Password changes have a separate equivalent account budget
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

## Enrollment migration and recovery

Schema four added private receipts for safe create retries. Schema five added
independently keyed MFA encryption and session verification state. Schema six
added structured security events and a durable local delivery outbox. Schema
seven added session-rotation revocation lineage. Schema eight adds explicit
account lifecycle and authentication policy, expiring enrollment grants, pending
setup sessions and durable operator decision references. Existing MFA rows move
from `admin_mfa` to `account_mfa` without changing their encryption context.
Schema nine adds immutable source event bytes, destination-specific delivery
obligations and a durable heartbeat counter. It preserves local delivery as
`local-v1`; remote delivery needs separate explicit activation. See the
[local collector and alert reference](../security_event_collector/README.md).
Schema ten adds purpose-bound browser flows, a persisted signing epoch, a
durable clock rejection floor, and one current session binding per flow. It
discards pending passkey challenges while preserving existing sessions. Stop
all old writers before migration; versions nine and ten must not write the same
storage. Clock rollback below a committed observation refuses authentication;
there is no automatic floor reset. Restore rotates the epoch, clears transient
authority and preserves the current authority's clock floor.
Upgrades from version three onward preserve existing accounts, passwords,
sessions, MFA, quotas and business records.
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
listener. For pre-five storage without an encryption key, explicitly create the
independent MFA key first with `--create-mfa-key`. For an existing schema-five
workspace, preserve its original MFA key. Use the same data and key paths for
migration. Local startup and hosted preflight require schema ten and never
migrate automatically.
Do not reprovision.
Existing account login budgets retain their original namespace. Only upgrades
from versions before eight mark existing accounts `legacy` and select
`transition` mode; they do not silently enroll accounts or end their access.
Upgrades from eight or nine preserve the current policy and account lifecycle,
including completed strict activation.
Legacy employees temporarily retain password-only access in transition mode;
legacy administrators retain their existing MFA/passkey requirements. This is
unfinished migration, not the final policy. Inspect the remaining work and issue
an account-specific migration grant, using the same data and key paths:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --data-dir 'C:\Private\Westbridge' --auth-readiness
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --data-dir 'C:\Private\Westbridge' --issue-enrollment alex --purpose migration
```

Deliver each private grant through a trusted channel. Issuing a migration grant
preserves legacy access until completion; completing it installs the chosen
password and confirmed authenticator, marks the account active and revokes its
old sessions. Complete each active account, verify a working administrator, then
explicitly close transition:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --data-dir 'C:\Private\Westbridge' --activate-auth-policy
```

Activation refuses unresolved accounts or accounts without a confirmed TOTP
factor or passkey, and requires an enrolled active administrator. Successful
activation revokes existing sessions. The read-only readiness report checks
stored enrollment/factor state; it does not prove a real device works.

For an uncompleted initial account whose code expired, use
`--issue-enrollment alex --purpose initial`. For lost credentials, a trusted offline operator first
verifies the person's identity outside the app and records that decision in the
operator's case system. Then issue account-specific recovery:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/run.py --data-dir 'C:\Private\Westbridge' --issue-enrollment alex --purpose recovery --case-ref CASE-2026-001
```

The opaque case reference is required, limited to 1-80 ASCII letters, digits,
periods, underscores, colons or hyphens, and durably recorded with issuance.
It is a reference to external proofing, **not proof of identity**. Do not put
identity documents or personal evidence in it. Possession of the grant permits
replacement of the account's credentials; proving a new TOTP code alone cannot
prove who the recipient is. Recovery immediately makes the account pending and
revokes its password, MFA, passkeys, sessions and challenges. It cannot enable
a disabled account. Reissue invalidates earlier grants and pending setup.

The compatibility command `--setup-admin-mfa` issues migration grants only for
legacy administrators missing a factor. `--reset-admin-mfa --case-ref CASE-...`
issues recovery for **all active administrators**, removing their current access;
prefer account-specific recovery and preserve a separately working administrator.
There is no password-only web reset. Commands preserve previous sheets and print
only the new private path. Use a sheet only after its command succeeds; a failed
transaction may leave an unused file. Initial, migration and recovery grants
all expire after 24 hours and start one setup attempt.

Schedule changes check revisions and reject overlapping employee assignments.
Dates are stored as UTC instants; the interface identifies the display time zone.
Pausing writes preserves reads, and the administrator can resume writes.
Disabling an employee invalidates their sessions. Password changes also sign out
existing sessions. The original account sheet contains temporary enrollment
codes, not permanent passwords or a usable long-term recovery credential.

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
For the enrollment lifecycle, use the focused checks and separate local browser
runner:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_business_enrollment_policy.py tests/test_business_enrollment_http.py tests/test_business_lifecycle_operator.py tests/test_business_lifecycle_custody.py
$enrollmentEvidence = Join-Path ([System.IO.Path]::GetTempPath()) ("radt-enrollment-browser-" + [guid]::NewGuid())
.\.venv\Scripts\python.exe tools/business_enrollment_browser.py --browser-channel chrome --output-dir $enrollmentEvidence
```

The [enrollment runner](../../tools/business_enrollment_browser.py) uses actual
local HTTP and browser forms with fictional accounts and programmatically
generated TOTP codes. Review its receipt and retained failures; the command is
not a passing result. It does not establish physical-authenticator possession,
external identity proofing, secure grant delivery or deployed acceptance.

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
