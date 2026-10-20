# Security lessons for dashboard hosts

The [business example](../examples/business_dashboard/README.md) exercises RADT
against anonymous submissions, private employee work and administrator actions.
These lessons belong to host design and review; they do not add a login provider,
content classifier or deployment service to the toolkit's public API.

## Recheck permission when an operation happens

A hidden button is only presentation. Resolve the current session, current role
and current freeze state at each protected read and write. Put authorization,
revision comparison, business mutation and its audit record in one transaction
when they share a store. Test an already-open session after revocation or a role
change, including an employee session whose user later becomes an administrator.
New privilege must not inherit an authentication level it never established.

## Keep incident containment available during a pause

A blanket write freeze can prevent removal of a harmful published post. Define
narrow host operations for unpublishing, revoking access and resuming work.
These still require current administrator authority and request protection.
They must not become a general edit route with a freeze exception: an unpublish
request changes only publication state, checks the revision and records an audit
entry. It cannot edit text, approve a submission or republish a draft.

RADT's normal shared-freeze behavior remains unchanged. The host deliberately
models containment separately. Test both the allowed containment action and
the surrounding ordinary writes that must stay blocked.

## Separate permission, moderation and bot protection

Public input belongs in a private pending queue. Only an authorized review
transaction can publish it. Reject extra request fields, escape untrusted text
in both the public view and the moderator's view, and keep staff records out of
public response projections. Approval and publication must commit together.

Published rules and a required acknowledgment state expectations; they do not
detect scams, discriminatory content or cleverly disguised abuse. Administrators
must judge meaning and context, and need a reliable takedown action afterward.
A CAPTCHA or bot challenge likewise does not establish that content is allowed.

CSRF/origin validation protects browser sessions against cross-site requests.
It is not a spam control: an automated client can set an Origin header. Apply
bounded inputs, submission quotas and a queue cap on the server. Perform cheap
pause/quota checks before contacting a challenge provider, then repeat them
atomically before inserting; never hold a database write lock during a network
call. Global limits protect capacity but can also let an attacker deny service
to legitimate visitors. Monitor queue saturation and provide a pause procedure.

For external challenges, require server verification of the returned token,
expected hostname and action. Fail closed on missing, malformed, expired or
failed responses. Bound the provider timeout and response size. Reject test
credentials on public hosts. A rendered widget or a mocked response is not
proof that the real provider configuration works.

Exercise the required-challenge browser path separately from a loopback demo
that disables challenges. Loading the provider script successfully does not
prove that its initialization API was used correctly. For asynchronous
Turnstile loading, use its documented `onload` callback; `turnstile.ready()`
rejects an asynchronous script. Test load failure and retry, retained form text,
expiration and late callbacks after a dialog closes. Keep submission disabled
until both rules agreement and a current verification token are present.

## Refresh public data without extending private access

A shareable board URL is public access, not an invitation or staff credential.
Automatic updates must read the same published-only projection as an ordinary
guest read; pending messages remain private until the administrator approves
them. Refresh removal and pause state as well as newly published content.

The example polls its public feed every ten seconds in visible guest or employee
board tabs. It pauses hidden/offline tabs, backs off after failures and preserves
open drafts. It does not poll authenticated administrator routes: background
reads that update session activity can otherwise defeat idle expiry. Keep one
request in flight, discard responses after navigation, and preserve escaping
when replacing the feed. Verify approval and unpublishing in two separate
browsers on the actual deployed commit; a local workflow is separate evidence.

## Charge failed attempts before expensive work

An accepted-submission quota does not limit rejected bot tokens. Keep separate
budgets for attempts and accepted records, and commit an attempt reservation
before calling a provider or checking a password. Provider errors, rejected
credentials and cancellation must not erase the charge. Raising an HTTP error
inside a database transaction can roll back a counter written in that same
transaction; returning the intended rejection after a committed reservation
avoids that hidden reset.

Apply account budgets to password changes and other reauthentication operations,
not only the sign-in form. A stolen session may expose a password-guessing route
even when ordinary login is limited. Share the budget across the account's
sessions. Reserve atomically so simultaneous requests cannot each pass a stale
limit check. A successful operation should release only its own reservation;
it must not erase other failures or reservations still in flight. Tie the release
to its original window so an old completion cannot reduce a new window's count.

The example budgets eight failed or in-flight attempts per known account per
five-minute window for login and uses a separate equivalent budget for password
changes. Wrong passwords and wrong or missing administrator codes share the login budget. Unknown usernames
do not create persistent per-name records. Login no longer treats a socket
peer's failure history as authority to lock out unrelated accounts. A targeted
attacker can still exhaust a particular account's budget; this availability
tradeoff requires monitoring and an operator response, not a claim that login
denial is impossible.

Generic 401 messages and dummy password work do not establish complete
username-enumeration resistance. Repeated probes can distinguish a known
account's 429 cooldown from an unknown username's 401 response. The example's
fictional usernames are public; account existence may be sensitive in another
host. Include this response-level tradeoff in that host's threat model instead
of claiming that bounded unknown-user storage also conceals all account names.

Public verification has its own committed sixty-second attempt budgets, separate
from accepted-post quotas. Its socket-peer budget can still group visitors behind
a proxy. Do not silently relabel the peer as a verified visitor or trust arbitrary
forwarding headers to escape a shared bucket.

## Bound blocking work without locking out unrelated routes

Timeouts alone do not prevent concurrent slow verification calls from occupying
every synchronous request worker. Reject excess work before queuing it, isolate
its worker admission from ordinary routes, and keep database write locks out of
password hashing and provider calls. The example admits at most two concurrent
authentication jobs and four submission-verification jobs per app instance.
These limits do not coordinate multiple processes or hosts.

Cancellation is part of the capacity contract. A cancelled request must not
release a slot while its synchronous callback is still running. Cancellation
before callback start must release the reservation and prevent a late callback
from doing the work. Test capacity recovery after success, exceptions and
cancellation, together with health and authenticated reads during a stalled
provider call. Do not infer isolation from a semaphore existing in the source.

Releasing a database lock around expensive work creates a new race boundary.
Recheck the current password hash, account eligibility, role and relevant MFA or
session state before committing the result. A concurrent password change,
revocation, role change or authenticator reset must invalidate stale work.
Keep MFA replay consumption, session issuance and the final permission check in
the committing transaction.

Concurrency bounds cap simultaneous expensive work, not cumulative CPU use or
the total traffic reaching a host. Sustained requests can still occupy capacity.
Separate local bounded-work evidence from claims about denial-of-service
resistance, upstream limits and fair access on the actual deployment.

## Keep abuse telemetry useful and private

Record scoped events such as an exhausted attempt budget or an operator action,
using fixed messages and bounded frequency. Do not log submitted passwords,
cookies, OTPs, challenge tokens, raw provider responses or submitted post bodies.
An attacker must not be able to turn every rejected request into unbounded log
growth. Budget events and activity records are useful diagnostics; they do not
constitute a complete security audit trail, alerting system or incident-response
process. Check host retention and operator visibility separately.

## Make stronger login affect existing sessions

Requiring an authenticator code only on a login form leaves old administrator
sessions untouched. Track the authentication generation on the server and revoke
older sessions during enrollment, reset and migration. Consume each accepted
TOTP time step transactionally to reject replay and simultaneous use. Limit
attempts for wrong codes as well as wrong passwords. Keep recovery as a trusted
operator action; do not expose a password-only MFA reset endpoint.

TOTP mitigates password theft but can still be phished. Use an organization's
identity provider and phishing-resistant authentication when that risk warrants
it. Secrets, enrollment sheets, session cookies and backups require private
storage. Screenshots, browser traces and exception messages can expose them too;
use disposable accounts and sanitized diagnostics in automated checks.

Close SQLite connections explicitly in test and operator helpers. A connection's
context manager commits or rolls back transactions but does not close the file;
use an explicit close or `contextlib.closing`. On Windows, an open connection
can prevent private temporary-data cleanup and hide the original test failure.

## Make randomized checks assert security outcomes

Random inputs alone are not a security test. Define the expected boundary before
mutating requests: anonymous input cannot gain a staff identity, employees cannot
perform administrator actions, and submissions cannot publish themselves. Check
both the response and persistent state after a denial; an error response alone
does not prove a transaction left protected records unchanged.

Include successful controls so an app that rejects every request cannot pass.
Exercise sequences as well as individual requests: sign in, rotate or revoke a
session, reuse the old cookie; submit, review and read the public projection.
Preserve the seed, case count and sanitized failure details so a failure can become
a focused regression. Keep generated credentials and authentication material out
of reports.

Use fresh disposable accounts and data, and intercept external providers at their
HTTP boundary. A required-challenge application path should still validate the
provider response rather than replacing authorization or challenge verification
with a success stub. Keep randomized tests separate from real-provider acceptance,
browser rendering, concurrent abuse and host configuration checks. More generated
cases do not establish those other boundaries or repair known defects.

## Verify persistence and the actual host separately

Apply schema upgrades transactionally and preserve existing records and identity
keys. Test failed upgrades and recovery without deleting the workspace. Before
reopening a restored backup, reconcile revocations, MFA enrollment generations
and sessions; an old backup can revive access previously removed.

Forwarded IP headers are attacker-controlled until a verified ingress replaces
them and the origin cannot be reached around that ingress. Ignoring these
headers is safe against spoofing, but can put all proxied visitors into one rate
bucket. Verify the actual proxy before changing this trust decision.
An external bot verifier's optional visitor-IP field must not be populated
with the proxy's socket address. Omit it when visitor identity is unverified;
do not weaken forwarding-header trust to make a provider request look complete.

Managed persistent disks may be absent during builds and pre-deploy commands.
If the operator needs a running instance to provision storage, provide a separate
maintenance-only listener. It must serve no application data, create no accounts
and never switch automatically into the application. Explicit provisioning and
a later start-command change keep missing storage from becoming a reseed path.
Normal startup must refuse missing or unsupported state before binding a port.

Local tests establish local behavior. Hosted CI, HTTPS cookies, DNS, bot-service
credentials, direct-origin access, private disk ownership, restart and restore
need their own evidence. Adding an example dependency also requires its runtime
audit lane; it must not silently escape checks of the toolkit's normal extras.
Record the exact source revision for every assessment. A fix checked in a
disposable local app is not a deployed fix, and an earlier live assessment does
not qualify a later source revision. Hosted acceptance must include a real human
challenge and moderation flow, bounded attempt/concurrency checks, and the
actual proxy behavior using fictional data.

## Executable references

- Business authorization and moderation: `tests/test_business_dashboard.py`
- Administrator MFA and containment: `tests/test_business_admin_mfa.py`
- Challenge and posting-policy checks: `tests/test_business_abuse.py`
- Persistent authentication budgets: `tests/test_business_auth_limits.py`
- Failed verification budgets and route progress: `tests/test_business_submission_limits.py`
- Work admission and cancellation: `tests/test_business_work_limits.py`
- Hosted startup and storage checks: `tests/test_business_hosting.py`
- [Real-browser workflow](../tools/business_dashboard_browser.py)
- [Seeded API fuzz runner](../tools/business_dashboard_fuzz.py)
- CI dependency-lane contract: `tests/test_landscaping_dependency_lane.py`

The test files are available in the repository checkout, not the source archive.

Provider references: [Cloudflare server validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
and [PyOTP security guidance](https://pyauth.github.io/pyotp/).
