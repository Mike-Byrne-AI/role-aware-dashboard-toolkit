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
password hashing and provider calls. The example reserves two expensive slots
for known-account login and password changes and one separate dummy-hash slot
for unknown usernames. Two short lookup slots classify requests first.
Password reverification has one separate slot, and submission verification four.
This protects known-account hashing from unknown-user work, while lookup
saturation and targeted account attacks remain possible.
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

## Verify recovery files before retiring originals

An encrypted file is not yet proof of recovery. Authenticate its complete
decryption and compare the recovered bytes with the unchanged original before
accepting a backup. Save the passphrase separately and verify the retained copy
before manually removing plaintext. Create outputs exclusively so an existing
file cannot be overwritten. Keep both plaintext and encrypted recovery artifacts
outside source control. Restoring an enrollment sheet does not reset MFA or
restore an application's database; keep recovery copies separate from the
runtime database and identity-key lifecycle.

File encryption and filesystem permissions protect different boundaries. On
Windows, verify the directory ACL separately; POSIX mode bits do not establish
a private Windows ACL. Use a trusted encryption executable and private terminal
prompts rather than passphrase arguments or logs. Decrypted bytes exist in
process memory, and deleting a file does not establish secure erasure. The
[business recovery-sheet guide](../examples/business_dashboard/RECOVERY.md)
provides a bounded, optional workflow for small files without modifying live
accounts, databases or password vaults.

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

The same invalid input can be rejected by different layers across supported
Python versions. A deeply nested JSON array may fail parsing with 400 or reach
schema validation and fail with 422. Accept only those documented alternatives
for that probe, while requiring unchanged protected state and successful
legitimate requests afterward. Keep authentication and authorization expectations
exact; accepting any error response could hide a broken guard behind a rate limit.

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

## Treat lost credential-change replies as uncertain outcomes

A disconnected browser cannot distinguish an unreceived request from a committed
password change whose reply was lost. Do not automatically retry, claim rollback,
or leave password fields in a hidden editor. Give explicit reauthentication
guidance and distinguish this from a confirmed wrong-current-password error,
which remains correctable in the form. Verify the actual stored credential and
revoked sessions when testing these failures; a mocked browser error alone does
not establish which side of the commit failed.

Tie credential-change completion to the originating account and session, not the
current page or dialog. Moving to another page must not retain that old session
after confirmed revocation, and a delayed reply must not clear a newer login.
Browser response headers need the same review: an old `Set-Cookie` expiration can
erase a new login even if JavaScript correctly ignores the stale reply. Server
revocation remains authoritative; retaining a revoked, unusable token until its
replacement or expiry avoids that response-ordering hazard.

## Bound request intake separately from expensive workers

A body-size limit alone does not stop a client from keeping a partial upload
open. Enforce a total read deadline and nonwaiting reader admission, release
slots on disconnect/cancellation/errors, and let completed bodies leave the
reader pool before downstream work. Include a scheduling checkpoint when an
ASGI receiver may return already-buffered chunks without suspending, so an
empty-chunk stream cannot starve its timeout. Test valid fragmented bodies as a
positive control alongside stalled, oversized and cancelled ones.

These limits bound one stage, not total process or network resources. Tune and
verify ingress limits, account quotas, retention and monitoring separately.
Provider responses also require bounded parsing and generic failure handling;
deeply nested JSON must not become an unhandled exception or approve a request.

## Make retries authorized, atomic and bounded

A disabled submit button prevents one kind of duplicate, but cannot identify
a committed request whose response was lost. Give a create operation a random
key, scope its stored receipt to the authenticated account and fixed route,
and fingerprint its normalized payload. The record, audit, quota charge and
receipt must commit together. A retry with changed content must conflict;
receipt corruption must fail rather than create another record. Check current
session, CSRF, role and shared freeze before returning a previous result.

Bound the number and size of receipts without evicting unexpired ones to make
room. State the replay window and when expired bytes are actually pruned. The
browser must retain an uncertain attempt's key and must not silently replace
an expired key while calling that action a safe retry. Do not save business
drafts or credential material merely to remember a retry. Test committed-but-
lost responses, refreshes, overlapping attempts, newer sessions, clock changes,
capacity, storage failures and transaction rollback with actual persisted data.

Use separate durable per-account posting quotas, checked only after resolving
a saved retry, and charge them with the accepted write. A storage ceiling should
not become silent data deletion: reject new writes clearly and leave archive
decisions to an explicit operator process. Bounds on one table do not establish
a bound on total disk, backups or audit history.

## Screen new password choices without adding disclosure

Apply a new-password policy after verifying the current credential, while
preserving existing sign-in compatibility. Give useful correction guidance,
preserve exact password characters for hashing, and never include rejected
values in errors or logs. A local common-password corpus avoids a new external
request containing password-derived data, but its provenance, license, checksum
and update process must ship with it. A pinned list is not a current breach
lookup, and a passing choice is not proof of strength. Keep screening work
bounded and recheck authority before committing the credential change.

## Separate read readiness from write capacity

A public read should not reserve a write lock merely to obtain a consistent
view. Use a read-only snapshot for public feed and health checks, and verify
that they complete while a writer holds a reservation. Keep authorization and
mutation together in the protected write transaction. Read readiness does not
prove that a write can commit immediately or that an exclusive lock is harmless.

## Limit the authority of old sessions

Require recent verification for sensitive actions, with a bounded server-side
expiry that ordinary reads cannot renew. Preserve immediate containment actions
such as pausing edits or disabling compromised accounts. Session inventories
must expose opaque display identifiers, never bearer tokens or their hashes,
and enforce ownership for every revocation. Recheck authority after expensive
verification so a concurrent revocation cannot revive a session.

Preserve the user's draft when verification is required, clear credential fields
promptly, and require deliberate resubmission after verification. Tie delayed
responses to the originating session so they cannot clear a newer sign-in.

## Separate MFA ciphertext from its key

Authenticated encryption needs a separate key, fresh nonces and context binding
to prevent copied ciphertext from becoming another account's enrollment. Fail
closed on missing or wrong keys, including empty-enrollment databases. Test
explicit migration and rollback. Database-only encryption cannot protect against
a host that can read both inputs, and a migration cannot erase historical
plaintext pages, backups or enrollment sheets.

## Restore records without restoring revoked authority

Use SQLite's backup API rather than copying only its main file while WAL writes
may exist. Encrypt the resulting bundle and keep its decryption material under
separate custody. Restore to a new directory with all sessions revoked and
editing paused. Without a current, identity-matched security source, quarantine
the restore instead of reactivating historical credentials or passkeys. Keep
the source service stopped through reconciliation and cutover. A local synthetic
drill proves that procedure only for its recorded platform and environment.

## Observe admission decisions without collecting secrets

Fixed aggregate counters can explain full work pools, exhausted budgets and
provider failures without user identifiers, IP addresses or request bodies.
Describe their process scope and restart behavior. A counter panel does not
provide durable alerting, visitor identity or measured capacity. Pair rejection
tests with legitimate-operation controls and check real proxy behavior before
treating a socket address as a distinct visitor.

## Executable references

- Business authorization and moderation: `tests/test_business_dashboard.py`
- Administrator MFA and containment: `tests/test_business_admin_mfa.py`
- Challenge and posting-policy checks: `tests/test_business_abuse.py`
- Persistent authentication budgets: `tests/test_business_auth_limits.py`
- Failed verification budgets and route progress: `tests/test_business_submission_limits.py`
- Work admission and cancellation: `tests/test_business_work_limits.py`
- Adversarial role and transaction boundaries: `tests/test_business_adversarial_access.py`
- Adversarial intake and provider failure: `tests/test_business_adversarial_abuse.py`
- Safe create retries and receipt boundaries: `tests/test_business_idempotency.py`
- Additive storage upgrade and rollback: `tests/test_business_storage_upgrade.py`
- Team-message quotas and storage capacity: `tests/test_business_message_limits.py`
- Offline password screening: `tests/test_business_password_policy.py`
- Hosted startup and storage checks: `tests/test_business_hosting.py`
- Read/write contention: `tests/test_business_public_reads.py`
- Session freshness and revocation: `tests/test_business_sessions.py`
- MFA encryption and key custody: `tests/test_business_secret_store.py`
- Current-authority restoration: `tests/test_business_backup.py`
- Aggregate security decisions: `tests/test_business_security_metrics.py`
- [Real-browser workflow](../tools/business_dashboard_browser.py)
- [Seeded API fuzz runner](../tools/business_dashboard_fuzz.py)
- CI dependency-lane contract: `tests/test_landscaping_dependency_lane.py`

The test files are available in the repository checkout, not the source archive.

Provider references: [Cloudflare server validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
and [PyOTP security guidance](https://pyauth.github.io/pyotp/).
