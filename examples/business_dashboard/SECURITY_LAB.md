# Learn security with Westbridge

Use disposable local workspaces first, then the existing hosted Westbridge
testbed for explicitly bounded hosted acceptance. Another paid service is not
required. Preserve its state and working administrator access, and use a
maintenance window for offline operations. Its public endpoint is not a
traffic-saturation target; the application exposes no attack or test-control
endpoints.

For each exercise, record the threat, the expected rejection, a legitimate
operation that still succeeds, unchanged business state after rejection, and
the exact source and environment tested. Passing one exercise establishes that
behavior under those conditions; it does not certify the whole application.

## Guided evidence and engineering decisions

Open `/security-lab` without signing in to inspect three bounded stories:
revoked-session rejection, conflicting toolkit API writers, and recovery without
restoring revoked authority. The private administrator timeline is a separate
authenticated read. Opening the lab never executes a scenario or changes
business records; authenticated reads retain ordinary session housekeeping.

Generate real local evidence in a new directory outside the checkout:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
$demoEvidence = Join-Path ([System.IO.Path]::GetTempPath()) ("westbridge-security-" + [guid]::NewGuid())
.\.venv\Scripts\python.exe tools/business_security_demo.py --output-dir $demoEvidence
```

Review the exit code and `receipt.json`, including failures and not-run checks.
`BUSINESS_SECURITY_EVIDENCE_FILE` optionally selects that private, sanitized
receipt when starting the app. The file must remain outside source storage.
The public API accepts only the bounded exact receipt schema; it exposes no raw
logs, screenshots, paths, user-submitted content, cookies or credentials. Keep
private diagnostics outside the public evidence file. Browser runs also emit
`receipt.json` alongside their local diagnostic summary.

Receipts identify source bytes, acceptance code, mode, runtime, time, scope and
individual outcomes. A source change during a run fails its receipt. The lab
marks a receipt stale when it differs from the source snapshot captured on the
serving process's first lab request; restart after source changes. A checksum
detects corruption, not a dishonest operator or compromised host. This is
operator-supplied evidence, not independent attestation. Local results never
become physical-device or public-host acceptance merely by uploading them.

Use the [security design dossier](SECURITY_DESIGN.md) for trust boundaries,
threats, design decisions and a versioned, deliberately scoped ASVS mapping.

## Durable events and delivery failure

Schema six adds structured security events and delivery obligations to the
business database. Required sensitive-action events commit with the action;
failure to record them rolls the transaction back. Fixed codes, outcomes,
reasons and opaque principals replace arbitrary request content. Authentication
and authorization rejections use bounded observation after the failed action;
suppressed denials and recording failures remain visible as process diagnostics.
The existing aggregate counters retain their separate in-memory scope. Denial
observations occupy at most 1,000 retained events and at most one quarter of
total event capacity, reserving at least three quarters from unauthenticated
traffic. Excess optional observations are suppressed with a visible diagnostic;
already admitted pending obligations are preserved.

Administrators can load the durable timeline in **Security lab**. Its endpoint
is `/api/admin/security/events`; current authorization is checked for every
read. Delivery uses a local idempotent consumer and a stable event ID. It is
at least once: a crash after delivery but before acknowledgment can repeat
delivery, while the consumer applies that event only once. No external service
receives these events. This local record does not protect against a host
administrator rewriting storage, and it is not an off-host alert service.

Application startup starts one local delivery worker per app, shared across
overlapping lifespans and stopped after the final lifespan exits. It attempts
at most 100 deliveries per cycle, waits five seconds between cycles, and honors shutdown
between events. Inspect **Automatic delivery** in the protected timeline:
running state, last cycle, last delivery and failed-cycle counts are process
diagnostics. Pending/failed event counts are durable. Failure logs contain fixed
messages rather than consumer exceptions or credentials. A stalled or failing
worker needs operator attention; successful local delivery is not off-host
retention. Manual delivery remains available for recovery.

Retention is bounded at 10,000 events. Delivered events become eligible for
pruning after 30 days and are pruned when a new event is recorded; this is not
a scheduled deletion deadline. Pending obligations are preserved. Ordinary
admission keeps retained events plus usable employee sessions within 9,000 slots.
Each employee session therefore has room for its eventual logout/revocation
receipt. Only a server-verified deletion of an owned session can spend that
reservation; an event name or a request claiming priority cannot do so. Current
administrator login/reverification and narrow containment may use the remaining
1,000 slots while preserving employee reservations. Routine administrator
changes do not qualify. Removal of authority and its audit event remain one
transaction, including at the normal watermark.
Current-session logout/revocation does not require fresh reauthentication.
Revoking another own session retains its existing freshness requirement; a stale
employee verification may still require delivery before a new verification
event fits. The reservation does not bypass that authentication check.

Existing databases can begin above the new reservation limit. The timeline
reports any deficit against total capacity; delivery must make room before
the termination guarantee applies. Required mutations fail on insufficient
storage rather than dropping pending evidence. Disk/database failure still
prevents a durable revocation, even when a logical slot is reserved. A freshly verified
administrator can POST an empty JSON object to
`/api/admin/security/events/dispatch` with the ordinary Origin and CSRF controls.
If no administrator session remains, use the trusted offline operator tool
after verifying maintenance and stopping workers:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/dispatch_security_events.py --help
```

Run `tests/test_business_security_events.py` and
`tests/test_business_security_delivery.py` for atomic rollback, restart,
delivery failure, deduplication, bounded denial floods, capacity recovery and
timeline access. An operator-supplied callback in these tests deliberately fails
between delivery and acknowledgment. Preserve its original failure and prove
that a subsequent delivery resumes without repeating the protected business
action.

## Reads and concurrent writes

Public-board and health reads use a read-only SQLite snapshot. A reserved
writer does not itself block these reads, and the freeze state and posts come
from one consistent snapshot. Health reports that storage can be read; it
does not promise that a write can commit immediately. An exclusive database
lock can still delay reads.

Protected operations retain their write transaction: current identity,
permission, freeze state, revision checks and the mutation must remain together.
Do not remove that transaction to make a performance test pass.

Run `tests/test_business_public_reads.py` for held-writer, snapshot consistency,
read-only enforcement and damaged-storage cases.

## Sessions and fresh verification

A session cookie is a bearer credential: possession can authorize requests
without presenting the original password again. HttpOnly helps keep scripts
from reading a cookie; it does not make a stolen cookie harmless.

Administrative business writes and resuming edits require identity verification
within five minutes. Sign-in establishes that window. Reverification uses the
current password and, for an administrator, a new authenticator code. Ordinary
reads update idle activity but never renew verification freshness. Pausing
edits, removing a public post and disabling an account remain available as
containment actions.

Open **Active sessions** from the profile or administrator security controls.
Only the account's own active sessions are returned. Revoking another session
requires fresh verification; revoking the current session works without it.
The server invalidates the token immediately. Session display identifiers are
separate from bearer tokens and their stored hashes.

When a save requires verification, its draft remains intact. Verification does
not replay the save automatically: review the draft and submit it deliberately.
Closing a verification dialog clears its password and authenticator fields.

Run `tests/test_business_sessions.py` and the browser runner's `--security-only`
mode. Test stale verification, wrong credentials, reused codes, another user's
session identifier, revocation during password work, and a delayed response
arriving after a newer sign-in.

## Passkeys and phishing resistance

After signing in, open **Passkeys** from the profile or security controls and
register a credential with a clear device name. Enrollment and removal require
recent verification. The browser asks the authenticator for user verification,
such as a device PIN or biometric; the server verifies its signed response.
Later, use **Sign in with a passkey** or the passkey option in the verification
dialog. Administrators and employees can both enroll credentials.

The server binds ceremonies to a one-use challenge, exact origin, relying-party
hostname, account and originating session or preauthentication cookie. A
discoverable sign-in identifies its account through the credential's opaque
user handle. Challenges expire after two minutes, and enrollment is limited to
eight credentials per account. Removing a credential revokes sessions bound to
it. Synced credentials may use zero or nonmonotonic counters; fresh challenges,
signature verification and user verification remain required.
Registration requests no identifying attestation. Backup status is reported by
the authenticator; it is not proof of hardware provenance or a non-exportable
private key. Passkey options and verification each have two admission slots,
separate from password hashing. Saturating those pools or the finite challenge
store can still delay legitimate passkey operations.

Passkeys are specific to the configured hostname. For local browser exercises,
use the browser runner's localhost origin; do not expect a credential enrolled
there to work at the production domain. The runner's `--passkeys-only` mode uses
Chromium's virtual authenticator with actual WebAuthn signatures. It does not
prove a particular physical device, sync provider or deployed HTTPS origin.

Password sign-in remains available, with TOTP required for administrators.
That fallback and trusted-operator recovery have lower phishing resistance;
adding passkeys does not turn every path into a phishing-resistant one. Losing
all devices requires the reviewed recovery process, not a new public bypass.

Run `tests/test_business_passkeys.py` alongside the browser exercise. Include
wrong origin/RP, invalid signature, missing user verification, wrong account
handle, expired/reused challenges, credential removal and concurrent revocation.

## MFA secret custody

Schema five stores authenticated ciphertext in `admin_mfa.secret_ciphertext`.
Each encryption uses a fresh nonce and binds the value to its account and
enrollment generation. A separate 32-byte key is required; the identity key
is not an encryption key. Wrong or missing keys fail closed.

Fresh local provisioning creates the default key in the sibling
`<data-directory-name>.secrets/mfa.key` directory. Hosted operation requires an
explicit `BUSINESS_MFA_KEY_FILE` path outside runtime storage. Protect that
key separately from database backups, including its directory permissions.
Windows protection depends on the directory ACL; POSIX mode bits are not a
Windows access-control boundary.

For legacy storage, create a new external key explicitly with
`run.py --create-mfa-key`, then use `--migrate-storage` with the same data and
key paths. Stop writes, retain a consistent protected backup, and rehearse on
a copy first. Startup does not silently create a replacement key or migrate
legacy storage. Losing the encryption key prevents recovery of its ciphertext.

This protects database-only disclosure. A compromised running host that can
read both the database and key can decrypt seeds. Migration does not erase old
SQLite pages, setup sheets, disk snapshots or backups. Retire old material
through a separate reviewed retention and credential-rotation procedure.

Run `tests/test_business_secret_store.py` for real encryption, binding,
tampering, wrong-key, explicit migration and rollback cases.

## Key rotation boundaries

Maintain separate protected version/retention records for `identity.key` and
the external MFA encryption key. Rotation records identify the operator,
reason, affected database/backups, cutover and verification results; they do
not contain key bytes, seeds or bearer credentials. Schedule reviews according
to key purpose and exposure, and contain suspected compromise immediately.

`rotate_mfa_key.py` supplies an offline MFA encryption-key rotation. It creates
an independent key at a new path and commits every enrollment ciphertext and
the database key binding in one transaction. It preserves the original key,
identity key, enrollment generations, consumed TOTP counters, sessions and current
permissions. `--migrate-storage` upgrades the schema and `--create-mfa-key`
creates a key; neither performs a rotation. Never overwrite an existing key to
resolve a startup error.

**Identity key.** This key derives user principals, passkey user handles and
other keyed identifiers; it also participates in MFA ciphertext context
binding. Replacing the file alone fails database validation and can break
credential continuity. The toolkit's empty-access-store reprovisioning
procedure does not migrate this business database. An identity-key change
requires a separately reviewed host migration covering every derived
identifier, ownership/audit linkage, MFA re-encryption, session/challenge
invalidation, passkey replacement or a verified compatibility strategy, and
backup recovery. Until that migration is implemented and rehearsed, keep an
affected deployment closed and preserve the matched original files. Do not
reseed the database or remove restore-quarantine markers to reopen it.

**MFA encryption key.** Rehearse the following procedure on a private disposable
copy before rotating the testbed's key:

1. Close ingress and stop all application/background writers. Verify that
   protected reads and writes are unavailable; pausing edits alone is not an
   access barrier. Take a consistent protected backup and preserve the original
   MFA key separately. Rehearse on a private disposable copy first.
2. Choose a new protected key path outside source and runtime-backup directories;
   it must not exist. Run the command below with the verified maintenance state
   and original key. It generates the replacement itself, re-encrypts every
   enrollment while preserving account/generation binding, and replaces the
   database key-binding ciphertext in the same SQLite transaction. A failure
   before commit rolls back every row, the binding and the activity event.
   On POSIX, the key file and its directory entries (including newly created
   ancestor directories) are flushed before ciphertext changes. A failed
   directory flush stops cutover and preserves the attempted files. Windows
   flushes file contents but has no directory-entry durability guarantee from
   this helper; qualify that host separately before claiming power-loss safety.
3. Validate all ciphertext and the binding with the replacement key before
   cutover. Verify the original key no longer opens the migrated database.
   Switch `BUSINESS_MFA_KEY_FILE` and restart every serving process while ingress
   remains closed. Test legitimate administrator sign-in, rejected invalid MFA,
   current grants/revocations and a restored backup before reopening access.
4. Keep original keys under separate protected custody while retained backups
   still require them. Restore such backups with the backup's key and the current
   security source's key, as described below. Record the dependency explicitly;
   deleting an old key can make its backups unrecoverable.

Example PowerShell command, after independently verifying closed ingress,
stopped workers and the protected backup:

```powershell
.\.venv\Scripts\python.exe examples/business_dashboard/rotate_mfa_key.py C:\private\westbridge `
  --current-mfa-key-file C:\private\westbridge.secrets\mfa.key `
  --new-mfa-key-file C:\private\westbridge.secrets\mfa-rotation-001.key `
  --maintenance-confirmed
```

The maintenance flag is an operator assertion, not a probe of the public host.
The exclusive SQLite transaction serializes writers but does not exclude WAL
readers. Runtime transactions recheck the key binding, so a process retaining
the old key refuses its next read or write after cutover; this does not replace
stopping and restarting every worker or checking ingress. The tool does not
change `BUSINESS_MFA_KEY_FILE`, open ingress or restart the service.

Preserve a newly created replacement even if the attempt fails. A process can
stop after committing but before printing success, so an uncertain outcome
requires verifying the database/key pair while offline before any restart or
new attempt. The command refuses an existing replacement path and never silently
retries, overwrites keys or rolls back a committed cutover. Keep a private record
of the operator, reason, attempt paths, backup dependencies and acceptance results.

`tests/test_business_mfa_rotation.py` covers actual process interruption before
commit in rollback-journal and WAL modes, exception rollback, unchanged current
authority, stale-worker rejection and recovery of an older backup with distinct
original/current keys. Directory-flush ordering and failure tests exercise the
publication boundary; they do not simulate a power failure. These are disposable local tests, not hosted rotation
acceptance. Run the documented sign-in and backup recovery checks on the
existing testbed before reopening it.
For a failed planned cutover, restore a consistent database/key pair only after
reconciling current revocations. Do not roll back to a compromised key. If an
MFA key and ciphertext were exposed, replacing the encryption key cannot make
copied authenticator seeds secret again: affected enrollments and sessions need
revocation and fresh trusted enrollment under the host's recovery procedure.

## Backups and recovery

`backup.py backup` uses SQLite's backup API so committed WAL records are
included. Its bundle contains unencrypted business data and the original
identity key. It excludes the independent MFA key and setup sheets. Encrypt
retained bundles and keep the MFA key separately; checksums detect accidental
corruption, not a malicious replacement.

Restore always uses a new directory. It revokes all sessions and pauses edits.
By default it quarantines the restored workspace so old credentials cannot
reactivate access. An explicit current security source is required for a
usable reconciled restore. The source must match the identity and account set;
current credentials, permissions and MFA state replace historical authority.
Keep the original service stopped throughout reconciliation and cutover so
later revocations cannot be lost.

Preserved schema-five archives need the explicit `restore --upgrade-backup-schema`
option. It verifies the archive's checksums, exact schema, original identity and
MFA key, then upgrades only its private staging copy to six. Reconciliation uses
the reviewed current schema-six security source, including current event delivery
acknowledgments. The original archive and authority source remain unchanged.
Without current authority, the upgraded result remains quarantined. Other
legacy archive versions are refused; ordinary startup and backup creation stay
schema-six-only. `restore.json` records original and resulting schema versions.
Run `tests/test_business_backup_schema_upgrade.py` for this migration boundary.

The small recovery-sheet tool and whole-application backup are separate. The
sheet tool retains its 1 MiB limit. Run the real-tool drill with a trusted
official age executable to prove encrypted-file and larger bundle recovery:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
.\.venv\Scripts\python.exe tools/business_recovery_drill.py --help
```

The drill uses fictional data and private temporary storage. Review its exact
arguments and preserve each receipt in a new directory outside the checkout.
Local results do not prove a hosted restore, host permissions or retained
backups. Rehearse the existing testbed's controlled maintenance and cutover
procedure separately before accepting a hosted restore.

## Abuse decisions and availability

Known-account login and password changes share two expensive-work slots.
Unknown usernames use one separate dummy-hash slot. Two short lookup slots
classify requests before that work. This prevents unknown-user hashing from
occupying the known-account pool; lookup traffic or attacks on known accounts
can still exhaust their own capacity. Reverification has one separate slot.
These are per-process admission controls, not a distributed limiter.

Persistent account attempt budgets remain in force. An attacker can still
spend a known account's password budget, so demonstrate that tradeoff and the
cooldown instead of calling lockout a complete availability solution.

Administrator security metrics contain fixed aggregate counters for decisions
such as a full worker pool, exhausted guess budget, body timeout, provider
failure and message quota. Counts cover one process lifetime and reset on
restart. They are not request rates, a durable audit trail or configured alerts.
No passwords, codes, cookies, account identifiers or addresses are labels.

Public submissions still count the socket peer, which may represent many
people behind a proxy. Arbitrary forwarding headers are not trusted identity.
Verify real edge rules, shared-office behavior and direct-origin access in
staging using [the hosting acceptance procedure](HOSTING.md). Measure bounded
traffic before choosing limits; increasing worker counts changes the resource
contract and requires new evidence.

Run `tests/test_business_security_metrics.py`, `test_business_auth_limits.py`,
`test_business_adversarial_abuse.py` and the public-submission/work-limit suites.
