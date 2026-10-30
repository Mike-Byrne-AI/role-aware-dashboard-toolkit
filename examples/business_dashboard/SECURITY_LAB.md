# Learn security with Westbridge

Use a disposable local workspace or an isolated staging service for these
exercises. The ordinary dashboard remains a working application. Its public
deployment is not a traffic-saturation target, and the application exposes no
attack or test-control endpoints.

For each exercise, record the threat, the expected rejection, a legitimate
operation that still succeeds, unchanged business state after rejection, and
the exact source and environment tested. Passing one exercise establishes that
behavior under those conditions; it does not certify the whole application.

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
backups. Repeat the procedure on an isolated service before deployment.

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
