# Host the business dashboard on Render

The source example includes a POSIX hosting adapter at `hosting/pilot.py`.
It serves only explicitly provisioned state, requires administrator MFA and
Turnstile for HTTPS, and ignores unverified forwarding headers. The local
`run.py` remains a loopback launcher. Keep this complete source-example layout;
the toolkit wheel alone does not include it.

This is a prepared deployment workflow. Local tests do not establish that a
particular Render account, domain, proxy or disk is configured correctly. Use
fictional records until the actual-host checks at the end pass.

## Prepare the Render form

Publish and review a branch containing the complete business example and its
hosting adapter before selecting it in Render. An older `main` containing only
the landscaping example cannot run these commands. Record the deployed commit.

Create a Python **Web Service** with these settings:

| Setting | Value |
| --- | --- |
| Name | A descriptive name, such as `example-dashboard` |
| Language | Python 3 |
| Branch | The reviewed branch containing this example |
| Root Directory | Leave blank; the build needs the toolkit and the example |
| Build Command | `python -m pip install ".[api]" -r examples/business_dashboard/requirements.txt` |
| Initial Start Command | `python examples/business_dashboard/hosting/pilot.py bootstrap` |
| Compute | Paid service supporting persistent disks; one instance |
| Persistent disk | Start with 1 GB mounted at `/var/data` |
| Initial Health Check Path | Leave blank for TCP checks |
| Auto-deploy | Off during initial acceptance |

Add these environment variables. Replace the sample hostname with the actual
planned subdomain, using lowercase and no trailing slash:

| Variable | Example |
| --- | --- |
| `PUBLIC_ORIGIN` | `https://business.example.com` |
| `BUSINESS_DATA_DIR` | `/var/data/westbridge` |
| `BUSINESS_MFA_KEY_FILE` | `/var/data/westbridge-secrets/mfa.key` |
| `PYTHONDONTWRITEBYTECODE` | `1` |

Render supplies `PORT`; the adapter defaults to 10000 when it is absent. It
binds to `0.0.0.0` with one worker, access logging off and proxy-header trust off.
The adapter does not infer visitor identity or HTTPS from request headers.

Review the displayed recurring compute and disk charges before deploying.
[Free web services](https://render.com/docs/free) cannot attach persistent disks
and lose local files on restart/redeploy. This SQLite application needs durable
storage for its accounts, identity key and posts. Selecting an external database
does not implement a different storage adapter.

## First deploy: maintenance only

Render's [persistent disks](https://render.com/docs/disks) are available only to
the running instance, not its build, pre-deploy command or one-off jobs. The
explicit `bootstrap` command starts a listener so a paid service's Shell can be
used for provisioning. It creates no files or accounts and returns a fixed 503
maintenance message for every HTTP path. It never serves application data and
never switches automatically into the dashboard, even after provisioning.

Keep the Health Check Path empty during this step. Render's default
[TCP health checks](https://render.com/docs/health-checks) test the listener;
an HTTP check would correctly reject the maintenance response. A successful
bootstrap deploy proves only that the maintenance listener is running.

## Provision privately through the service Shell

After bootstrap is live, open the service's paid
[Shell](https://render.com/docs/ssh). Confirm the persistent disk mount is present
and writable by the service account. The private child `/var/data/westbridge`
will be created with mode 0700; do not use the potentially broader disk mount
itself as the runtime directory.

Create the external encryption key once, then provision in the Render Shell:

```bash
python examples/business_dashboard/run.py --data-dir "$BUSINESS_DATA_DIR" --mfa-key-file "$BUSINESS_MFA_KEY_FILE" --create-mfa-key
python examples/business_dashboard/hosting/pilot.py provision
```

The key creator uses a private directory and exclusive file creation. Verify
service-account ownership, directory mode 0700 and key-file mode 0600. A provider
secret-file mount is suitable only if it satisfies these checks; do not assume
its default permissions do. The sibling path above is separate from database
bundles, but shares the same disk and host. Preserve its recovery copy separately
from database backups. Losing that key prevents decryption of enrolled MFA seeds.

This creates fictional data, a private identity key, six distinct account
passwords and administrator authenticator enrollment. It prints only the paths
to private `ACCOUNTS.md` and `ADMIN_MFA_SETUP.md` sheets. Inspect or retrieve
them through your trusted private operator session, enroll the administrator's
authenticator, and keep a secure offline recovery copy. Never paste their
contents into a support message, screenshot, source file or build log. Remove
the host's enrollment sheet after successful enrollment if the recovery copy
is secure. The [recovery-sheet guide](RECOVERY.md) provides an optional age-based
encryption and verification helper; keep its passphrase separately and verify
the recovery copy before removing any plaintext sheet.

The command refuses nonempty storage. On failure, inspect and preserve existing
files; do not delete them to force a new installation. Normal `serve` never
seeds data, recreates a key or migrates an old schema. For an older example,
follow the README's explicit migration/MFA setup on a protected copy before
replacing a running service's matched database and identity key.

## Configure the subdomain and Turnstile

While still running bootstrap, add the intended subdomain in Render's
[Custom Domains](https://render.com/docs/custom-domains) settings. In Cloudflare,
create a CNAME for that subdomain pointing to the exact `onrender.com` hostname
Render assigned to this service. Start with **DNS only** until Render verifies
the hostname and issues a valid certificate, as described in its
[Cloudflare DNS guide](https://render.com/docs/configure-cloudflare-dns).
For a dashboard subdomain, change only that subdomain's records; existing root,
`www`, email and unrelated site records are outside this setup.

Create a Cloudflare Turnstile widget restricted to the same hostname. Add these
service environment settings and apply them while the Start Command is still
`bootstrap`:

| Variable | Meaning |
| --- | --- |
| `BUSINESS_TURNSTILE_SITE_KEY` | Public widget identifier |
| `BUSINESS_TURNSTILE_SECRET_KEY` | Private verification key; store as a Render secret |

HTTPS preflight refuses missing keys and known testing credentials on public
hosts. Each guest token is verified on the server against the configured
hostname and the action `guest_submission`. The optional visitor IP is omitted
because the socket peer may be Render's proxy. Follow Cloudflare's
[server verification guidance](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).
Rules acknowledgment and bot verification do not classify content: every guest
post still needs human approval.

After the custom-domain certificate is valid, the Render subdomain can be
disabled in Settings to remove that alternate public URL. Cloudflare proxying
is optional. Before relying on an edge restriction, test whether direct-origin
routes can bypass it. Keep server-side moderation and Turnstile regardless.

## Switch deliberately to the dashboard

In the current service's Shell, after environment changes have applied:

```bash
python examples/business_dashboard/hosting/pilot.py preflight
```

This validates existing schema-v5 storage, the matched identity key, private
files, active administrator MFA and challenge configuration. It starts no
listener and makes no provider calls. It does not prove that Turnstile accepts
the real keys, or that the disk actually survives a redeploy.

After preflight passes and the one intended custom domain is verified, change:

| Setting | Value |
| --- | --- |
| Start Command | `python examples/business_dashboard/hosting/pilot.py serve` |
| Health Check Path | `/healthz` |

Deploy that configuration. The health route checks access-state storage and
returns only readiness. It remains behind the application's exact Host check.
Render uses a verified custom domain as the health-check Host, so configure
only the intended domain for this service. Resolve hostname mismatches in the
deployment settings, not by accepting arbitrary hosts in application code.

Login and password-change budgets are scoped to known accounts, independent of
socket-peer failure history. Each permits eight failed or in-flight attempts in
a five-minute window; successful work removes only its own reservation. Prior
failures remain charged until the window expires. The budgets persist across
restarts and sessions.
Unknown usernames do not create persistent limiter rows.
Their generic 401 response can nevertheless be distinguished from a known
account's 429 cooldown after repeated probes. These fictional account names are
public; the example does not promise to conceal account existence.

Public submissions still use socket-peer buckets and ignore forwarded-address
headers. They reserve an attempt before external verification: ten attempts per
peer and thirty globally per sixty-second window. Failed tokens and provider
errors retain their charge. Accepted submissions have separate limits of three
per peer per ten minutes, thirty globally per hour, and one hundred pending.
Multiple visitors behind Render's proxy may share a public-submission bucket.
Do not set wildcard forwarding trust to fix that symptom: first verify the actual
ingress and header replacement rules. Render's Python environment can supply
`FORWARDED_ALLOW_IPS=*`; the adapter explicitly disables proxy-header handling
so that ambient setting does not enable trust.

Blocking authentication and public verification use separate worker admission.
Known-account login and password changes share two slots; unknown-user dummy
hashing has one separate slot, preceded by two short lookup slots. Fresh
password verification has one separate slot, and public verification has four.
These limits apply per application instance.
Excess jobs receive 429 with `Retry-After: 1`, without waiting for a
worker. A cancelled request whose callback is running continues occupying its
slot until that callback exits. Password hashing and provider calls hold no
database write lock, and the application rechecks relevant authority and state
before committing their result.

JSON writes have a 32 KiB body limit and a ten-second total body-read deadline,
including trickled or empty chunks. Each application instance admits at most
32 simultaneous body readers without queuing: full intake returns 429 with
`Retry-After: 1`, and an incomplete body at the deadline returns 408. Disconnects,
cancellation and rejection release the reader slot; a complete body releases
it before database or worker operations. This bounds active reader buffers to
roughly 1 MiB, not total process memory or upstream connections. Slow legitimate
clients may need to retry a rejected upload; these bodies never reached mutation
handlers. Set and verify ingress connection/read limits as well.

The hosting adapter's single worker and single instance are part of this
capacity policy. Increasing either does not create a distributed limiter.
Attempt budgets reuse `login_limits` with separate namespaces. Safe create
retries use receipt storage, and schema five adds encrypted MFA and session
verification state. Keep the existing database and identity
key together; never reprovision to apply this update. Before deployment, rehearse
`run.py --migrate-storage --data-dir <private-copy>` on an application-consistent
backup, verify accounts/records and rollback behavior, then stop production
writes and explicitly migrate the original through a private operator shell.
For the documented Render directory, the command is:

```bash
python examples/business_dashboard/run.py --data-dir "$BUSINESS_DATA_DIR" --migrate-storage
```

Run this only with the reviewed code, a verified backup and writes stopped.
Normal hosted preflight refuses the old schema. Do not run two code versions
against the same store during this upgrade. A code rollback also requires
its compatible backup and reconciliation of any later access changes.

Render documents managed [DDoS protection](https://render.com/docs/ddos-protection),
but that does not establish route-specific throttling or monitoring for this
deployment. Lookup traffic and targeted known-account traffic can still exhaust
their respective admission pools. Unknown-user hashing cannot consume the
known-account hashing slots. Before wider exposure, verify edge limits on login,
password change, public submissions and expensive reads, including direct-origin
bypass checks and alerting for sustained 429/503 responses. Apply limits using
verified visitor identity; do not treat a shared proxy address as one attacker.

Team-message writes allow 10 accepted posts per minute and 100 per hour per
account, using durable fixed windows. A full 10,000-message board rejects new
posts with 507 while preserving history. Choose an operator-reviewed archive
and retention policy before that point; this example never silently deletes
old messages. These bounds do not cap every source of database or audit growth.
Receipts for authenticated creates retain a 24-hour replay window, limited to
512 per account and 4,096 globally. See the [retry contract](README.md) for
browser-storage limits, expiry and excluded operations.

New passwords require 15-128 characters and offline screening against a pinned
common-password list and repetitions of its entries. Existing sign-ins remain
compatible. This sends no screening traffic but cannot establish that a password
is unique or absent from current breaches; review the bundled list's documented
update procedure and the identity requirements of your eventual application.

## Draft hosting-level bot controls

These are starting rules to review and calibrate on an isolated deployment, not
measured capacity or a claim that this live service has them enabled. Render's
managed protection and rules in your own Cloudflare account are separate.
First confirm the actual public hostname, Cloudflare plan and whether the DNS
record is proxied. Verify the custom-domain certificate before enabling proxying.

In Cloudflare, open **Security rules**, create a **Rate limiting rule**, and
save it as a draft. For a Free plan's one path-based rule, a candidate is:

```text
http.request.uri.path in {"/api/login" "/api/password" "/api/public/submissions"}
```

Count by Cloudflare's visitor IP, with an initial 10 requests per 10 seconds and
a 10-second block. Free-plan path matching applies to matching paths on other
hostnames in the zone too: do not enable this draft where it would interfere
with unrelated applications. On Pro, consider separate hostname-scoped rules:
20 requests per minute for login/password together and 10 per minute for guest
submissions, each with a 60-second block. These conservative example values may
need raising for a shared office; do not present them as demonstrated safe load.
Check the current [plan limits](https://developers.cloudflare.com/waf/rate-limiting-rules/)
and [dashboard procedure](https://developers.cloudflare.com/waf/rate-limiting-rules/create-zone-dashboard/)
before applying a rule. Use a temporary block/429 for JSON API endpoints;
[interstitial challenges](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/)
can return HTML that interrupts fetch-based forms. Where the plan supports a
custom response, return a generic JSON `detail` without submitted data.

Before enabling a draft, test legitimate sign-ins and password changes from
several accounts sharing one office address and from mobile. Check edge events
to confirm the rule and visitor IP. Exercise accepted trailing-slash and encoded
path variants as well as the canonical paths; an exact-path edge rule must not
miss an alternate route accepted by the origin. Verify responses, cooldown
recovery, existing-session reads and health during a bounded staging test.
Cloudflare's [counters are not globally exact](https://developers.cloudflare.com/waf/rate-limiting-rules/request-rate/),
so retain application budgets. Never accept arbitrary forwarded headers as
proof of visitor identity or administrator access.

After the custom domain works, disable the alternate Render subdomain as
documented above. Separately prove that the origin cannot be reached around
your own Cloudflare rules with the intended Host header; disabling the default
URL alone is not that proof. Monitor sustained 429/503 responses and latency
using edge/service metrics without request bodies, passwords or authenticator
codes. Record the reviewed rule, source revision and acceptance result before
claiming this protection is active. A Render-only URL cannot use rules in an
unrelated Cloudflare zone.

Targeted attempts can still exhaust an account's budget, and continuing traffic
can still occupy worker capacity or the public global budget. Fixed budget-event
messages contain no submitted credentials or tokens, but they are not a complete
security audit trail. Check log retention and operator visibility. These controls
are not a promise of availability under sustained load.

The direct guest link is `PUBLIC_ORIGIN` followed by `/board`, for example
`https://business.example.com/board`. **Share board** displays the same URL.
It is publicly accessible, not invitation-only. Submitted guest messages are
saved pending administrator approval. Visible guest tabs refresh the public
feed every ten seconds, pause while hidden or offline, and retry failed updates
with backoff while preserving an open draft. Administrators refresh manually,
so background polling does not renew authenticated idle sessions. No additional
service or database migration is required for this board.

## Accept the actual hosted service

Use disposable fictional records and private evidence for these checks:

1. Confirm the deployed source revision, URL, exact public origin, persistent
   mount and current runtime dependency audit.
2. Check HTTPS redirects/certificate, accepted Host/Origin, cookie Secure,
   HttpOnly and SameSite attributes, and absence of secrets in service logs.
3. Sign in with the administrator password plus authenticator; verify wrong,
   missing and reused codes fail. Verify employee password-only sign-in and
   guest access do not grant administration.
4. Submit through the real widget. Missing/invalid/reused tokens, another
   hostname/action and provider failure must not create a pending post.
5. Confirm a pending post is private, approval publishes exactly once, rejection
   stays private, and the moderator sees the same rules as the guest. Use a
   separate guest browser opened directly at `/board` and an administrator
   browser. Without reloading the guest page, approve a test post and confirm it
   appears on the next successful refresh; unpublish it and confirm it disappears.
   Keep a guest draft open during an update, then check hidden-tab/offline
   recovery and confirm the draft remains intact. Check this on the deployed
   commit; local browser results do not establish live update behavior.
6. Pause work, then unpublish a notice and revoke an employee. Confirm ordinary
   editing, approvals and guest submissions remain blocked while paused.
7. On an isolated deployment of the exact reviewed commit, verify that rejected
   login/password-change attempts remain charged across sessions and restarts.
   Unknown-user failures from the same proxy must not impose a stored cooldown
   on another account's valid sign-in. Confirm targeted-account expiry behavior.
8. Use bounded, coordinated checks on that isolated deployment to verify failed
   verification attempts eventually stop before provider calls, excess work is
   rejected promptly, and health and authenticated reads progress during slow
   verification. Check capacity recovery after errors and cancellation. Do not
   use a public client demo as a saturation or denial-of-service target.
9. Test the real proxy's public-submission buckets and direct-origin behavior.
   Rehearse queue saturation and the submission pause without filling a real
   customer's queue. Keep shared-peer effects distinct from login account limits.
10. Restart/redeploy and verify persistence. Restore an application-consistent
    backup in isolation and reconcile revocations, MFA and sessions before reopening.
11. On the isolated deployment, lose a create reply after commit and retry the
    unchanged staff message, event, contact and notice. Verify one saved record
    and one audit action, including after refreshing the same browser tab.
    Confirm a revoked/downgraded account cannot retrieve its prior receipt.
12. Check message 429 feedback with a retained draft and the documented retry
    interval. Verify that a blocked common new password leaves the old password
    and current session usable. Confirm no password-screening network request
    or credential-bearing log entry is produced.

Do not treat a raw disk snapshot as a tested database backup. Back up SQLite
consistently with its original identity key, keep credentials private and
rehearse restoration. A lost authenticator uses the README's explicit trusted
operator reset; no password-only web reset endpoint exists.

Local tests cover startup and request boundaries with disposable data. They do
not replace hosted checks or establish public HTTPS/proxy configuration. Keep
automatic deployments off until a reviewed branch and operational acceptance
process are in place. Record the source revision and scope with each result:
local remediation of an earlier assessment finding is not evidence that the fix
is deployed. A prior live report does not establish the behavior of a new commit.

## Security lab deployment prerequisites

Review [the security lab](SECURITY_LAB.md) before migrating. Hosted schema five
requires an explicit `BUSINESS_MFA_KEY_FILE` outside the data/backup directory.
Create and protect that independent key before migration; never replace a lost
key to force startup. Hold its recovery copy separately from database backups.
Migrate a protected copy first, then the original with writes stopped. Old
backups and SQLite remnants may still contain plaintext MFA seeds.

Fresh verification is required for sensitive administration. Test the real
browser flow and session revocation after deployment. Security counters are
per-instance observations that reset on restart; configure retention and
alerts at the host separately. Public health now checks read readiness, not
write capacity. Run the real encrypted recovery drill on an isolated service
and reconcile current access before switching to restored storage.

## Prepare an isolated staging service

Use a separate service named, for example, `westbridge-security-staging`, with
its own 1 GB disk, fictional accounts, independent keys and hostname. Start in
`bootstrap`, with auto-deploy off. Select the exact reviewed commit after local
and CI checks; an uncommitted working tree cannot identify a Render deployment.
Do not copy the production database, enrollment sheets or Turnstile secret into
this service. Give the staging hostname its own widget configuration.

Render's smallest paid web-service plan is currently `0.5c-512mb` (formerly
Starter). Its official example estimates about $7/month for compute plus
$0.25/month for a 1 GB disk. Treat $7.25/month as a starting estimate, excluding
workspace charges, tax, bandwidth and other usage; review the creation form's
current quote before creating resources. This is not a measured capacity
recommendation. See [compute plans](https://render.com/docs/compute-plans),
[Render's cost example](https://github.com/render-examples/nanobot-render/blob/main/README.md#cost-expectations)
and [pricing](https://render.com/pricing).

Keep test artifacts in a private directory on the staging disk. For the portable
real-age drill, download the matching archive from the official release, then:

```bash
umask 077
mkdir -m 700 /var/data/security-drills
python tools/business_recovery_drill.py --release-archive /path/to/age-v1.3.2-linux-amd64.tar.gz --output-dir /var/data/security-drills/recovery-001
```

Choose a new output directory for every attempt and use a disposable passphrase
at the terminal prompts. The helper verifies its pinned release checksum,
encrypts and decrypts fictional data, and checks restored authority locally on
that host. Its local HTTP client does not exercise the public proxy or an
actual service cutover. Preserve failures as well as successful receipts.

### Rehearse recovery of the staging application's own data

Use only the isolated service created above. Before taking its backup, establish
an employee browser session, register and successfully use a disposable passkey,
and confirm a second employee can sign in. Preserve these private test controls
without putting cookies or credentials in evidence. Keep a current administrator
and a working authenticator available throughout the exercise.

The following commands run in the staging service's private POSIX Shell. Replace
the example hostname and staging paths in the guards with that isolated service's
actual values. Do not substitute production paths. Use the verified age binary
from the completed pinned-release drill above. Reserve disk space for several
copies of the database; preserve failures and choose a new attempt directory.

```bash
set -eu
umask 077
export STAGING_SOURCE=/var/data/westbridge-staging
export CUTOVER_DIR=/var/data/security-drills/cutover-001
export RECOVERED_KEY="$CUTOVER_DIR/key-custody/mfa.key"
AGE=/var/data/security-drills/recovery-001/age
test "$PUBLIC_ORIGIN" = 'https://staging.example.com'
test "$BUSINESS_DATA_DIR" = "$STAGING_SOURCE"
test "$BUSINESS_MFA_KEY_FILE" = '/var/data/westbridge-staging-secrets/mfa.key'
test "$("$AGE" --version)" = 'v1.3.2'
mkdir -m 700 "$CUTOVER_DIR"
mkdir -m 700 "$CUTOVER_DIR/key-custody"
python examples/business_dashboard/backup.py backup "$STAGING_SOURCE" --output "$CUTOVER_DIR/bundle" --mfa-key-file "$BUSINESS_MFA_KEY_FILE"
```

Package only the three expected bundle members. This creates a private archive
and a digest to retain with the attempt's trusted records:

```bash
python - <<'PY'
# staging-pack-bundle
import hashlib
import os
from pathlib import Path
import zipfile

root = Path(os.environ["CUTOVER_DIR"])
bundle = root / "bundle"
names = ("business.sqlite3", "identity.key", "manifest.json")
if {path.name for path in bundle.iterdir()} != set(names):
    raise SystemExit("Unexpected or incomplete backup bundle; preserve it.")
with (root / "backup.zip").open("xb") as output:
    os.chmod(output.name, 0o600)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in names:
            archive.write(bundle / name, name)
digest = hashlib.sha256()
with (root / "backup.zip").open("rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
with (root / "archive.sha256").open("x", encoding="ascii") as receipt:
    receipt.write(digest.hexdigest() + "\n")
PY
```

Use age directly for the application archive, which may exceed the recovery-sheet
wrapper's 1 MiB limit. Use separate nonempty passphrases for the bundle and key,
entered only at age's private prompts. Every output below must be new:

```bash
test ! -e "$CUTOVER_DIR/backup.zip.age"
test ! -e "$CUTOVER_DIR/recovered.zip"
"$AGE" --encrypt --passphrase --output "$CUTOVER_DIR/backup.zip.age" "$CUTOVER_DIR/backup.zip"
"$AGE" --decrypt --output "$CUTOVER_DIR/recovered.zip" "$CUTOVER_DIR/backup.zip.age"
python examples/business_dashboard/recovery.py --age-executable "$AGE" encrypt "$BUSINESS_MFA_KEY_FILE" --output "$CUTOVER_DIR/key-custody/mfa.key.age"
python examples/business_dashboard/recovery.py --age-executable "$AGE" restore "$CUTOVER_DIR/key-custody/mfa.key.age" --output "$RECOVERED_KEY"
```

Check the recovered archive against the retained digest, admit exactly the fixed
members, and write new private regular files. Do not use unrestricted extraction:

```bash
python - <<'PY'
# staging-unpack-bundle
import hashlib
import os
from pathlib import Path
import shutil
import zipfile

root = Path(os.environ["CUTOVER_DIR"])
digest = hashlib.sha256()
with (root / "recovered.zip").open("rb") as source:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
if digest.hexdigest() != (root / "archive.sha256").read_text(encoding="ascii").strip():
    raise SystemExit("Recovered archive differs; preserve this attempt.")
names = ("business.sqlite3", "identity.key", "manifest.json")
destination = root / "decrypted-bundle"
with zipfile.ZipFile(root / "recovered.zip") as archive:
    if sorted(archive.namelist()) != sorted(names):
        raise SystemExit("Unexpected, missing or duplicate archive members.")
    if any(member.compress_type != zipfile.ZIP_STORED for member in archive.infolist()):
        raise SystemExit("Unexpected archive encoding.")
    destination.mkdir(mode=0o700)
    for name in names:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(destination / name, flags, 0o600), "wb") as output:
            with archive.open(name) as source:
                shutil.copyfileobj(source, output, 1024 * 1024)
PY
```

This is a same-host encryption and recovery rehearsal. To demonstrate independent
custody, repeat using an encrypted bundle, its trusted digest and the matching
encrypted key recovered from your separate storage location, with separately
held passphrases. Recover them into a new private attempt; do not depend on the
original plaintext files or host disk. A same-disk copy does not prove off-host
backup availability. Never replace a missing original key with a newly generated
key. Checksums alone do not authenticate a maliciously replaced bundle.

After the backup, use the staging UI to change the first employee's password,
remove the disposable passkey and disable the second employee. Verify current
sign-in still works. To exercise stale authenticator recovery too, perform the
README's explicit administrator MFA reset and enroll the new authenticator
privately. These changes must precede reconciliation; otherwise the expected
rejection of an "old" credential is an empty test.

Switch the staging service to maintenance: set **Health Check Path** to blank
(TCP) and **Start Command** to `python examples/business_dashboard/hosting/pilot.py bootstrap`,
then deploy those settings together. Confirm the actual HTTPS URL returns the
fixed 503 maintenance response and the dashboard process has stopped. Keeping
`/healthz` configured would reject bootstrap's intentional 503. Do not merely
pause business edits: authentication changes must also stop. Keep this original
runtime stopped through reconciliation and cutover.

The maintenance deploy may terminate the old Shell. Open a new staging Shell
and restore the guarded variables below, using the same attempt paths. Do not
repeat the earlier directory creation, backup or encryption steps. Restore with
the stopped **current runtime** as security authority, not the old bundle or
another historical backup. The output directory must not exist:

```bash
set -eu
umask 077
export STAGING_SOURCE=/var/data/westbridge-staging
export CUTOVER_DIR=/var/data/security-drills/cutover-001
export RECOVERED_KEY="$CUTOVER_DIR/key-custody/mfa.key"
test "$PUBLIC_ORIGIN" = 'https://staging.example.com'
test "$BUSINESS_DATA_DIR" = "$STAGING_SOURCE"
test "$BUSINESS_MFA_KEY_FILE" = '/var/data/westbridge-staging-secrets/mfa.key'
test -f "$RECOVERED_KEY"
test -d "$CUTOVER_DIR/decrypted-bundle"
test ! -e "$CUTOVER_DIR/restored"
python examples/business_dashboard/backup.py restore "$CUTOVER_DIR/decrypted-bundle" --output "$CUTOVER_DIR/restored" --mfa-key-file "$RECOVERED_KEY" --security-source "$STAGING_SOURCE"
BUSINESS_DATA_DIR="$CUTOVER_DIR/restored" BUSINESS_MFA_KEY_FILE="$RECOVERED_KEY" python examples/business_dashboard/hosting/pilot.py preflight
```

If the encryption key changed after backup, independently recover both keys:
`--mfa-key-file` must identify the current source's key and
`--backup-mfa-key-file` the original backup's key. Omitting `--security-source`
intentionally produces an unusable quarantined restore. No usable current source
means this procedure cannot safely reopen historical authority; retain quarantine
for a separate reviewed recovery plan. Never remove its marker to force startup.

After successful preflight, persist **BUSINESS_DATA_DIR** as the full restored
path and **BUSINESS_MFA_KEY_FILE** as the full recovered-key path in Render's
settings; Shell variables alone do not change the service. Preserve the staging
**PUBLIC_ORIGIN** so passkeys keep their original relying-party hostname. Set
**Start Command** back to `python examples/business_dashboard/hosting/pilot.py serve`
and **Health Check Path** to `/healthz`, then deploy. The old source stays offline.

Through the real HTTPS URL, verify the retained old session, superseded password,
removed passkey and disabled account fail. Verify the current credentials and
authenticator succeed, business records are present, and edits remain paused
until deliberately resumed with fresh verification. Restart and repeat these
essential checks. Record commit, dependencies, configuration, artifact hashes,
platform, positive controls and rejected operations without secrets. Preserve
originals; rollback after later access changes needs another reconciliation,
not a blind switch to old storage.

Test edge rules and proxy grouping separately on the isolated hostname.
Cloudflare Free path-only rules can affect other hosts in the zone, so a staging
hostname alone does not isolate such a rule. Review the entire rule scope before
enabling it. Hosted recovery, public passkeys, real Turnstile and ingress
acceptance remain separate evidence until each is exercised.
