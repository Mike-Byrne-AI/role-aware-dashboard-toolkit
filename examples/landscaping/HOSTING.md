# Host the landscaping dashboard

The [dashboard demo](README.md) includes a hosting adapter with explicit account
provisioning, storage checks and secure sessions, plus a checker for your chosen
HTTPS address. Use these to move the fictional company from a local trial to a
single-host pilot. This guide does not configure a hosting account, supply a
container image or establish that any provider has passed acceptance.

The toolkit supplies access policy; this example supplies password sessions,
business rules and SQLite storage. The operator supplies the host, persistent
disk, HTTPS ingress, private credential delivery, backups and ongoing monitoring.
Keep fictional records until the host checks and recovery exercise below pass.

## Choose a suitable host

A domain points browsers to a service; it does not run this Python application.
Choose a host that supports all of these requirements before deploying:

- One POSIX application instance and one server process, using a persistent
  local disk. The service account must own its private directory (`0700`) and
  files (`0600`). A build directory, temporary filesystem or network filesystem
  is not the application's durable store.
- An HTTPS ingress with a valid certificate, HTTP redirect or rejection, and
  an isolated plaintext backend port. The adapter listens on `0.0.0.0` inside
  that boundary; never expose its port directly to the internet.
- Preservation of the exact public Host header, including for health checks,
  and documented proxy peer addresses and forwarded-header handling.
- A private shell or operator job that can provision and back up the **same
  disk** the application uses. A separate build or one-off job may not mount it.
- Supervision, restart controls, storage alerts and a reviewed service cost.

These are deployment requirements, not verified claims about a particular
hosting provider. SQLite in this example does not support a multi-replica
deployment. A Cloudflare-managed domain can point to a suitable Python host;
this application is not a Cloudflare Workers application.

## Configure and provision once

Install the demo dependencies using the [local setup](README.md#run-from-this-checkout).
Use the same reviewed source and Python environment for each command. Preserve
the example's full directory layout within the checkout or extracted source
distribution; its imports and private-data guards depend on that layout. Do not
flatten or copy just the launch scripts into another source directory. The bash
commands below run from the repository root on the POSIX host; for a Windows
operator, run them in WSL Ubuntu rather than native PowerShell. Replace the
example hostname and select a persistent directory owned by the service account:

```bash
export PYTHONDONTWRITEBYTECODE=1
export PUBLIC_ORIGIN=https://landscaping.example.com
export LANDSCAPE_DATA_DIR="$HOME/.local/share/radt-landscaping-hosted"
export PORT=10000
export TRUSTED_PROXY_CIDRS=""
.venv/bin/python examples/landscaping/hosting/pilot.py provision
.venv/bin/python examples/landscaping/hosting/pilot.py preflight
```

`PUBLIC_ORIGIN` must be one canonical HTTPS DNS origin without a path, port,
credentials or wildcard. `LANDSCAPE_DATA_DIR` must be absolute and outside the
entire checkout or extracted source package, including paths through symlinks.
When using a managed persistent disk, replace the sample home-directory path
with a private directory on that disk. Set the same environment values in the
service's startup configuration; shell exports alone do not persist there.

`provision` creates fictional records and six accounts **only in new or empty
storage**. It prints the location of the private `TRIAL_ACCOUNTS.md` account
handoff, not the passwords. Read it through private operator access and give each
tester only their own password. Never put the handoff, databases, keys, acceptance
accounts or backups in source control, build contexts, public logs or screenshots.
The handoff is an initial account sheet, not a register of later password changes.

`preflight` checks existing private permissions, database structure and integrity,
references, an active administrator and the identity key's match to **every**
saved account, including disabled accounts. It starts no listener and does not
repair or initialize storage. A different valid-length key is still the wrong
key: preserve the original database and `identity.key` together.

## Configure ingress, then start the service

Complete the host's HTTPS configuration and backend isolation before starting
the listener. The adapter sets Secure cookies and HSTS and derives its HTTPS
scheme from `PUBLIC_ORIGIN`. This describes the external connection; it does not
encrypt traffic to the backend or prove that a host's ingress is secure.

Set `TRUSTED_PROXY_CIDRS` to a comma-separated list of verified ingress peer IPs
or canonical narrow networks. The adapter accepts IPv4 `/24` or narrower and
IPv6 `/64` or narrower. It refuses wildcards, all-address networks, hostnames and
duplicates. Empty means forwarded client IPs are not trusted. Do not guess these
values from an example or broaden them until a provider works. If its contract
cannot fit this boundary, choose a controllable private reverse proxy or another
host.

Verify which ingress peers can reach the backend and how each trusted proxy
replaces or appends forwarded-client-IP headers. Only those peers should be
trusted; an arbitrary visitor must not be able to choose their apparent IP.
With no trusted forwarding, clients behind one proxy can share the application's
source login bucket: 30 failures in 15 minutes. An attacker cycling bogus
usernames could then temporarily block other users. Per-account limits remain,
but they do not resolve this shared-source denial of service. Test two clients
and attempted header spoofing on the actual ingress before unrestricted use.

The normal supervised start command is:

```bash
.venv/bin/python examples/landscaping/hosting/pilot.py serve
```

`serve` runs preflight before opening its listener, reuses accounts and business
records, and **never provisions**. A restart with missing, partial or mismatched
storage must fail for an operator to investigate. Do not put `provision` into a
routine restart command or delete storage to make a failed deployment start.
Schema changes require a reviewed migration before service startup.

Configure the hostname at the application host, then add its specified DNS
records. Preserve unrelated website and mail records. Verify certificate
issuance, public HTTP handling and backend isolation from outside the host.
An additional DNS provider proxy changes the trust chain; verify ingress and
client-IP behavior again whenever that chain changes. Health checks must use the
allowed hostname; do not replace the exact Host allowlist with a wildcard to
accommodate a mismatched check.

## Check the actual HTTPS address

The [hosted acceptance checker](scripts/hosted_acceptance.py) connects to an
explicit existing service; it never launches its own fixture. From a trusted
operator environment, choose a fresh output file outside the entire checkout or
extracted source package, including paths through symlinks:

```bash
hosted_evidence=$(mktemp -d "${TMPDIR:-/tmp}/radt-landscape-hosted-XXXXXX")
.venv/bin/python examples/landscaping/scripts/hosted_acceptance.py \
  --base-url https://landscaping.example.com \
  --output "$hosted_evidence/public.json"
```

The public run checks certificate/hostname verification, the expected dashboard,
security headers and unauthenticated boundaries. It does not sign in. For account
checks, create a private JSON file outside the source tree, owned by the operator
with mode `0600`, without symlinks or hard links. Its shape is:

```json
{"admin":{"username":"admin","password":"REPLACE_PRIVATELY"},"workers":[{"username":"alex","password":"REPLACE_PRIVATELY"}]}
```

Supply all five workers to check the full initial company; the runner accepts
one to five distinct workers. Enter real values only through your private editor
or secret-management workflow. Add `--accounts-file` to the command, using that
file's absolute path and a new output name. The checker verifies the expected
public boundary before sending passwords and never follows redirects. It uses
separate sessions to check identity and role, common schedule visibility, admin
denials, cookie attributes, CSRF/origin checks and logged-out token replay.

Inspect `status`, `authenticated_checks`, `worker_accounts_requested`, individual
checks and `not_verified` in the JSON receipt. A public-only run can pass while
all account checks are unperformed. The runner changes no business records;
requests still produce telemetry/audit events and account checks create and end
sessions. Receipts exclude passwords, cookies and response bodies. Use dedicated
pilot accounts and never attach the private account file to results.

Omit `--ca-file` for public acceptance so the operator's normal certificate trust
store applies. A custom CA run is labelled `custom_ca_rehearsal`; it does not
establish public certificate trust. Do not disable browser certificate checks.

## Rehearse a company week

The protocol checker complements real browser and operational checks. Use
separate browser profiles and fictional data on the intended host:

1. Each worker signs in on desktop and phone, sorts the common schedule, joins
   and leaves work and posts a message. Other workers see the same crew and
   messages. An attempted foreign account selector or direct admin request is
   denied by the server.
2. Admin creates and disables accounts, changes a password, reschedules and
   archives/restores jobs, and assigns/removes crew. Check conflicts, reasons,
   job history, customer views and metrics. Hiding controls alone is insufficient.
3. Two workers compete for the last place; simultaneous edits and stale dialogs
   preserve capacity and history. Admin freezes writes and revokes an already
   signed-in worker; subsequent requests must obey the changed permissions.
4. Verify Secure, HttpOnly and SameSite cookies in actual browser responses,
   then confirm their transport behavior. Test a supervised restart and update;
   accounts, passwords, jobs and messages must persist. Repeat the two-client
   throttling and forwarded-header spoofing checks at the public ingress.
5. Perform an isolated backup/restore and controlled failure. Exercise external
   alerts and administrator recovery before inviting real staff.

For load testing, use a separate fictional-data service with the same host
configuration. Define a bounded request/concurrency plan, stop conditions and
acceptable latency/error rates. Observe worker interactions while load runs and
verify persisted work afterward. Record actual results rather than inferring
capacity from passing functional tests.

The local [browser, TLS/recovery and artifact checks](README.md#verify-changes)
verify their stated fixtures. They do not establish public proxy configuration,
Windows/WSL installation, production load capacity or an operator's restore
process. This example uses password sessions, not an OIDC provider. Keep evidence
for each deployed source revision and environment separate; earlier release
receipts do not certify later changes or a new host.

## Back up, restore and operate

Name the operator responsible for accounts, recovery, updates and incidents.
Choose an encrypted off-host backup destination, retention, acceptable data loss
and recovery time. Configure external uptime checks at the allowed hostname,
storage/backup alerts and a test notification. The dashboard's telemetry page
cannot report that its own server is unreachable.

For the initial consistent backup procedure, stop **every writer** and verify
they are stopped, then copy the complete private directory with its original
database and identity key. Preserve ownership and permissions; encrypt transfers
and stored backups. Do not copy only the SQLite file while the app is writing.

Restore into an isolated service with no user access. Run preflight on the
matched database/key pair, invalidate restored sessions, and reconcile **all**
account, password, freeze and business changes made after the backup before
reopening access. An older backup can restore revoked accounts and old passwords.
Preflight validates structure and pairing; it does not invalidate sessions or
make restored data current. Maintain a protected current change record and keep
the restored service closed if reconciliation is incomplete. Freeze blocks
writes, not permitted reads, so it is not a maintenance access barrier.

The [local recovery drill](README.md#local-tls-and-recovery) demonstrates one
revocation scenario, not a general recovery tool. Test the real restore procedure
and an application rollback separately. Keep a previously reviewed application
build available, but do not roll business data backward merely to match older
code. No production backup automation, public-host acceptance, performance target
or operator recovery guarantee is supplied by this example.
