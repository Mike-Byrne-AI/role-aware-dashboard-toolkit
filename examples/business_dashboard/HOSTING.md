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

Run exactly once in the Render Shell:

```bash
python examples/business_dashboard/hosting/pilot.py provision
```

This creates fictional data, a private identity key, six distinct account
passwords and administrator authenticator enrollment. It prints only the paths
to private `ACCOUNTS.md` and `ADMIN_MFA_SETUP.md` sheets. Inspect or retrieve
them through your trusted private operator session, enroll the administrator's
authenticator, and keep a secure offline recovery copy. Never paste their
contents into a support message, screenshot, source file or build log. Remove
the host's enrollment sheet after successful enrollment if the recovery copy
is secure.

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

This validates existing schema-v3 storage, the matched identity key, private
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

The application uses socket-peer rate buckets and ignores forwarded-address
headers. Multiple visitors behind Render's proxy may share a bucket. Do not set
wildcard forwarding trust to fix that symptom: first verify the actual ingress
and header replacement rules. Render's Python environment can supply
`FORWARDED_ALLOW_IPS=*`; the adapter explicitly disables proxy-header handling
so that ambient setting does not enable trust.

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
   stays private, and the moderator sees the same rules as the guest.
6. Pause work, then unpublish a notice and revoke an employee. Confirm ordinary
   editing, approvals and guest submissions remain blocked while paused.
7. Test the real proxy's rate buckets and direct-origin behavior. Rehearse queue
   saturation and the submission pause without filling a real customer's queue.
8. Restart/redeploy and verify persistence. Restore an application-consistent
   backup in isolation and reconcile revocations, MFA and sessions before reopening.

Do not treat a raw disk snapshot as a tested database backup. Back up SQLite
consistently with its original identity key, keep credentials private and
rehearse restoration. A lost authenticator uses the README's explicit trusted
operator reset; no password-only web reset endpoint exists.

Local tests cover startup and request boundaries with disposable data. They do
not replace hosted checks or establish public HTTPS/proxy configuration. Keep
automatic deployments off until a reviewed branch and operational acceptance
process are in place.
