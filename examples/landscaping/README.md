# Cedar & Stone landscaping dashboard

A working demonstration of a small landscaping company's shared schedule,
crew signups, message board and administration pages. It connects the toolkit's
access policy to real password sessions, SQLite transactions and a responsive
FastAPI/HTML dashboard. All initial company records are fictional.

This optional source example runs on Linux, macOS or Windows through WSL Ubuntu.
It is included in the repository and source distribution; the installed toolkit
wheel does not include this application or its extra dependencies.

For a shared pilot, use [Host the landscaping dashboard](HOSTING.md). It includes
separate provision/preflight/serve commands, a checker for your chosen HTTPS
address and the operator steps needed before inviting real staff.

## Run from this checkout

Use Python 3.10 or later. Open a terminal in the repository root. Create the
environment only if `.venv` does not already exist:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[api]"
.venv/bin/python -m pip install -r examples/landscaping/requirements.txt
.venv/bin/python examples/landscaping/run.py
```

The `api` extra retains the toolkit's reviewed HTTP dependency floors. This
demo adds its own pinned FastAPI, Uvicorn and Argon2 dependencies without changing
the toolkit's core requirements. Use a virtual environment without system site
packages. The editable install uses the current checkout, not an older trial
wheel.

Open **http://127.0.0.1:8089** in a browser on the same computer. The terminal
prints the location of a private `TRIAL_ACCOUNTS.md` file containing your six
random initial passwords. Open that file locally, then sign in as `admin` or
one of `alex`, `blair`, `casey`, `drew` and `ellis`. Passwords never appear in the
terminal or login page. Use separate browser profiles/private windows to compare
admin and worker sessions.

Stop the server with **Ctrl+C**. Running the same command again keeps your
accounts, password changes, jobs and messages. A local server in a cloud session
requires supported port forwarding before your PC can reach it.

## Windows

The source demo uses POSIX file permissions and ownership checks. Run it inside
WSL Ubuntu, using a Linux virtual environment and a checkout in the Linux home
directory. A native Windows `.venv` cannot be reused inside Ubuntu.

If WSL is not installed, open PowerShell as administrator:

```powershell
wsl --install -d Ubuntu
```

Complete the prompted restart and Ubuntu user setup. In Ubuntu, install Python
if needed, then follow the repository-root commands above:

```bash
sudo apt update
sudo apt install python3 python3-venv
```

Open the printed local URL in your usual Windows browser. The private account
sheet is in your Ubuntu home directory at
`.local/share/radt-landscaping-demo/TRIAL_ACCOUNTS.md`; Windows File Explorer can
browse the Ubuntu distribution under **Linux**.

For a packaged trial without setting up a source checkout, use the previously
prepared [Windows dashboard ZIP](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/raw/a0ef150b95e98c102258ee45ab4f7d93f2bda125/trial-downloads/cedar-and-stone-windows.zip).
That immutable download contains its own documented WSL launcher and earlier
toolkit wheel. The source demo here uses the current toolkit and a separate data
directory and browser cookie, so its accounts are independent of the ZIP trial.

## Try the workflow

1. Sign in as a worker. Sort or filter the shared schedule, see who is working,
   join an available job, leave it again, and post to the shared message board.
   Workers only have the schedule page and can change their own signups.
2. Sign in as `admin`. Create a worker account and assign its password; reset
   passwords or disable accounts through account management. Edit job capacity,
   assign or remove crew members, and archive or restore jobs.
3. Open a job's management dialog. Reschedule it with a reason, review any crew
   overlaps, cancel it, or reopen it. Completion is available once its start
   time has passed. Completed/cancelled work remains in the shared history view.
4. Inspect the job's before/after history and the admin audit/telemetry page.
   Pause changes and confirm worker writes stop. A stale edit asks you to reload
   the current record before retrying.
5. Explore the customer/outreach and business metrics pages. These track local
   fictional records; they do not send messages, collect money or issue invoices.

The first start creates one administrator, five workers, twelve sample jobs and
ten fictional customers. Schedules display in **America/New_York**, including
when your browser uses another time zone; persisted timestamps use UTC. Ambiguous
or nonexistent daylight-saving clock times are rejected. Crew conflicts require
an administrator's explicit acknowledgment for the current change.

## Private data and restart behavior

The default private directory is `~/.local/share/radt-landscaping-demo`, outside
the repository. It contains `landscape.sqlite3`, the original `identity.key` and
the private initial account sheet. Directories use mode `0700` and files `0600`.
Keep the complete directory private; never commit it or put it under a web root.
If you change a password, the initial account sheet is not a current password
register. Removing that sheet does not regenerate passwords on restart.

An entirely new or empty directory is seeded once. Populated storage is reused;
incomplete storage, missing identity keys and existing databases without accounts
are refused without silently reseeding. For a fresh independent demo, choose a
new outside-repository directory rather than deleting your saved workspace:

```bash
.venv/bin/python examples/landscaping/run.py --data-dir "$HOME/.local/share/radt-landscaping-demo-2" --port 8090
```

`LANDSCAPE_DATA_DIR` supplies an alternative default; an explicit `--data-dir`
takes precedence. Storage inside any part of the source tree is rejected,
including paths reached through symbolic links. The launcher listens only on
`127.0.0.1` and does not trust forwarded proxy headers. Importing `landscape.app`
does not create a database. Advanced ASGI integration can call
`landscape.app:create_default_app` as a factory after provisioning private data;
the factory itself does not seed accounts.

## How it uses the toolkit

| Source | Responsibility |
| --- | --- |
| [landscape/security.py](landscape/security.py) | Verify password sessions, resolve current identity and grants, enforce toolkit `AccessPolicy` and shared freeze |
| [landscape/app.py](landscape/app.py) | Protected server routes, CSRF/origin checks, validation, crew and job rules, readable history |
| [landscape/db.py](landscape/db.py) | Private SQLite storage, atomic migrations and transactions spanning authorization, changes and audit |
| [landscape/action_workflow.py](landscape/action_workflow.py) | Reusable revision/reason/reauthorization/save/audit recipe |
| [landscape/static/app.js](landscape/static/app.js) | Shared schedule, admin pages, accessible dialogs and stale-edit handling |
| [landscape/launcher.py](landscape/launcher.py) | Local startup, persistent private storage and first-run provisioning |
| [hosting/pilot.py](hosting/pilot.py) | Explicit hosted provisioning, read-only storage checks and service startup behind verified HTTPS ingress |
| [scripts/hosted_acceptance.py](scripts/hosted_acceptance.py) | Protocol checks against a selected HTTPS service, with optional private pilot accounts |

The action helper is an exact copy of
[the record workflow example's actions.py](../record_workflows/actions.py), under
the repository's [MIT license](../../LICENSE). Copying keeps this host example
self-contained without making the helper a new public core API. The host owns
authentication, SQLite schema, validation, audit selection and business rules.
The toolkit's source regression suite checks both copies byte for byte so a
recipe fix cannot silently miss this demo; change and review them together.
See [protected record workflows](../../docs/record_workflows.md) to adapt this
pattern to another application.

## Verify changes

The regression test files are available in a repository checkout, and are not
included in the source distribution. Install optional test tools from the
repository root:

```bash
.venv/bin/python -m pip install -r examples/landscaping/requirements-dev.txt
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -c examples/landscaping/pyproject.toml examples/landscaping/tests --import-mode=importlib -q
.venv/bin/python -m playwright install chromium
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python examples/landscaping/scripts/browser_check.py
```

The demo's [browser runner](scripts/browser_check.py) exercises real desktop and
mobile interactions with temporary synthetic data. Run `--help` for its browser
and outside-repository evidence-directory options. Tests use their own private
temporary databases and do not need your running demo accounts.

The tests cover worker attempts to reach admin actions and other accounts,
session revocation, freeze, stale writes, concurrency and rollback on history or
audit failure. These checks demonstrate the implemented boundaries; they do not
make this a production identity service or a security certification.

### Local TLS and recovery

With the demo runtime installed, run the disposable operational drill from the
repository root. It requires Linux, macOS or WSL and the `openssl` executable:

```bash
operations_evidence=$(mktemp -d "${TMPDIR:-/tmp}/radt-landscape-operations-XXXXXX")
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python examples/landscaping/scripts/operational_check.py --output-dir "$operations_evidence"
```

The drill owns fresh fictional accounts and a temporary certificate, verifies
loopback HTTPS and rejected trust/hostname errors, and checks session cookie
attributes, direct authorization, CSRF, origin and freeze behavior. It stops its
fixture server to copy the database, identity key and account sheet, then restores
them into a separate private directory.

Recovery deliberately demonstrates that an old backup also restores access
revoked after the backup. Before opening the restored server, the drill
invalidates all restored sessions, reapplies that fixture's revocation and
freezes writes. It verifies original valid passwords and saved work, denies old
sessions and the revoked account, and requires an administrator to resume writes.
This scenario is not a general backup utility: a real restore must reconcile
all subsequent account, grant, password and business-data changes.

The only retained output is a secret-free `summary.json` with its scope, completed
checks and `success`/`stage`; private accounts, keys, certificates, databases and
backups are temporary and removed. Use a new or empty private output directory
outside the checkout. The drill never opens your running demo's data. A
successful run requires `success: true` and `stage: complete`.

### Verify a source package

Release maintainers can test the exact reviewed source distribution with
[the artifact runner](../../tools/landscaping_artifact_smoke.py). Set
`reviewed_sdist` to that built `.tar.gz` file, then run from its matching reviewed
checkout in a POSIX shell:

```bash
artifact_evidence=$(mktemp -d "${TMPDIR:-/tmp}/radt-landscape-artifact-XXXXXX")
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tools/landscaping_artifact_smoke.py --sdist "$reviewed_sdist" --output-dir "$artifact_evidence"
```

The runner verifies the exact archive contents, installs the source package and
demo dependencies into a fresh environment, performs protected HTTP actions and
restarts with saved accounts/work/history intact. It checks that imports use the
installed toolkit and the archive and extracted source remain unchanged. Require
`passed: true` in `summary.json` and compare its artifact digest with the reviewed
build. The archive is executable trusted source; these checks do not make an
arbitrary downloaded archive safe. Retain the summary rather than publishing the
whole temporary installation. See the [release checklist](../../docs/release_checklist.md)
for build and release evidence requirements.

Contributor CI runs the source/security/browser suite, artifact smoke and local
operational drill. Dependency CI separately audits the demo's resolved `api` and
landscaping requirements, including Argon2, alongside the toolkit's `api` and
`full` environments.

### Deployment boundary

The artifact smoke uses local HTTP; the operational drill uses verified local
TLS and a Python HTTP client. Neither verifies browser cookie enforcement, public
HTTPS/proxy configuration, an actual OIDC provider, Windows/WSL installation or a
production backup policy. The demo uses its own password sessions; it is not an
OIDC deployment example.

For a shared pilot, follow the example's [hosting guide](HOSTING.md). The hosted
adapter separates one-time provisioning from restart, checks that the database
matches its identity key, and requires secure sessions behind an isolated HTTPS
ingress. Its acceptance checker connects to the selected address; it does not
launch a test fixture or establish browser, load or restore acceptance.

Public ingress and proxy trust, tested backups, monitoring, recovery ownership
and your real business rules still require host-specific work. This is a
single-host SQLite example, not a Cloudflare Workers deployment. The separate
[deployment guide](../../role_aware_dashboard_toolkit/resources/guides/deployment.md)
covers the toolkit's authenticated Streamlit starter with OIDC; its provider
configuration does not apply to this password-session example.
