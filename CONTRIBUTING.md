# Contributing to Role-Aware Dashboard Toolkit

Contributions should keep the dashboard library usable across applications.

Use the [documentation map](docs/README.md) to find the relevant guide or example,
and [architecture scope](ARCHITECTURE_SCOPE.md) for the library's boundaries.

## Development setup

Use Python 3.10 or later. From the repository root:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -c "import role_aware_dashboard_toolkit as r; print(r.__file__)"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check role_aware_dashboard_toolkit tools examples tests --no-cache
```

The printed package path must resolve inside this checkout; an older installed
wheel can otherwise give misleading test results.

Create `.venv` only when it does not already exist. On Linux or macOS with bash
or zsh, use `export PYTHONDONTWRITEBYTECODE=1` instead of the PowerShell
environment assignment, and `.venv/bin/python` instead of
`.\.venv\Scripts\python.exe`. Do not enable system site packages in a new
environment. Reinstall `.[dev]` after dependency changes; this upgrades
tools that no longer meet the declared floors, including Twine 7's metadata
reader. For a release, use the fresh environment in the release checklist.

Run focused tests while developing, then run the full checks before submitting
changes. The [release checklist](docs/release_checklist.md) adds coverage, build,
artifact, and installation verification for release candidates.

Set `PYTHONDONTWRITEBYTECODE` before starting Python so pytest collection and
child processes do not create bytecode in the source tree. The release checker
rejects generated cache files. Ruff's selected `E4`, `E7`, `E9`, and `F` checks
are explicit in `pyproject.toml`, so a new Ruff default does not change the
repository's lint policy.

## Change scope

- Keep changes small and explain the behavior they affect.
- Preserve documented public APIs unless a reviewed change explicitly updates
  the contract and its migration guidance.
- Add focused regression tests when behavior changes.
- Keep identity-provider configuration, credentials, deployment policy, and
  application-specific integrations in the host application. The optional access
  layer supplies verification adapters, role grants and shared freeze enforcement.
- Update documentation and generated references when their contracts change.

## Before submission

Confirm tests, lint, and documentation links pass. Describe the problem, the
resulting behavior, and the verification performed. Follow
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and consult [SECURITY.md](SECURITY.md)
before sharing sensitive findings.

Pull requests automatically run `.github/workflows/contributor-ci.yml`: full
tests on Linux with Python 3.10–3.14, Windows with Python 3.11 and macOS with
Python 3.12, lint, coverage, package build/metadata validation, and a Chromium
dashboard smoke.
The browser smoke checks profile restoration, role changes, and frozen
controls using synthetic local state. It also generates the Project Pulse
starter and exercises desktop and mobile layouts, navigation and keyboard
editing. It does not test an external login provider.
The dedicated Linux landscaping job also installs the demo's optional
dependencies and runs its API/security suite against the checkout, plus Chromium
flows against the installed toolkit. The job also runs the disposable local
TLS/restore drill and verifies the demo from a freshly installed source
distribution. See the [demo guide](examples/landscaping/README.md) for local
commands and evidence boundaries. These checks use newly generated fictional
accounts and private temporary storage; they never use an existing dashboard's
data. A source regression requires the copied landscaping action helper to match
the generic workflow helper byte for byte; update both together when changing
that recipe.
The stable required check is `contributor-checks`; failed, skipped, or cancelled
test, quality, browser, or landscaping jobs make it fail. Browser diagnostics are retained
for seven days. The workflow has read-only permissions and does not receive
release credentials. GitHub may require a maintainer to approve the first
workflow run for a fork contributor.

To run these browser checks locally, install Playwright in the development
environment. From the repository root, in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install "playwright==1.63.0"
.\.venv\Scripts\python.exe -m playwright install chromium
$browserEvidence = Join-Path ([System.IO.Path]::GetTempPath()) ("radt-browser-" + [guid]::NewGuid())
.\.venv\Scripts\python.exe tools/browser_smoke.py --output-dir $browserEvidence
```

In bash or zsh:

```bash
.venv/bin/python -m pip install "playwright==1.63.0"
.venv/bin/python -m playwright install chromium
browser_evidence=$(mktemp -d "${TMPDIR:-/tmp}/radt-browser-XXXXXX")
.venv/bin/python tools/browser_smoke.py --output-dir "$browser_evidence"
```

If a managed environment already supplies Chromium, pass
`--browser-executable /path/to/chromium` instead of downloading a browser. The
output directory must be empty and outside the checkout. Inspect `summary.json`,
screenshots and traces; retain a failed run separately when retrying. The runner
owns and stops its servers and uses temporary sample data. CI adds
`--installed-package` to exercise its non-editable installation; use that option
with an isolated wheel installation when checking packaged starter resources.

`.github/workflows/dependency-audit.yml` audits three freshly resolved runtime
environments: `api`, `full`, and `landscaping` (the toolkit's `api` extra plus
the demo requirements, including Argon2). It runs on pull requests, pushes to
`main`, manual dispatch, and Mondays at 09:17 UTC. Its `dependency-checks`
result requires all three audits
to complete without known vulnerabilities or skipped packages. Scanner and
network errors fail separately from vulnerability findings. Reports and exact
resolved versions are retained for seven days. The local toolkit and environment
installation tools (`pip`, `setuptools`, `wheel`) are explicitly excluded;
the scanner runs in a separate environment. Advisories require maintainer
review; the workflow does not upgrade packages automatically.

The artifact smoke and operational drill are complementary. The artifact smoke
checks an actual source package, isolated installation, protected HTTP actions
and restart. The drill verifies a temporary certificate and hostname, session
cookie attributes and restoring synthetic data while reconciling revoked
access. Neither establishes public HTTPS/proxy configuration, a real OIDC
provider, browser cookie enforcement or the Windows-to-WSL first-run experience.
Record those as separate host acceptance work, not implied CI coverage.

Maintainers should require `contributor-checks` and `dependency-checks` on `main`, with the branch up
to date before merging and force pushes/deletions disabled. Check the live
repository rules rather than assuming this document configures protection.
The separately guarded release workflow in `ci.yml` remains manually dispatched.

## Contribution channels

Use the [issue tracker](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/issues)
for public bug reports and feature proposals. Follow [SECURITY.md](SECURITY.md)
for vulnerability reports; do not include sensitive details in public issues.
