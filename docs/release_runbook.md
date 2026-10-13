# Release publication runbook

**Maintainer-only.** This runbook prepares a GitHub-source release of
[Mike-Byrne-AI/role-aware-dashboard-toolkit](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit).
Contributors do not need it; see [CONTRIBUTING.md](../CONTRIBUTING.md).
Completing local preparation does not authorize network pushes, merging,
hosted release CI, tagging, or publication; each needs a separate maintainer
decision.

## Freeze the source identity

Finish metadata, reporting policy, documentation, and workflow edits before
the final local release commit. Run [release_checklist.md](release_checklist.md),
then capture that clean commit:

```powershell
$releaseCommit = (git rev-parse HEAD).Trim()
$releaseStatus = @(git status --porcelain)
if ($releaseStatus.Count -ne 0) { throw "Release requires a clean working tree." }
```

Project metadata must contain the configured source coordinates and
`SECURITY.md` must document the intended private vulnerability reporting path.
All local configuration checks must pass. `live_validation_required` remains
a separate launch checklist; local success does not prove reachability,
report delivery, human monitoring, or public visibility.

The release channel is `github-source` and `package-index-publication` is
false. No PyPI name ownership, reservation, or publishing authority is claimed.

## Build once

Build the frozen source with isolation enabled, validate it with Twine, and
record SHA-256 digests. Use a fresh output directory; do not reuse stale
artifacts. Audit the wheel and source distribution independently as described
in the release checklist: require complete, unique, regular members for each
archive and reject any unexpected artifact.

Use the checklist's fresh external `$releasePython` environment for source
tests, build, and metadata validation. Install the declared `dev` tooling there
before building; Twine 7 and its packaging dependency support the generated
metadata. Record their versions rather than relying on tools inherited from
the development workstation.

## Smoke the local artifacts

A pre-publication smoke must use local artifacts, not a public-index install
of this project. Create fresh environments in temporary directories outside
the repository. Install and check the core wheel, each of `workbench`, `auth`,
`api`, `pandas`, and `full`, and the source distribution. Check the independent
`auth` wheel on Linux and Windows, including Streamlit/Authlib, access and
resolver imports, and authenticated starter/guide resources; include those
authentication checks in the `full` smoke too. These installation checks do not
establish an external identity provider or deployment configuration. Keep
source-distribution build isolation enabled. Use isolated Python and verify
imports resolve to the installed environment rather than the source checkout.

## Verify source did not move

```powershell
$currentCommit = (git rev-parse HEAD).Trim()
if ($currentCommit -ne $releaseCommit) { throw "HEAD changed after the release build." }
$releaseStatus = @(git status --porcelain)
if ($releaseStatus.Count -ne 0) { throw "Working tree changed after the release build." }
```

All later lanes must reuse these exact bytes. The hosted build produces its
own audited artifacts from the same frozen source commit; the hosted evidence
job downloads those artifacts rather than rebuilding them. Verify artifact
digests against the release candidate evidence for that run and attempt.
The Windows job also downloads the same validated artifacts, rejects download
digest mismatches, and checks per-file hashes before and after its install
smokes. The evidence job requires the Windows receipt to match its source SHA,
run identifier, run attempt, and artifact hashes before recording a candidate.

## Stage through a pull request

Pushing and merging each need separate authorization. Push the reviewed
candidate branch and open a pull request targeting `main`.
Require the protected-branch checks and an up-to-date branch before an authorized
merge. Review the commits and refs being introduced; keep application data and
unrelated history outside the public source.

After merging, check out the final remote `main` commit in a clean release
checkout. If the merge or rebase changed the SHA, capture that final SHA as
`$releaseCommit` and repeat the local source checks, artifact build, audits, and
install smokes above for that commit. Pull-request-head evidence does not certify
a different merge commit. Confirm remote `main` equals `$releaseCommit`. Do not
add another metadata commit before the hosted run.

Check branch protection using live GitHub evidence: require the stable
`contributor-checks` status from `contributor-ci.yml` and `dependency-checks`
from `dependency-audit.yml`, require branches to be
up to date before merging, and disable force pushes and branch deletions.
Contributor CI runs on pull requests and pushes to `main` without the release
approval variable. Keep the manually gated release jobs separate from required
PR status checks. Verify the intended security settings as well.

Verify that GitHub private vulnerability reporting is still enabled and its
public form is reachable. Check the maintainer's notification configuration
without describing it as proof of message delivery or a response-time
commitment.

## Run CI on the final main commit

Only after authorization to consume hosted CI, set the repository variable
`RELEASE_CI_APPROVED_SHA` to the full `$releaseCommit` and manually dispatch the
workflow on `main`. The workflow permits only `candidate` or `main`, an exact
approved SHA, and `workflow_dispatch`; push and pull-request events do not
start this release workflow. Leave the variable unset until the approved run
is ready. The automatic contributor workflow is independent of this variable.

Require every expected Linux Python 3.10-3.14, coverage, packaging, Windows,
and release-evidence job and required step to succeed for the same run attempt
and final SHA. A skipped, cancelled, or merely green-looking incomplete run
is not proof. Review artifact digests, source SHA, branch, run ID, and attempt.
Retain evidence before the one-day artifact retention expires, then remove
the approval variable to disarm the workflow.

If a real failure requires a code change, review a new commit and repeat the
checks affected by it. Never reuse hosted evidence from an older SHA or attempt.

## Publish the same commit

After a separate publication approval, verify the required branch protections,
hosted evidence, and artifact identity. Tag `$releaseCommit` and publish the
GitHub release from that tag
without changing `main` or adding a metadata commit. Confirm the release and
source URLs are anonymously reachable at the approved SHA. Verify GitHub private vulnerability reporting is enabled, its
public reporting form is reachable, and the maintainer's security notification
configuration is set.

If a live requirement is unavailable, record the failure and resolve it;
do not claim publication is complete. Publishing the release does not require
a second CI run when the source SHA and workflow are unchanged.

## Separate package-index release

A future PyPI or TestPyPI release needs its own explicit authorization,
current name/account authority checks, upload credentials, artifact policy,
and post-upload install verification. None of those actions is part of this
GitHub-source launch. Do not treat the configured distribution name or an
availability observation as ownership proof.
