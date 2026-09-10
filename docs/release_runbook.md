# Release publication runbook

This runbook prepares a GitHub-source release at
[Mike-Byrne-AI/role-aware-dashboard-toolkit](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit).
The URL is the planned destination until the repository exists. Completing
local preparation does not authorize repository creation, network pushes,
hosted CI, or publication.

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

## Smoke the local artifacts

A pre-publication smoke must use local artifacts, not a public-index install
of this project. Create fresh environments in temporary directories outside
the repository. Install and check the core wheel, each of `workbench`, `api`,
`pandas`, and `full`, and the source distribution. Keep source-distribution
build isolation enabled. Use isolated Python and verify imports resolve to
the installed environment rather than the source checkout.

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

## Stage on a private GitHub repository

After separate authorization, create a new private repository at the configured
destination. Push the prepared local candidate commit to remote `main` only.
Confirm the remote `main` SHA equals `$releaseCommit`, the repository is still
private, and no inherited history or unexpected refs have been introduced.
Do not create another metadata commit before the hosted run.

Check the intended branch protection and security settings using live GitHub
evidence. GitHub private vulnerability reporting is a public-repository
feature: record the configured policy before the visibility change, then
verify activation and the public form immediately afterward. Check the
maintainer's notification configuration without describing it as proof of
message delivery or a response-time commitment.

## Run CI on the final main commit

Only after authorization to consume hosted CI, set the repository variable
`XL422_CI_APPROVED_SHA` to the full `$releaseCommit` and manually dispatch the
workflow on `main`. The workflow permits only `candidate` or `main`, an exact
approved SHA, and `workflow_dispatch`; push and pull-request events do not
start it. Leave the variable unset until the approved run is ready.

Require every expected Linux Python 3.10-3.12, coverage, packaging, Windows,
and release-evidence job and required step to succeed for the same run attempt
and final SHA. A skipped, cancelled, or merely green-looking incomplete run
is not proof. Review artifact digests, source SHA, branch, run ID, and attempt.
Retain evidence before the one-day artifact retention expires, then remove
the approval variable to disarm the workflow.

If a real failure requires a code change, review a new commit and repeat the
checks affected by it. Never reuse hosted evidence from an older SHA or attempt.

## Publish the same commit

After a separate visibility-change approval, verify private staging, required
branch protections, hosted evidence, and artifact identity. Make the repository
public without changing `main` or adding a metadata commit. Confirm the public
URLs are anonymously reachable at the approved SHA. Verify GitHub private
vulnerability reporting is enabled, its public reporting form is reachable,
and the maintainer's security notification configuration is set.

If a live requirement is unavailable, record the failure and resolve it;
do not claim publication is complete. The visibility change itself does not
require a second CI run when the source SHA and workflow are unchanged.

## Separate package-index release

A future PyPI or TestPyPI release needs its own explicit authorization,
current name/account authority checks, upload credentials, artifact policy,
and post-upload install verification. None of those actions is part of this
GitHub-source launch. Do not treat the configured distribution name or an
availability observation as ownership proof.
