# Release publication runbook

Run these commands from the repository root after
[release_checklist.md](release_checklist.md) passes.

## Freeze the source identity

```powershell
$version = py -3 -c "from role_aware_dashboard_toolkit.version import ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION; print(ROLE_AWARE_DASHBOARD_TOOLKIT_VERSION)"
$releaseCommit = (git rev-parse HEAD).Trim()
$releaseStatus = @(git status --porcelain)
if ($releaseStatus.Count -ne 0) { throw "Release requires a clean working tree." }
```

Do not publish until the configured PyPI distribution name is available to the
releasing account, the project metadata contains real public coordinates, and
`SECURITY.md` contains a monitored reporting path.

## Build once

Remove only the repository's local `dist` directory, then build and validate:

```powershell
if (Test-Path -LiteralPath "dist") { Remove-Item -LiteralPath "dist" -Recurse -Force }
py -3 -m build
$distArtifacts = Get-ChildItem -LiteralPath dist -File
$twineArgs = @("-3", "-m", "twine", "check") + $distArtifacts.FullName
py @twineArgs
```

Audit member paths and excluded surfaces:

```powershell
py -3 -c "import pathlib, tarfile, zipfile; from role_aware_dashboard_toolkit.release_audit import audit_release_artifact_members; members=[]; [members.extend(zipfile.ZipFile(p).namelist() if p.suffix == '.whl' else tarfile.open(p, 'r:gz').getnames()) for p in pathlib.Path('dist').glob('*')]; result=audit_release_artifact_members(members); print(result); raise SystemExit(0 if result['ok'] else 1)"
```

## Smoke the local artifacts

Install the wheel from `dist` into a fresh environment. From a temporary
directory outside the repository, confirm:

```powershell
python -c "import role_aware_dashboard_toolkit as radt; registry=radt.ControlRegistry(); registry.register('Limit', kind='number', min_value=1, default=5); run=radt.build_run({'limit': 5}); packet=radt.build_run_packet(run); assert radt.load_packet_json(radt.export_packet_json(packet))['packet_type']=='run'; print(radt.__version__)"
```

Repeat with the source distribution. Install its declared build backend before
using `--no-build-isolation` in an offline smoke environment.

Install and smoke each optional capability independently, then install
`role-aware-dashboard-toolkit[full]`. A pre-publication smoke must use local artifacts, not
`pip install role-aware-dashboard-toolkit` from the public index.

## Verify source did not move

```powershell
$currentCommit = (git rev-parse HEAD).Trim()
if ($currentCommit -ne $releaseCommit) { throw "HEAD changed after the release build." }
$releaseStatus = @(git status --porcelain)
if ($releaseStatus.Count -ne 0) { throw "Working tree changed after the release build." }
```

All later lanes must reuse these exact bytes.

## TestPyPI

```powershell
$distArtifacts = Get-ChildItem -LiteralPath dist -File
$uploadArgs = @("-3", "-m", "twine", "upload", "--repository", "testpypi") + $distArtifacts.FullName
py @uploadArgs
```

Install `role-aware-dashboard-toolkit==$version` from TestPyPI in a clean environment and repeat
the core import/packet smoke. Verify artifact digests against the release
candidate evidence.

## PyPI

Upload the same audited files:

```powershell
$distArtifacts = Get-ChildItem -LiteralPath dist -File
$uploadArgs = @("-3", "-m", "twine", "upload") + $distArtifacts.FullName
py @uploadArgs
```

After upload, install the exact version from PyPI in a clean environment and
repeat the smoke.

## Tag and announce

Create the tag only after the PyPI smoke passes:

```powershell
git tag "v$version" $releaseCommit
git push origin "v$version"
```

Release notes should include the version, artifact names and digests,
verification commands, and known limitations. Confirm the README renders
correctly on PyPI and every announcement link resolves to the real public
project.
