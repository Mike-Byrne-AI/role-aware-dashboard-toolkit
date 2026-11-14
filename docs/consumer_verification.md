# Verify an application built with the toolkit

Build a consumer in its own directory and environment, using an installed toolkit
artifact. Keep application data, credentials and generated verification receipts
outside this public source tree. The installed `guide web` describes presentation
and host integration; `guide workflows` describes protected record changes.

The source distribution includes the dependency-free
[`tools/consumer_evidence.py`](../tools/consumer_evidence.py) helper. It records
explicit source and artifact hashes before a check run, compares those bytes
afterward, and binds supplied JUnit/browser reports to the result. It is a source
tool, not an installed wheel command or a new public library API.

## Define the consumer proof

Choose one useful workflow and verify both its intended result and its denial
boundaries. Include current-role and record-scope checks, revocation after a form
is loaded, frozen writes, stale and repeated submissions, transactional history,
restart persistence and the real browser path. Inspect narrow layouts, keyboard
focus, empty/error states, request links, Back and reload. Cross-tab account
changes must clear old private state and rebuild the current role's interface.

Use disposable fictional accounts and storage. Check that the interpreter imports
the toolkit from the consumer environment's installed distribution, rather than
from this checkout or an editable installation. Separately verify the installed
artifact's identity: hashing a wheel on disk does not prove that Python used it.

## Snapshot before running checks

Run the source helper with an explicit allowlist of all inputs that can affect
the claim: application modules, assets, tests, browser runner, dependency lock and
configuration. Include the toolkit artifact separately. Unlisted files, including
newly added files, are outside the snapshot's scope. Globs and directory recursion
are deliberately unavailable. Never select runtime databases, account sheets,
keys or other private inputs.

For example, from the consumer directory in PowerShell, replace the toolkit path
and file list with this consumer's actual inputs:

```powershell
$proofDir = Join-Path ([System.IO.Path]::GetTempPath()) ("consumer-proof-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $proofDir | Out-Null
$evidenceTool = 'C:\path\to\toolkit\tools\consumer_evidence.py'
python $evidenceTool snapshot --root . --file app.py --file tests/test_app.py --file tools/browser_check.py --file requirements.lock --artifact vendor/toolkit.whl --output (Join-Path $proofDir 'before.json')
```

The snapshot requires a nonempty set of unique project-relative source files.
Absolute paths, traversal, symbolic links and missing/nonregular inputs are
refused. Supply public source paths only; explicit selection is not an automatic
secret detector. Existing outputs are never overwritten.

## Run and retain the checks

Run the consumer's tests with its installed interpreter, for example:

```powershell
.\.venv\Scripts\python.exe -m pytest tests --junitxml (Join-Path $proofDir 'api.xml')
```

The browser runner must exercise the actual host and write its own summary after
the attempt. The helper expects a boolean `passed`, a nonempty list of unique
completed-check labels in `checks`, and a `source_sha256` map identical to the
starting snapshot. A failed or interrupted runner must retain its failure; never
hand-author success to satisfy this contract. Capture browser diagnostics without
credentials, raw private traces or arbitrary exception messages.

The helper reads actual JUnit test cases and refuses empty, failed, errored or
skipped results and inconsistent declared counts. A browser failure, empty check
set or different source map also refuses a passing receipt. Keep execution and
fixture errors distinct from a failed application assertion when diagnosing the
original reports.

Supported JUnit reports use unnamespaced XML with at most 64 levels and 100,000
elements. Namespaced or over-budget reports are refused before aggregation.

## Bind the result afterward

```powershell
python $evidenceTool finish --root . --snapshot (Join-Path $proofDir 'before.json') --junit (Join-Path $proofDir 'api.xml') --browser (Join-Path $proofDir 'browser.json') --output (Join-Path $proofDir 'receipt.json')
```

Source/artifact drift or missing, invalid or unsuccessful reports produce a
failed receipt and a nonzero exit. Receipts retain fixed failure codes and counts
where available, plus report hashes; they omit test names, browser labels, report
contents and absolute local paths. Preserve that receipt and use a new output for
a separate repair. Invalid configuration is refused before a receipt is written.

A passing receipt establishes a bounded comparison of selected bytes and supplied
reports. The helper does not execute tests, authenticate their producer, establish
that the listed tests are adequate, detect every omitted input, or certify the
application. Source/CI results, public hosting, physical devices, human usability
and recovery custody need their own evidence. Do not transfer a consumer's older
results to a changed toolkit or host.
