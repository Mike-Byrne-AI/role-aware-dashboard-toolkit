# Operator Review Lab

A complete synthetic workflow: save a baseline profile, adjust AI settings,
capture a candidate, compare outcomes, record a human decision, and hand off
portable evidence. Every number comes from a deterministic teaching formula.
No model is called and these numbers are not performance measurements.

From the repository root, using the development environment:

```powershell
.\.venv\Scripts\python.exe -m streamlit run examples/operator_review/app.py --server.address 127.0.0.1
```

Run from the repository root so the `examples.operator_review` imports resolve.
Install the optional workbench dependencies first, as described in
[CONTRIBUTING.md](../../CONTRIBUTING.md). Nothing is written to disk by the app;
profiles, audit history, runs and review records last for the browser session.
Explicit downloads save a copy through the browser.

1. Use Admin or Operator and click **Save baseline and start run**. This saves a
   named profile and a checkpoint containing settings and simulated metrics.
2. Change Model tier, Response limit, Temperature or Use reference material.
   Click **Capture candidate for review**. Compare recorded metric deltas,
   units, sample times and changed settings. Later live edits do not alter the
   evidence being reviewed.
3. Switch the sidebar role to Approver. Enter a demo reviewer name, choose
   approved, changes_requested or rejected, add a reason, and save the decision.
   This completes the review run and creates a checkpoint-linked signoff and
   handoff. Completion does not imply approval or deploy anything.
4. Download JSON evidence or a standalone readable HTML report. The latter
   needs no Python installation. A saved JSON run packet can also be uploaded
   to the read-only reader to generate another report; upload never restores
   settings or adds records to the active session.

The sidebar Profiles menu can restore the saved baseline. Selecting it previews
the effective changes; click Load to apply them. Restoring live controls does
not rewrite captured checkpoints or a completed review.

Convert a saved packet without running the dashboard:

```powershell
.\.venv\Scripts\python.exe -m examples.operator_review.report run.json review.html
```

The converter refuses to overwrite an existing output file and limits input to
2 MiB. It renders the supplied record without verifying exported identities or
the truth of its claims. Host applications remain responsible for authorization
and omitting sensitive values before export.

Viewer can inspect settings and comparisons, but cannot see reviewer names,
review notes or decisions, change controls, or record decisions. Review display
and signoff both require `can_view_team_ops`; signoff additionally requires its
write permissions. A new baseline clears the previous review form.
Turning **Controls Writable**
off blocks all workflow writes, including signoff; read-only export remains
available to authorized roles. Actions recheck permissions and freeze state in
the workflow functions, independently of disabled buttons. Role selection and
typed names are demonstrations of policy, not authentication or independent
reviewer identity. A shared host must supply trusted identity and durable stores.

`workflow.py` composes existing toolkit controls, profiles, runs, team records
and packets. Replace `simulate_metrics` with an application-owned evaluation
only after defining its data, permissions and side effects. The invented formula
increases simulated quality, latency and cost with the model tier; longer
responses increase latency/cost and add a capped quality increment. Reference
material adds a fixed increment, and distance from temperature 0.3 subtracts
quality points. These relationships demonstrate a tradeoff, not real model behavior.

The run packet preserves the toolkit run payload. Example-specific review data
lives in `meta.operator_review`: `simulation`, `assignments`, `signoffs` and
`handoff`. `report.py` validates the packet and renders escaped, read-only HTML.

To evaluate usefulness, ask two people unfamiliar with the toolkit to complete
the exercise independently. One captures a baseline and candidate; the other
reads the report and explains which settings changed, how the simulated
outcomes differ, who recorded the decision, and whether it was approved. Success
means both can finish without editing toolkit code or consulting raw JSON.
Record points of confusion before adding more workflow features; this exercise
has not yet established external adoption or a development-time saving.

Focused regression checks:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_operator_review_example.py -q
```
