# Team Ops

Role-Aware Dashboard Toolkit provides a local-first team-ops layer on top of the runbook and protocol layers.

## Included records

- comments
- review assignments
- signoffs
- handoff summaries

## Intended use

Use team ops when a run needs explicit human review, traceable signoff, or shift handoff notes.

## Core pattern

1. Operator starts a run and creates checkpoints.
2. Approver or lead assigns a review against the active run or latest checkpoint.
3. Reviewer leaves comments and optionally signs off.
4. Operator or admin creates a handoff summary for the next person or shift.

## Important boundary

Team ops is local-first and file-backed. It is not a cloud coordination service and does not imply real-time synchronization.
