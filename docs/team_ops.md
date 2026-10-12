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

Store listings and recent-evidence summaries compare ISO timestamps by UTC time,
including explicit offsets and the `Z` suffix. Historical timestamps without a
timezone mean UTC. Undated or malformed timestamps remain visible after dated
records with the existing stable tie ordering.

For governance approval coverage, a later signoff supersedes the same reviewer's
earlier signoff within the same run and checkpoint. A change of role or assignment
does not preserve an identified reviewer's old approval. Signoffs without an
actor use the role as their reviewer identity. Other reviewers and other
run/checkpoint scopes remain independent. When timestamps tie or order cannot be
established, rejection or requested changes takes precedence over positive
coverage; conflicting roles at an unresolved time do not establish coverage.

## Important boundary

Team ops is local-first and file-backed. It is not a cloud coordination service and does not imply real-time synchronization.
