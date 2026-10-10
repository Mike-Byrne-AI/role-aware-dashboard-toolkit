# Governance model

Role-Aware Dashboard Toolkit governance records turn case state into explicit admissibility review.

## What governance covers

- policy checks with pass, warn, fail, or waived outcomes
- derived severity and escalation level
- approval requirements
- blocked actions and allowed next actions
- case-linked history over time

Native incident statuses `open`, `monitoring`, and `mitigated` remain unresolved
until explicitly marked `closed`, matching operator-memory summaries. They block
case closure and remain subject to incident severity checks. Mitigation alone
does not close an incident. Allowed next actions exclude every blocked action,
including when an otherwise admissible case still has unresolved incidents or
missing approvals. These records provide review guidance; hosts must enforce
their actual action permissions.

## View and write model

Governance is now preview-first.
The governance panel builds a preview record, validates it, and only persists it when an operator explicitly saves it.

Recommended permissions:

- `can_view_governance`
- `can_manage_governance`
- `can_export_packets`

Governance permissions are explicit. Missing permission keys fail closed; run
and team permissions do not imply governance access.

The native governance panel also requires `can_view_decisions`, including when
the decision store has been removed: saved governance can still contain derived
decision evidence. Denied, unreadable or invalid evidence blocks the preview
and save action with a generic notice. It is not evaluated as an empty set of
decisions or incidents. Restore permission or repair the evidence and retry;
historical store diagnostics alone do not block a successful retry. Optional
stores that were never configured retain their intentional empty-input behavior
when the case does not require records from them. Explicit linked decisions,
incidents, notes, narratives, checkpoints and runs must resolve to readable, valid records;
an identifier alone is not evidence. Decision links work independently of run
links, so a rejected decision linked only by its identifier still blocks review.

Evidence links are additive. A run link includes its decision and signoff
records; a checkpoint-only link includes those records for that checkpoint.
Explicit decision links add records to that scope rather than replacing it.
Adding an approved decision link therefore cannot conceal a rejected decision
from an already linked run. To review a narrower scope, link the relevant
checkpoints or decisions without linking the entire run.

## Common flow

1. Select a case.
2. Preview the derived governance summary.
3. Inspect policy checks and blocked actions.
4. Save the governance snapshot explicitly if it should become durable review state.

Governance persistence stays explicit: preview and packet export can happen without saving, and audit logging of those events does not enqueue hidden governance execution.

## Record shape

A governance record links to one case and can reference runs, decisions, and incidents.
It captures:

- `state`
- `severity`
- `escalation_level`
- `policy_checks`
- `approval_requirements`
- `blocked_actions`
- `allowed_next_actions`
- `history`

See `schemas/governance.schema.json` for the workbench schema snapshot.
