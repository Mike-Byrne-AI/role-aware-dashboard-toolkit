# Governance model

Role-Aware Dashboard Toolkit governance records turn case state into explicit admissibility review.

## What governance covers

- policy checks with pass, warn, fail, or waived outcomes
- derived severity and escalation level
- approval requirements
- blocked actions and allowed next actions
- case-linked history over time

## View and write model

Governance is now preview-first.
The governance panel builds a preview record, validates it, and only persists it when an operator explicitly saves it.

Recommended permissions:

- `can_view_governance`
- `can_manage_governance`
- `can_export_packets`

Governance permissions are explicit. Missing permission keys fail closed; run
and team permissions do not imply governance access.

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
