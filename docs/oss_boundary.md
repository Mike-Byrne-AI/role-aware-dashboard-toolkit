# Public distribution boundary

This document defines the supported Role-Aware Dashboard Toolkit distribution.
The source distribution includes public documentation and fixture-free examples.
It does not include product-specific adapters or application integrations.

## Included

The library includes:

- controls, dashboard configuration, and optional Streamlit rendering;
- security contexts, roles, and explicit permission helpers;
- profiles, audit history, and their in-memory and file stores;
- trusted plugin contracts and lifecycle diagnostics;
- runtime diagnostics and telemetry normalization;
- runs, checkpoints, comparisons, ledgers, and replay previews;
- neutral packet envelopes, validators, and protocol metadata;
- local operator records and stores;
- optional FastAPI and pandas capabilities;
- public documentation and standalone examples.

## Application boundary

Host applications own authentication, business policy, external actions, and
deployment security. Application-specific adapters and data do not belong in
the reusable library. Credentials and private endpoints must not appear in
public documentation, examples, or artifacts.

## Public API

The package root exposes the bounded convenience surface listed in
[public_api.md](public_api.md). Specialist APIs remain available from their
owning modules without expanding `role_aware_dashboard_toolkit.__all__`.
Documented use cases and contract tests define supported behavior.

## Artifact policy

The wheel contains the importable library and required package metadata. The
source distribution also contains public project files, documentation, and
selected examples. Both artifacts exclude:

- tests and fixtures;
- private records and internal maintenance data;
- cache, coverage, temporary, and generated report files;
- local build output and stale distribution artifacts;
- application-specific adapters and local datasets.

Release audit helpers reject unsafe member names and excluded paths. Inspect
the actual wheel and source distribution before publication.

## Publication gates

The GitHub-source release channel requires:

- configured repository, issue tracker, documentation, and homepage URLs;
- a source-repository identity matching the Python distribution;
- a documented private vulnerability reporting policy;
- complete tests, coverage, and lint verification;
- generated public API, distribution, and release-audit references in sync;
- separate complete wheel and source-distribution member audits;
- isolated installation checks for the core and optional capabilities.

Those local configuration checks do not establish live readiness. The launch
also requires live repository and branch-protection checks, hosted CI for the
final SHA, and public URL and security-reporting activation checks. Notification
configuration does not prove report delivery or human monitoring.

Package-index publication is a separate future task; this channel does not
verify or claim PyPI ownership, reservation, or publishing rights. Until the
applicable launch checks pass, artifacts remain release candidates.
