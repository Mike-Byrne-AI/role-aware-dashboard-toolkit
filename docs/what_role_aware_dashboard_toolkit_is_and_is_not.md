# What Role-Aware Dashboard Toolkit is and is not

Role-Aware Dashboard Toolkit is a Python library for building operator dashboards with
explicit controls, policy, profiles, audit history, plugins, operational
records, and exportable evidence.

## Role-Aware Dashboard Toolkit is

- a typed control registry and optional Streamlit renderer
- a small role-policy layer for application-supplied identities
- profile and audit infrastructure with sensitive-value handling
- a trusted plugin lifecycle with visible failure diagnostics
- a local-first run, checkpoint, compare, ledger, and replay model
- a neutral JSON packet envelope for application records
- optional FastAPI and pandas-backed presentation capabilities

## Role-Aware Dashboard Toolkit is not

- an identity provider or authentication system
- a secret manager
- an autonomous action executor
- an application-specific integration framework
- a distributed workflow engine or database
- a substitute for network, deployment, or storage security

## The boundary in practice

Your application owns identity, business policy, data sources, and external
side effects. Role-Aware Dashboard Toolkit owns the reusable dashboard primitives around those
decisions.

Plugins are trusted code loaded into the host process. Replay objects are
previews built from recorded state. Packets are evidence envelopes, not commands.
File stores target trusted local or mounted storage and surface diagnostics
instead of claiming distributed transaction semantics.

Keeping that boundary sharp makes the library useful across applications
without turning it into the face or runtime of any one product.
