# Security Policy

Role-Aware Dashboard Toolkit treats authorization, sensitive values, and
persistence integrity as part of its public library contract.

## Beta support and updates

During the beta, security fixes target the latest published beta release.
Older versions and development snapshots have no backport commitment. Release
notes identify affected versions and migration steps when a security fix needs
operator action. There is no guaranteed response time or security certification.

Operators should follow repository releases and security advisories, retain a
record of the installed artifact and resolved dependencies, and test upgrades
in a separate environment before switching a shared dashboard. Keep a protected
backup and a tested recovery path; an older artifact may remain vulnerable even
if rolling back would restore functionality. Dependencies and the identity
provider require their own updates as well as toolkit updates.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting for this repository:

Report a vulnerability at
<https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/security/advisories/new>.

Maintainers use private reports to assess vulnerabilities and coordinate
fixes and disclosure. If the private form is unavailable, open an
[issue](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/issues)
asking only for a private contact channel. Wait for a maintainer to arrange
that channel before sharing any vulnerability details.

The private form must be enabled and checked when the repository is made public.
Maintainers must also verify the intended account's security notification
settings. A link in this document does not establish that reporting is live,
that a notification was delivered, or that somebody has read a report.

Do not disclose credentials, personal information, or exploitable details in
public issues. In a private vulnerability report, include:

- the affected version and relevant configuration;
- the security impact and required access;
- minimal reproduction steps and supporting evidence;
- any suggested mitigation, without including real secrets.

Security fixes should include a regression test and coordinated disclosure
appropriate to the affected users.

If you have a fix for a suspected vulnerability, report it privately first.
Coordinate with maintainers before opening a public pull request or publishing
reproduction details.

## Deployment responsibilities

Demo dashboard roles do not authenticate users. The optional authenticated mode
binds verified OIDC identity to explicit server-owned grants and shared freeze.
Shared deployments must configure the provider and grants, and provide appropriate
network, transport, and storage security. Plugins execute as trusted code in
the host process. See [API security](docs/api_security.md) and
[architecture scope](ARCHITECTURE_SCOPE.md) for these boundaries.
