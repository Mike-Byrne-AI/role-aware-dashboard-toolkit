# Security Policy

Role-Aware Dashboard Toolkit treats authorization, sensitive values, and
persistence integrity as part of its public library contract.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting for this repository:

Report a vulnerability at
<https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/security/advisories/new>.

Maintainers use private reports to assess vulnerabilities and coordinate
fixes and disclosure. If the private form is unavailable, open an
[issue](https://github.com/Mike-Byrne-AI/role-aware-dashboard-toolkit/issues)
asking only for a private contact channel. Wait for a maintainer to arrange
that channel before sharing any vulnerability details.

Do not disclose credentials, personal information, or exploitable details in
public issues. In a private vulnerability report, include:

- the affected version and relevant configuration;
- the security impact and required access;
- minimal reproduction steps and supporting evidence;
- any suggested mitigation, without including real secrets.

Security fixes should include a regression test and coordinated disclosure
appropriate to the affected users.

## Deployment responsibilities

Demo dashboard roles do not authenticate users. The optional authenticated mode
binds verified OIDC identity to explicit server-owned grants and shared freeze.
Shared deployments must configure the provider and grants, and provide appropriate
network, transport, and storage security. Plugins execute as trusted code in
the host process. See [API security](docs/api_security.md) and
[architecture scope](ARCHITECTURE_SCOPE.md) for these boundaries.
