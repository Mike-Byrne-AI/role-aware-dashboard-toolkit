# Security Policy

Role-Aware Dashboard Toolkit treats authorization, sensitive values, and
persistence integrity as part of its public library contract.

## Reporting-channel status

This local release candidate does not yet publish a verified, monitored
security-reporting contact. No reporting address or response-time commitment
is claimed here.

Pre-OSS release state remains blocked on `oss_public_coordinates` and
`security_intake_contact` until real public project URLs and a monitored public
security reporting contact are documented. A maintained reporting channel and
response expectations must be established before publication.

## Reporting guidance

Do not disclose credentials, personal information, or exploitable details in
public issues. Once a verified reporting channel is available, include:

- the affected version and relevant configuration;
- the security impact and required access;
- minimal reproduction steps and supporting evidence;
- any suggested mitigation, without including real secrets.

Security fixes should include a regression test and coordinated disclosure
appropriate to the affected users.

## Deployment responsibilities

Dashboard roles are authorization context, not authentication. Shared
deployments must bind roles to trusted identities and provide appropriate
network, transport, and storage security. Plugins execute as trusted code in
the host process. See [API security](docs/api_security.md) and
[architecture scope](ARCHITECTURE_SCOPE.md) for these boundaries.
