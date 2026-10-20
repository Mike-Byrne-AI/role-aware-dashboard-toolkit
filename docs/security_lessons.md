# Security lessons for dashboard hosts

The [business example](../examples/business_dashboard/README.md) exercises RADT
against anonymous submissions, private employee work and administrator actions.
These lessons belong to host design and review; they do not add a login provider,
content classifier or deployment service to the toolkit's public API.

## Recheck permission when an operation happens

A hidden button is only presentation. Resolve the current session, current role
and current freeze state at each protected read and write. Put authorization,
revision comparison, business mutation and its audit record in one transaction
when they share a store. Test an already-open session after revocation or a role
change, including an employee session whose user later becomes an administrator.
New privilege must not inherit an authentication level it never established.

## Keep incident containment available during a pause

A blanket write freeze can prevent removal of a harmful published post. Define
narrow host operations for unpublishing, revoking access and resuming work.
These still require current administrator authority and request protection.
They must not become a general edit route with a freeze exception: an unpublish
request changes only publication state, checks the revision and records an audit
entry. It cannot edit text, approve a submission or republish a draft.

RADT's normal shared-freeze behavior remains unchanged. The host deliberately
models containment separately. Test both the allowed containment action and
the surrounding ordinary writes that must stay blocked.

## Separate permission, moderation and bot protection

Public input belongs in a private pending queue. Only an authorized review
transaction can publish it. Reject extra request fields, escape untrusted text
in both the public view and the moderator's view, and keep staff records out of
public response projections. Approval and publication must commit together.

Published rules and a required acknowledgment state expectations; they do not
detect scams, discriminatory content or cleverly disguised abuse. Administrators
must judge meaning and context, and need a reliable takedown action afterward.
A CAPTCHA or bot challenge likewise does not establish that content is allowed.

CSRF/origin validation protects browser sessions against cross-site requests.
It is not a spam control: an automated client can set an Origin header. Apply
bounded inputs, submission quotas and a queue cap on the server. Perform cheap
pause/quota checks before contacting a challenge provider, then repeat them
atomically before inserting; never hold a database write lock during a network
call. Global limits protect capacity but can also let an attacker deny service
to legitimate visitors. Monitor queue saturation and provide a pause procedure.

For external challenges, require server verification of the returned token,
expected hostname and action. Fail closed on missing, malformed, expired or
failed responses. Bound the provider timeout and response size. Reject test
credentials on public hosts. A rendered widget or a mocked response is not
proof that the real provider configuration works.

Exercise the required-challenge browser path separately from a loopback demo
that disables challenges. Loading the provider script successfully does not
prove that its initialization API was used correctly. For asynchronous
Turnstile loading, use its documented `onload` callback; `turnstile.ready()`
rejects an asynchronous script. Test load failure and retry, retained form text,
expiration and late callbacks after a dialog closes. Keep submission disabled
until both rules agreement and a current verification token are present.

## Make stronger login affect existing sessions

Requiring an authenticator code only on a login form leaves old administrator
sessions untouched. Track the authentication generation on the server and revoke
older sessions during enrollment, reset and migration. Consume each accepted
TOTP time step transactionally to reject replay and simultaneous use. Limit
attempts for wrong codes as well as wrong passwords. Keep recovery as a trusted
operator action; do not expose a password-only MFA reset endpoint.

TOTP mitigates password theft but can still be phished. Use an organization's
identity provider and phishing-resistant authentication when that risk warrants
it. Secrets, enrollment sheets, session cookies and backups require private
storage. Screenshots, browser traces and exception messages can expose them too;
use disposable accounts and sanitized diagnostics in automated checks.

Close SQLite connections explicitly in test and operator helpers. A connection's
context manager commits or rolls back transactions but does not close the file;
use an explicit close or `contextlib.closing`. On Windows, an open connection
can prevent private temporary-data cleanup and hide the original test failure.

## Verify persistence and the actual host separately

Apply schema upgrades transactionally and preserve existing records and identity
keys. Test failed upgrades and recovery without deleting the workspace. Before
reopening a restored backup, reconcile revocations, MFA enrollment generations
and sessions; an old backup can revive access previously removed.

Forwarded IP headers are attacker-controlled until a verified ingress replaces
them and the origin cannot be reached around that ingress. Ignoring these
headers is safe against spoofing, but can put all proxied visitors into one rate
bucket. Verify the actual proxy before changing this trust decision.
An external bot verifier's optional visitor-IP field must not be populated
with the proxy's socket address. Omit it when visitor identity is unverified;
do not weaken forwarding-header trust to make a provider request look complete.

Managed persistent disks may be absent during builds and pre-deploy commands.
If the operator needs a running instance to provision storage, provide a separate
maintenance-only listener. It must serve no application data, create no accounts
and never switch automatically into the application. Explicit provisioning and
a later start-command change keep missing storage from becoming a reseed path.
Normal startup must refuse missing or unsupported state before binding a port.

Local tests establish local behavior. Hosted CI, HTTPS cookies, DNS, bot-service
credentials, direct-origin access, private disk ownership, restart and restore
need their own evidence. Adding an example dependency also requires its runtime
audit lane; it must not silently escape checks of the toolkit's normal extras.

## Executable references

- Business authorization and moderation: `tests/test_business_dashboard.py`
- Administrator MFA and containment: `tests/test_business_admin_mfa.py`
- Challenge and posting-policy checks: `tests/test_business_abuse.py`
- Hosted startup and storage checks: `tests/test_business_hosting.py`
- [Real-browser workflow](../tools/business_dashboard_browser.py)
- CI dependency-lane contract: `tests/test_landscaping_dependency_lane.py`

The test files are available in the repository checkout, not the source archive.

Provider references: [Cloudflare server validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
and [PyOTP security guidance](https://pyauth.github.io/pyotp/).
