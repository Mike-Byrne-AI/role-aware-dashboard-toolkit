# Westbridge security design and review map

Westbridge is a fictional security testbed on the existing hosted service. Its
purpose is to make security decisions inspectable and exercise their failure
paths. This dossier describes source contracts and named regression tests;
it is not a test receipt, deployment report or security certification.

`[verified/source]` below means the cited implementation contains the described
control. Execution results require a receipt for the exact source and environment.
Regression and CI paths below refer to the full repository checkout; the source
distribution does not ship those test or workflow files.
Read [SECURITY_LAB.md](SECURITY_LAB.md) for exercises and
[HOSTING.md](HOSTING.md) for operator acceptance.

## Assets, adversaries and trust boundaries

Protect authentication secrets, bearer sessions, current permissions, private
staff records, publication decisions, recoverable data and trustworthy evidence.
The modeled adversaries are anonymous internet clients, malicious or revoked
staff accounts, callers holding a stolen session, and operators making mistakes
during restart, recovery or deployment. Database-only disclosure is modeled;
complete compromise of the running host is outside the encryption boundary.

```mermaid
flowchart LR
  subgraph Untrusted[Untrusted clients]
    B[Browser or direct HTTP client]
    A[Device authenticator]
    B <-->|WebAuthn ceremony| A
  end
  subgraph Host[Host application boundary]
    P[HTTPS ingress and proxy]
    R[Origin, body and admission checks]
    C[Current identity, grants, freshness and revisions]
    D[(Private SQLite data, sessions and security events)]
    K[Independent MFA key and identity key]
    P --> R --> C --> D
    K --> C
  end
  B --> P
  T[Turnstile provider] <-->|Server-verified submission challenge| R
  O[Trusted offline operator] --> M[Backup, reconciliation and key rotation]
  M --> D
  M --> K
  L[Disposable local scenario and browser runners] --> E[Sanitized receipt]
  E --> S[Public read-only security evidence view]
```

The diagram expresses required boundaries, not proof of current ingress settings.
The operator selects an existing sanitized receipt with
`BUSINESS_SECURITY_EVIDENCE_FILE`; `/security-lab` and `/api/security-lab` only
read it. There is no public scenario runner, file upload or recovery endpoint.
The private event timeline requires current administrator authority.

| Threat | Enforced invariant and source | Decisive regression |
| --- | --- | --- |
| Client invents a role or uses another account's object | Current identity and grants control the operation; display roles and object identifiers confer no authority. [security.py](business/security.py), [app.py](business/app.py) | Adversarial access (`tests/test_business_adversarial_access.py`): every admin route denies untrusted roles; caller-supplied authority fields fail. |
| Revocation races a request or expensive verification | Check current state again at commit. A request admitted before a completed revocation is a distinct concurrency ordering. [auth_routes.py](business/auth_routes.py), [passkeys.py](business/passkeys.py) | Access races (`tests/test_business_adversarial_access.py`), credential races (`tests/test_business_passkeys.py`). |
| Stolen session performs sensitive administration | Idle activity does not renew the five-minute verification window. Containment remains available; restoring authority requires fresh verification. [session_state.py](business/session_state.py) | Sessions (`tests/test_business_sessions.py`): stale writes denied, pause allowed, resume challenged, draft retained in [browser checks](../../tools/business_dashboard_browser.py). |
| Lost response or stale editor repeats/overwrites work | Host create receipts and revision checks preserve the intended operation. Toolkit shared-state compare-and-set rejects a competing revision. [idempotency.py](business/idempotency.py), [state store](../../role_aware_dashboard_toolkit/state_store.py) | Host retries (`tests/test_business_idempotency.py`), API concurrent state (`tests/test_api_state_store.py`). |
| Old backup resurrects revoked authority | A restore stays quarantined unless reconciled with a trusted current security source; all restored sessions are revoked. [backup.py](backup.py) | Backup recovery (`tests/test_business_backup.py`), [scenario runner](../../tools/business_security_demo.py). |
| Security recording or delivery fails | Required mutation events and delivery obligations share the transaction. Delivery retries use stable IDs; the business action is not replayed. [security_events.py](business/security_events.py) | Event failures and crash windows (`tests/test_business_security_events.py`). |
| Rotation fails halfway or a worker retains its old key | Enrollment ciphertext and key binding change together; original key files remain; each runtime transaction checks its cached key against current binding. [rotation CLI](rotate_mfa_key.py), [db.py](business/db.py) | Rotation (`tests/test_business_mfa_rotation.py`): row/binding faults, real process exit, stale workers and old-backup recovery. |

## Decisions and their limits

- **Server authority is current and transactional.** `[verified/source]`
  Westbridge evaluates session, permission, freeze and revision in its SQLite
  transaction. The generic toolkit API can use separate access, state, profile
  and audit adapters. It does not make those stores one atomic transaction.
  In particular, an API state operation can commit before an audit adapter fails;
  the response reports that outcome and must not cause blind retry. See
  [API security](../../docs/api_security.md) and
  committed-operation audit failures (`tests/test_api_audit_failures.py`).
- **Authentication methods have different assurance.** `[verified/source]`
  Administrators may use password plus TOTP or a user-verified passkey; employees
  also have password-only sign-in. Recovery is a trusted offline operator action.
  Passkey challenges are one-use and origin/RP-bound, but no device attestation
  proves hardware provenance. A stolen bearer cookie still has authority until
  expiry/revocation; adding passkeys does not remove weaker fallback paths.
- **Containment remains available.** `[verified/source]` Pausing edits,
  unpublishing and disabling an account are narrow operations, not permission to
  edit arbitrary records during a freeze. Session inactivity expires after
  30 minutes and absolute lifetime after eight hours; reads do not renew fresh
  verification. At most eight sessions are kept per account, with oldest excess
  sessions removed on sign-in. These are testbed policy choices.
- **Availability has an explicit budget.** `[verified/source]` Account attempt
  budgets persist; expensive work has bounded per-process admission. A targeted
  attacker can exhaust a known account's budget, and shared proxy peers can share
  public-submission limits. These controls do not promise sustained-load
  availability or configured edge protection. See [abuse exercises](SECURITY_LAB.md#abuse-decisions-and-availability).
- **Logging has separate guarantees.** `[verified/source]` Activity history,
  aggregate counters and durable security events are different records. Required
  events fail the associated mutation if they cannot commit. Denial observations
  have a bounded budget; suppressed observations and recording failures remain
  visible in counters. The outbox uses at-least-once delivery to a local
  idempotent consumer. It is not an off-host archive or a tamper-proof log.
  A lifespan-owned worker attempts at most 100 local deliveries per cycle, with
  five-second waits between cycles; protected status reports progress and failures. Pending
  obligations are retained; capacity exhaustion can still refuse sensitive work.
  Ordinary admission keeps retained events plus usable employee sessions within
  9,000 slots. Each such session reserves its eventual termination receipt; only
  a verified removal of an owned session may consume that reservation. The final
  1,000 slots remain administrator authentication/containment headroom, and
  administrator actions preserve employee reservations. Existing overfull state
  reports a reservation deficit and needs draining before these guarantees apply.
  This is finite headroom, not unlimited availability; an offline operator can
  drain an exhausted queue if automatic delivery cannot recover it.
- **Key custody and recovery are operational work.** `[verified/source]`
  MFA encryption protects database-only disclosure. A host able to read both key
  and database can decrypt seeds. Rotation does not erase already exposed seeds,
  old pages or backups. Identity-key migration is separate and unsupported by
  the MFA rotation command. Old-before-rotation backup tests use the same current
  schema. An explicit `restore --upgrade-backup-schema` can also upgrade a
  validated schema-five archive only in private restore staging; current schema-six
  authority is still required to leave quarantine. The original archive stays unchanged.
  See `tests/test_business_backup_schema_upgrade.py`.

## Selected OWASP ASVS 5.0.0 review map

These versioned IDs reference the pinned official release, not changing branch
content. The map selects review targets; it does not establish an ASVS level or
complete coverage. Requirement descriptions below are abbreviated. Primary
references: [Authentication](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x15-V6-Authentication.md),
[Sessions](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x16-V7-Session-Management.md),
[Authorization](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md),
[Logging and errors](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md).

| Requirement | Source and targeted test evidence | Review scope or gap |
| --- | --- | --- |
| `v5.0.0-6.2.3` Current password for password changes | [auth_routes.py](business/auth_routes.py); password policy (`tests/test_business_password_policy.py`), `test_current_password_is_checked_before_choice_screening` | Current-password proof is separate from password-quality screening. |
| `v5.0.0-6.3.1` Controls against password attacks | [auth_routes.py](business/auth_routes.py), [work_limits.py](business/work_limits.py); authentication limits (`tests/test_business_auth_limits.py`) | Local durable budgets and admission; edge configuration and calibrated hosted load require their own evidence. |
| `v5.0.0-6.5.1` Single use of TOTP | [mfa.py](business/mfa.py); admin MFA (`tests/test_business_admin_mfa.py`), `test_simultaneous_admin_logins_consume_code_once` | Transactionally consumed server-side counter; separate from physical-device proof. |
| `v5.0.0-7.4.1`, `v5.0.0-7.4.2` Session termination and disabled accounts | [security.py](business/security.py), [session_routes.py](business/session_routes.py); sessions (`tests/test_business_sessions.py`), adversarial access (`tests/test_business_adversarial_access.py`) | Rejection at the next protected request is the acceptance observation. |
| `v5.0.0-7.5.2`, `v5.0.0-7.5.3` Session management and sensitive-operation verification | [session_state.py](business/session_state.py), [session_routes.py](business/session_routes.py); sessions (`tests/test_business_sessions.py`) | Own-session inventory and revocation, five-minute freshness; containment exceptions are deliberate. |
| `v5.0.0-8.2.1`, `v5.0.0-8.3.1` Trusted enforcement of function access | [app.py](business/app.py), [security.py](business/security.py); admin route matrix (`tests/test_business_adversarial_access.py`) | Every sensitive route needs inventory coverage; hidden UI controls are not the boundary. |
| `v5.0.0-16.2.5` Protect sensitive data in logs | [security_events.py](business/security_events.py); event field rejection (`tests/test_business_security_events.py`), `test_fixed_fields_refuse_secret_content_and_unverified_identity` | Fixed codes and opaque principals; actual host/proxy logging must be inspected separately. |
| `v5.0.0-16.3.1`, `v5.0.0-16.3.2` Authentication/authorization event coverage | [security_events.py](business/security_events.py); denial budgets (`tests/test_business_security_events.py`) | **Partial:** bounded denial suppression means this is not a complete record of every attempt/decision. |
| `v5.0.0-16.5.3` Secure failure behavior | [db.py](business/db.py), [security_events.py](business/security_events.py); event rollback (`tests/test_business_security_events.py`), rotation interruption (`tests/test_business_mfa_rotation.py`) | Targeted host transaction coverage, not a guarantee for every adapter or exception. |

Other explicit differences from the selected standard: employee password-only
fallback does not meet `v5.0.0-6.3.3`'s general MFA expectation; in-session
reverification preserves the bearer token rather than rotating it as
`v5.0.0-7.2.4` requires; no separate logging system supplies
`v5.0.0-16.4.3`. The fictional provisioned `admin` account and non-expiring initial
credentials also require separate review under `v5.0.0-6.3.2` and
`v5.0.0-6.4.1` before treating this as a production identity system. These are
recorded boundaries, not claims of exemptions or compliance.

## From source to a demonstrable result

1. **Identify tested bytes.** [evidence.py](business/evidence.py) fingerprints a
   defined code/assets/configuration/test set and records Git identity/dirty state,
   runtime versions, UTC times and local scope. A source-changing run fails.
   The [scenario runner](../../tools/business_security_demo.py) uses disposable
   data for revocation, competing toolkit edits and reconciled recovery. The
   [browser runner](../../tools/business_dashboard_browser.py) emits a sanitized
   receipt alongside private diagnostics. Test definitions alone are not results.
2. **Display the boundary.** [security_lab.py](business/security_lab.py) serves
   operator-supplied observations. Missing, failed, stale and unavailable evidence
   remain distinguishable. Receipt checksums detect changes, not dishonest authors.
   A source snapshot is cached per serving process: restart after code changes.
   Receipt tests (`tests/test_security_evidence.py`) and
   public-view tests (`tests/test_business_security_lab.py`) enforce the safe
   projection. Raw credentials, paths, screenshots and exceptions stay private.
3. **Bind builds and dependencies.** Contributor CI (`.github/workflows/contributor-ci.yml`)
   uses SHA-pinned actions and multiple Python/OS lanes.
   Dependency audits (`.github/workflows/dependency-audit.yml`) retain exact
   resolved inventories and scanner outcomes for seven days.
   Release CI (`.github/workflows/ci.yml`) binds artifact hashes to source and
   workflow identity. None proves that a specific hosted process runs those bytes.
4. **Accept the existing hosted testbed.** Follow [HOSTING.md](HOSTING.md) to match
   the deployed revision/configuration, verify actual HTTPS/proxy behavior,
   exercise a real-device passkey session and reconcile a recovery cutover.
   Preserve successes, failures and not-run work with their environment. Local
   virtual authenticators, synthetic identity adapters and receipt imports cannot
   substitute for these observations.

A standard SBOM and signed build attestation could extend this chain later.
They are not generated by this dossier or implied by dependency-audit inventories
and checksums. A curated showcase evidence pack should retain the reviewed
receipts beyond transient CI retention without publishing private diagnostics.
