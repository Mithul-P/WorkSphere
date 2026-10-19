# Verification record

Verified locally on 19 October 2026. This records observed checks, not a production audit or a claim that every requested scenario has exhaustive coverage.

| Check                       | Observed result                                                                                       |
| --------------------------- | ----------------------------------------------------------------------------------------------------- |
| TypeScript strict typecheck | Passed for API and web                                                                                |
| ESLint                      | Passed                                                                                                |
| Production build            | Passed for API and web                                                                                |
| Real database suite         | 73 tests passed across ten files on embedded PostgreSQL 16.14                                       |
| Coverage, API source        | Statements 85.65%; branches 74.61%; functions 88.63%; lines 87.60%                                    |
| npm dependency audit        | Zero known vulnerabilities after dependency updates                                                   |
| RLS removal proof           | Removing projects RLS exposed four rows without context; rollback restored the deny-by-default result |
| Playwright Chromium demo    | Passed: login, task update, cross-tenant 404, Inspector and Viewer API denial                         |
| Docker Compose              | Files supplied; Docker CLI is installed but the Docker Desktop Linux daemon was unavailable           |
| GitHub Actions / Gitleaks   | Workflow supplied; remote CI and Gitleaks not executed locally                                        |

Coverage excludes seed, migration and server entrypoint files. It does not measure frontend coverage. The statement target exceeds 80%; branch coverage remains below 80%. Coverage counts are not equivalent to security guarantees.

## Security extension phases

- Phase 7: new tenant tables, composite references, forced RLS, immutable tenant IDs, readonly secret-column restrictions, and db:audit. Audit passes; an intentionally unprotected throwaway table makes the audit fail. Application DDL and pg_authid access fail.
- Phase 8: multipart validation, safe storage paths, content policy/ACLs, SQL-filtered lists, versions, soft deletion and authenticated downloads. Tests cover foreign-company 404s, cross-company grants, expired/revoked ACLs, Viewer ceilings, quarantine, tampering, oversized/spoofed/empty uploads and quota denial. Traversal and symlink tests pass. Project grants deliberately fail closed because project membership does not exist.
- Phase 9: tenant envelope encryption, fresh nonces, different-tenant decryption failure, copy-on-write rotation and durable jobs. Operator offboarding/restore is tested with a newly generated disposable tenant: export, remove the live DEK, restore using a new DEK, verify the restored file and reject the original ciphertext under the new key.
- Phase 10: one-time API keys, HMAC storage, scopes, service-principal ACLs, restricted-content denial, expiry, revocation, IP rules, rotation grace and rate limits. Bearer requests do not create browser sessions; administration routes reject keys.
- Phase 11: database row quotas, storage policy, safe Explorer datasets, ACL-filtered content rows/counts and formula-safe CSV. Non-Admins and unsafe sort identifiers are rejected; injection strings remain data. Optional custom fields are not implemented.
- Phase 12: Content Library, sharing, API Keys, Data Explorer, policy controls and Inspector additions. Chromium verified the base work flow and Alice/Bob/Carol/Dave confidential-sharing flow, cross-company 404, Viewer controls, Inspector activity and Explorer. Desktop/mobile screenshots were inspected. Production builds and lint pass.

These are local observations, not a remote CI result. The CI workflow now runs db:audit and the expanded suites. Scanning, process-local rate counters, worker crash cleanup, external storage and other operational limits are documented in SECURITY_EXTENSION.md.

## What the tests prove

- Application DB role is not a table owner, superuser or BYPASSRLS role.
- No-context reads return zero projects. Other-company rows are invisible and cross-company inserts fail RLS checks.
- Forty alternating concurrent transactions preserve tenant context; connection reuse does not leak it.
- Composite tenant/project task foreign key rejects cross-company linkage.
- App role cannot delete audit events.
- API rejects anonymous requests, missing workspace context, revoked membership, Viewer writes, Member administration, CSRF violations, tampered cookies, malformed IDs and tenant body injection.
- Cross-company project GET/PATCH/DELETE return 404; target data stays unchanged and the caller’s Inspector records the attempt.
- TOTP replay produces the generic failure response; three failures lock the account.
- Unknown device denial, approved device access, out-of-hours denial and one-time override consumption are exercised.
- Admin CRUD, policy validation, member enrollment/role changes/revocation, device review, step-up, replay rejection, logout and absolute session expiry are exercised.
- The router audit walks actual Express layers and checks tenant routes for auth, membership, access and role guards. Pre-workspace routes have an explicit allow-list.
- The RLS proof uses the non-superuser owner under FORCE RLS in a transaction. It demonstrates that the zero-row invariant would fail if RLS were removed, then verifies rollback restored it. It does not disable RLS in a production database or show a remote CI run turning red.

## Remaining gaps and deviations from the source specification

- The role tests cover all seeded identities and core work/Admin boundaries, but are not a full Cartesian matrix of every verb, route, role and tenant.
- There is no exhaustive captured-log secret scan, stolen valid-session test, or separate expired-TOTP API test. Unit tests cover code verification and crypto; integration tests cover replay/lockout. Runtime error logging is intentionally restricted to request ID and status.
- The browser/HTTP demonstrations cover selected live flows, not the entire eight-step requested presentation including a live CI status change.
- Base routes remain consolidated in `app.ts`; content, API keys, explorer, storage, envelope encryption and key jobs now use separate modules. SQL remains parameterized and tenant operations use withTenant.
- Migrations are sorted, rerunnable numbered SQL files with one transaction per file, rather than a node-pg-migrate/Prisma ledger. Schema upgrades must remain idempotent.
- All tenant content endpoints require fresh membership. Auth/workspace discovery/step-up/logout intentionally do not require an active tenant: otherwise users could not select or recover a workspace.
- Access policy is checked on protected company content rather than credential authentication. A user may sign in and choose a workspace outside hours but cannot read or change its content.
- Unknown tenant body properties are rejected rather than silently accepted. Tenant query/header spoofing cannot replace server session context.
- Some denial paths (such as malformed requests, missing workspace, revoked membership and CSRF rejection) do not append a separate tenant audit event. Cross-tenant resource misses, role denials, access-hour/device denials and known-user authentication failures are logged. Unknown-email failures cannot be safely assigned to a company.
- Login unknown-user password verification uses a dummy Argon2 hash but does not establish constant-time responses. Missing and cross-tenant resources use identical query/error paths; no measured timing-class proof is claimed.
- Rate limits are process-local, active-assignee checks are service-level, and work/audit writes are separate transactions. These are documented hardening tasks.
- No production deployment was performed. Compose serves a local development portal and intentionally includes demo-only access helpers/bootstrap credentials. Production must remove them and follow the README hardening requirements.

For setup and commands, see README.md. For every page and workflow, see APPLICATION_GUIDE.md.
