# WorkSphere

**A tenant-safe SaaS workspace portal/API for secure team collaboration.**

Built for the Advantix Hackathon by **Syntax Syndicate**. React and TypeScript frontend, Express API, and a local PostgreSQL engine using PGlite. The interface includes a project dashboard, task board, workspace members, invitations and a Tenant Security Inspector.

## Run locally

Requires Node.js 22.12+ (Node 24 recommended).

```sh
npm install
npm run dev
```

Open **http://localhost:3000**. Both the frontend and API run on the same origin. No Docker, API key or external database account is required. Development data persists in `.data/`, which is excluded from Git.

On Windows, you can also double-click **START-WORKSPHERE.cmd**. It installs missing dependencies and starts the server. Keep that terminal open while using the app. In VS Code, open this folder and select **Run and Debug → WorkSphere server** after installing dependencies.

### Demo accounts

The login screen includes buttons to fill these local demo credentials. Password: `WorkSphereDemo2026!`

| Email | Workspace | Role |
| --- | --- | --- |
| admin@alpha.demo | Alpha Studio | Admin |
| member@alpha.demo | Alpha Studio | Member |
| viewer@alpha.demo | Alpha Studio | Viewer |
| admin@beta.demo | Beta Labs | Admin |

Development seeds demo accounts only when the database has no users. Never use the demo database or demo credentials for real company data. Production mode disables demo seeding unless explicitly enabled.

## Demo in three minutes

1. Sign in as the Alpha admin and open a project. Create a task, assign a teammate, and move it to Done.
2. Open **Team** to see workspace-specific roles. A Viewer account can read work but cannot mutate it.
3. Open **Security Inspector** and run the tenant boundary check. The local demo preloads a Beta project ID. Alpha receives a uniform **404**, no foreign project data, and a denial in Alpha's audit log.
4. Sign in as the Beta admin to confirm its project remains unchanged.
5. Create an invitation for an email. Share its token manually. The matching account can accept it once, within 24 hours. This prototype does not send email.

## Security design

- Opaque sessions in HttpOnly, SameSite=Strict cookies. Only SHA-256 token digests are stored. Sessions expire after eight hours.
- Passwords use salted scrypt hashes. Mutations require same-origin requests and a session-bound CSRF token.
- Membership is resolved server-side for each request. A URL tenant ID alone never grants access.
- API checks enforce roles and resource ownership. All tenant-owned queries execute as the non-owner `worksphere_app` role.
- PostgreSQL row-level policies enforce `tenant_id` on projects, tasks, audit events and invitations. Tenant context is transaction-local.
- Composite foreign keys prevent cross-tenant project/task and assignee relationships.
- Denied object access returns 404. Forbidden actions within a known workspace return 403. Audit records exclude passwords, tokens and request bodies.
- Invitations are email-bound, expire, and store token digests. The last administrator cannot demote themselves.

PGlite is an embedded PostgreSQL engine suitable for the local hackathon demonstration. This repository uses a single server process and local filesystem storage. A multi-instance deployment requires a managed PostgreSQL connection adapter, shared rate limiting, operations monitoring, backups and a deployment review. No production certification or security audit is claimed.

## Checks

```sh
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

The integration suite covers tenant ID swapping, read/write permissions, safe auditing, nested resources, CSRF, invitation replay, last-admin protection, direct database RLS enforcement and transaction isolation. Tests use a fresh in-memory PostgreSQL instance. CI runs the same checks.

Browser tests cover account registration, independent workspace creation, project/task workflows, viewer restrictions, invitations and the Security Inspector. API and browser checks are complementary, rather than a claim to cover every possible input or attack.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| PORT | 3000 | Local HTTP port |
| APP_ORIGIN | http://localhost:3000 | Exact allowed browser origin, including port |
| DATA_DIR | .data | Persistent local database directory |
| DEMO_MODE | true in development | Demo seed and cross-tenant target endpoint |
| NODE_ENV | development | Set to production to serve the built frontend and require secure cookies |

For production, build first, set `NODE_ENV=production`, `DEMO_MODE=false`, and an HTTPS `APP_ORIGIN`. The server binds to loopback for local use. Configure a trusted TLS reverse proxy before deployment.

## Repository structure

```text
server/       Express routes, session handling, schema, seed data
src/          React interface and responsive styling
tests/        Security and functionality integration tests
.github/      Automated checks
.vscode/      VS Code launch and task configuration
```

## Team

Syntax Syndicate — fill in member names and individual contributions before submission.

## Technical references

- [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [OWASP object-level authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PGlite](https://pglite.dev/docs/)
- [Express security guidance](https://expressjs.com/en/advanced/best-practice-security/)
