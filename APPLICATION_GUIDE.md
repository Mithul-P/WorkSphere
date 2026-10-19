# WorkSphere — complete application guide

For the new Content Library, sharing, API Keys, Data Explorer, storage policy and encryption rotation screens, follow [SECURITY_EXTENSION.md](SECURITY_EXTENSION.md).

This guide explains what the project contains, how to access every screen, and how each role uses it. For installation, commands, architecture, recovery and test instructions, read [README.md](README.md).

## What the application does

WorkSphere gives companies separate workspaces inside one shared application. People organize projects, tasks and shared content; administrators control membership and security. The Security Inspector records activity and denied requests within the selected company. Email, billing and chat are outside this MVP.

The seeded companies are **Acme Corp** (Workspace Alpha) and **Globex Ltd** (Workspace Beta). Each has two projects, each with three tasks. Sam belongs to both companies, so you can demonstrate changing context without sharing one company’s records with the other.

## Start and access the application

In a terminal opened in the WorkSphere folder, run `docker compose up --build`. Open **http://localhost:5173** in your browser. Keep that terminal running. Alternatively, after `npm ci`, run `npm run local` for a temporary database; its data disappears when you stop it.

The web app is on port 5173, the API is on port 3000, and PostgreSQL is on port 5432 with Docker or 55432 with the optional local runner. You interact with the portal in your browser; you do not need to open the database to use normal features.

## Accounts and roles

| Account (append @worksphere.test) | Role   | Company         |
| --------------------------------- | ------ | --------------- |
| alice                             | Admin  | Acme            |
| bob                               | Member | Acme            |
| carol                             | Viewer | Acme            |
| dave                              | Admin  | Globex          |
| erin                              | Member | Globex          |
| sam                               | Member | Acme and Globex |

Default password: **Demo-WorkSphere-2026!**. These are local demonstration credentials.

| Capability                               | Admin | Member | Viewer |
| ---------------------------------------- | ----- | ------ | ------ |
| Read projects and tasks                  | Yes   | Yes    | Yes    |
| Create/edit/delete projects and tasks    | Yes   | Yes    | No     |
| Add members, change roles, revoke access | Yes   | No     | No     |
| Edit access hours / create overrides     | Yes   | No     | No     |
| Approve or revoke devices                | Yes   | No     | No     |
| View Security Inspector                  | Yes   | No     | No     |

Controls are hidden for roles without permission, and the server independently checks permission. If an administrator changes your role while you are signed in, the server uses the new role on your next request. Refresh to update the navigation display.

## 1. Sign in

Enter email, password and a six-digit authenticator code. Click **Sign in**. In local development, expand **Local demo tools** and click **Get current demo code** to populate the field. The seed no longer prints enrollment secrets. Newly created members receive their enrollment URL once when the administrator creates them.

For a first tour, choose **Dave**. Globex permits all days and does not require approved devices. For Alice, click **Bootstrap Alice’s device** before signing in. This installs a known local demo token matching Alice’s seeded approved device.

Acme permits Monday–Friday, 09:00–18:00 in Asia/Kolkata and requires trusted devices. Correct credentials can establish a session and list workspaces, but access to Acme’s protected content is denied outside those rules. Workspace selection itself is membership discovery; company policy is applied to content requests. A fresh demo can therefore show the workspace picker even when work is blocked.

A code cannot be reused for another login or step-up. Wait for the next 30-second code when needed. Wrong passwords, wrong/expired/reused codes and locked accounts all show **Login failed**. Three failures cause a 15-minute lockout. Signed-in idle sessions expire after 30 minutes and cannot exceed eight hours total.

## 2. Choose or switch a workspace

After sign-in, click a company card. The card shows your role in that company. Only active memberships appear. Sam sees both cards; Alice sees Acme and Dave sees Globex.

To switch later, click the company name near the top of the left sidebar. Select another card. Switching clears sensitive-action verification and the active access override; permissions are checked again. Switching to another company never copies or moves projects.

## 3. Projects & tasks (`/`)

The dashboard shows projects on the current page and a task board for the selected project. Counts describe the current page, not all database records.

**Read work:** click a project on the left. Tasks appear in three columns: **To do**, **In progress**, **Done**. Empty columns show a placeholder. Use Previous/Next when there are more records; list pages contain up to 30 records.

**Create a project:** Admins and Members enter a name and description in **New project**, then click **Create project**. Select it to open its board.

**Rename a project:** open it, click **Rename**, enter the new name in the browser dialog and confirm. Description is entered on creation; the API also supports updating it.

**Create a task:** enter its title in **What needs to happen next?** and click **Add task**. It starts in To do.

**Change task status:** use the status selector on its card. Selecting Done moves the card to the Done column after saving.

**Edit a task:** click **Edit**, enter a new title and confirm.

**Assign a task:** click **Assign**. Enter the user UUID of an active member of the current company. Clear the field to unassign. Administrators can find user IDs on Members. Members who cannot open Members need a user ID supplied by their administrator. This is a basic MVP assignment control; there is no searchable people picker.

**Delete a task:** click its × button and confirm. **Delete a project:** click Delete near the board title and confirm. Deleting a project also deletes its tasks. These actions are permanent within that database; cancel the confirmation to keep the data.

Viewers can inspect boards, but editing controls are absent. Requests for another company’s resource return Not found; a Viewer’s own-company write returns Permission denied.

## 4. Verify sensitive actions

Members, Security Settings and device management are Admin-only. Changing roles, revoking people, creating members, changing policy, issuing overrides and approving/revoking devices also require step-up.

At the verification panel, enter a **new** authenticator code and click **Verify**. Verification lasts five minutes. Login does not count as step-up, and its code cannot be reused. Use your authenticator app for the next code, or click **Fill demo verification code** in development; the local helper is also available as a development-only API request described in the README. Changing workspace clears this verification.

A **Fresh verification required** error means you need to verify and retry the action. The failed attempt does not authorize the change.

## 5. Members (`/members`, Admin)

The table shows email, user UUID, role and active/revoked status.

- **Add a demo member:** verify first, enter a new email, a password with at least 12 characters, and a role. Click **Create member**. Save the returned authenticator enrollment URL immediately and share credentials securely. No invitation email is sent. Existing email addresses cannot be invited into a second company through this MVP screen.
- **Change a role:** choose Admin, Member or Viewer in the row. It saves immediately after verification; the user’s next request uses the new permission.
- **Revoke:** click Revoke and confirm. Their existing session loses company access on the next request. Their account and other-company memberships remain.
- The last active Admin cannot be demoted or revoked. Keep at least one administrator able to access the workspace.

There is no UI for restoring a revoked membership or resetting authentication factors. Those are future administrative workflows; do not assume they are implemented.

## 6. Security settings (`/settings`, Admin)

### Access hours

Verify, choose allowed weekdays, start/end times and an IANA timezone such as **Asia/Kolkata**, then click **Save policy**. Times use a 24-hour clock. A window crossing midnight belongs to its start day. For example, Monday 22:00–03:00 includes early Tuesday until 03:00. An ordinary window includes both endpoints.

The server checks time on each protected content request. Changing the policy can block your own next request. The screen warns you to create an override first and keep an administrator able to enter.

### One-time override

While you still have access and fresh verification, enter an active member’s user UUID and click **Create override**. It expires 30 minutes after creation. The first protected request outside allowed hours consumes it and authorizes that session until the original expiry. It cannot be redeemed again by another session. It does not bypass revoked membership, role permissions or trusted-device requirements. Inspector records creation and use.

If every administrator is already outside the window, they cannot create an application override. The README documents local database-operator recovery.

### Trusted devices

A correct login registers the browser token as pending for the user’s active workspaces. Where approval is required, that device cannot read or change company content until approved.

An approved Admin opens Settings, identifies the user and browser label, verifies with a fresh code and clicks **Approve**. The user retries their request or refreshes. **Revoke** blocks subsequent requests when the company requires trusted devices. The list does not expose device tokens or their hashes.

The bootstrap token is only for Alice’s first local demo access. Bob, Carol and Sam still need normal device approval in Acme. Clearing browser cookies creates a new device on the next login. Devices are approved per person and per company.

## 7. Security Inspector (`/inspector`, Admin)

This table shows security and work activity for the selected company. It includes timestamp, action, outcome, actor/resource IDs, reason and request ID. Allowed is green; denied/failed outcomes are highlighted. The alert strip counts security events on the current filtered page.

Filter by **Denied only**, **Failed**, **Allowed**, exact action name, From/To dates, or page. Click Refresh after reproducing an event in another browser. Example actions:

| Action                               | Meaning                                      |
| ------------------------------------ | -------------------------------------------- |
| auth.login / auth.failed             | Successful or failed authentication          |
| auth.lockout                         | Failure threshold reached                    |
| auth.stepup                          | Fresh sensitive-action verification          |
| workspace.selected                   | User selected this company                   |
| device.pending / device.denied       | New device or blocked device request         |
| device.approve / device.revoke       | Administrator reviewed a device              |
| hours.denied                         | Request outside allowed window               |
| breakglass.created / breakglass.used | Override lifecycle                           |
| permission.denied                    | Role did not permit the action               |
| projects.not_found / tasks.not_found | Resource missing or outside current company  |
| project.* / task.*                   | Work was created, updated or deleted         |
| member.* / policy.changed            | Membership or security configuration changed |

A cross-company attempt is logged with the caller’s company and the attempted UUID, without the other company’s name or records. Before-workspace authentication events for a known user are attributed to that user’s active workspaces; unknown email failures do not appear in a tenant Inspector. Event records are append-only for the application role.

## 8. Sign out

Click **Sign out** at the bottom of the sidebar or picker. This deletes the server session and clears the session cookie. Device trust is a separate browser cookie, so logging out does not automatically revoke a device. An Admin can revoke that approval separately.

## API access for developers

All endpoints start with `http://localhost:3000/api`. Use a cookie-capable HTTP client. Fetch `GET /auth/csrf` first. Retain its cookies, and attach the returned token in `X-CSRF-Token` plus `Origin: http://localhost:5173` on every mutation. Login rotates the session and returns a replacement token. Then `GET /workspaces` and `POST /session/workspace` with a verified tenant UUID. There are no bearer API keys.

| Area                | Endpoints                                                                             |
| ------------------- | ------------------------------------------------------------------------------------- |
| Health              | GET /health                                                                           |
| Authentication      | GET /auth/csrf; POST /auth/login; GET /auth/me; POST /auth/logout; POST /auth/stepup  |
| Workspace discovery | GET /workspaces; POST /session/workspace                                              |
| Projects            | GET/POST /projects; GET/PATCH/DELETE /projects/:id                                    |
| Tasks               | GET/POST /projects/:id/tasks; PATCH/DELETE /tasks/:id                                 |
| Members             | GET /members; POST /members/invite; PATCH /members/:id/role; POST /members/:id/revoke |
| Policy              | GET/PUT /policy; POST /overrides                                                      |
| Devices             | GET /devices; POST /devices/:id/approve; POST /devices/:id/revoke                     |
| Inspector           | GET /audit?outcome=&action=&from=&to=&page=&limit=                                    |
| Development only    | GET /dev/totp?email=…                                                                 |

Lists accept page (starting at 1) and limit (1–100, default 30). Unknown tenant query/header values never override session context; extra body properties are rejected. Errors use `{error, requestId}`. 400 means validation, 401 means sign-in/verification, 403 means permission/policy/CSRF, 404 means missing or inaccessible resource, 409 protects the last Admin, 429 means rate limited. Internal errors do not expose stack traces.

Example project body: `{"name":"Launch","description":"Autumn release"}`. Task body: `{"title":"Review access","status":"todo","assignee_id":null}`. Task patch can include just `{"status":"done"}`. Member invite: `{"email":"new@example.test","password":"a-long-demo-password","role":"viewer"}`. Workspace selection: `{"tenantId":"10000000-0000-4000-8000-000000000002"}`. Override: `{"userId":"20000000-0000-4000-8000-000000000001"}`.

## What is included in the code

The repository contains the React interface and CSS, Express API, session/CSRF/TOTP security, centralized permission matrix, PostgreSQL schema and forced RLS, seeded companies, Docker stack, unit/DB/attack tests, browser test, local runtime, HTTP demo, RLS proof and CI workflow. README explains installation and security; this document is the user manual; VERIFICATION records the evidence and gaps.

Not included: chat, billing, enterprise SSO, project membership/permissions, email delivery, S3 storage or optional custom fields. Tenant-only encrypted uploads, tenant file keys and scoped API keys are included in the security extension. This is a local-development MVP with documented production hardening and test limitations.
