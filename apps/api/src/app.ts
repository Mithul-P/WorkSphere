import express, {
  type Request,
  type Response,
  type NextFunction,
  type RequestHandler,
} from "express";
import session from "express-session";
import connectPg from "connect-pg-simple";
import helmet from "helmet";
import cors from "cors";
import { rateLimit } from "express-rate-limit";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";
import { z } from "zod";
import { pool, withTenant } from "./db/pool.js";
import { config } from "./config.js";
import { can, type Role, type Action } from "./policy/permissions.js";
import { decrypt, encrypt, hash, counter, authenticator } from "./crypto.js";
import { registerContent } from "./content.js";
import { bearerMiddleware, registerApiKeys } from "./api-keys.js";
import { registerExplorer } from "./explorer.js";
declare module "express-session" {
  interface SessionData {
    userId: string;
    tenantId: string;
    csrf: string;
    started: number;
    stepup: number;
    overrideUntil: number;
    overrideTenant: string;
  }
}
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      requestId: string;
      role: Role;
    }
  }
}
class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
const fail = (status: number, message: string): never => {
  throw new HttpError(status, message);
};
const wrap =
  (fn: (req: Request, res: Response) => Promise<unknown>): RequestHandler =>
  (req, res, next) => {
    Promise.resolve(fn(req, res)).catch(next);
  };
const uuid = z.string().uuid();
const pagination = z.object({
  page: z.coerce.number().int().min(1).max(10000).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(30),
});
const id = (req: Request) => uuid.parse(req.params.id);
const tenant = (req: Request) => req.session.tenantId || "";
const user = (req: Request) => req.session.userId || "";
async function audit(
  req: Request,
  action: string,
  outcome = "allowed",
  reason = "",
  resourceId?: string,
  tenantId?: string,
  actorId?: string,
) {
  const tid = tenantId || tenant(req);
  const values = [
    randomUUID(),
    tid || null,
    actorId || user(req) || null,
    action,
    action.split(".")[0],
    resourceId || null,
    outcome,
    req.apiKey ? `API key ${req.apiKey}; ${reason}` : reason,
    req.requestId,
    req.ip,
    req.get("user-agent")?.slice(0, 500),
  ];
  if (tid)
    await withTenant(tid, (c) =>
      c.query(
        "INSERT INTO audit_events(id,tenant_id,actor_user_id,action,resource_type,resource_id,outcome,reason,request_id,ip,user_agent) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        values,
      ),
    );
  // Pre-workspace failures are attributed to each of the user's current workspaces; no global events are exposed.
  else if (user(req)) {
    const { rows } = await pool.query("SELECT * FROM discover_workspaces($1)", [
      user(req),
    ]);
    for (const row of rows)
      await audit(
        req,
        action,
        outcome,
        reason,
        resourceId,
        row.tenant_id as string,
      );
  }
}
export function withinHours(
  policy: {
    timezone: string;
    access_days: number[];
    access_start: string;
    access_end: string;
  },
  now = new Date(),
) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: policy.timezone,
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(now);
  const val = (key: string) => parts.find((p) => p.type === key)?.value || "";
  const day = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(
    val("weekday"),
  );
  const time = `${val("hour")}:${val("minute")}:${val("second")}`;
  if (policy.access_start <= policy.access_end)
    return (
      policy.access_days.includes(day) &&
      time >= policy.access_start &&
      time <= policy.access_end
    );
  return (
    (policy.access_days.includes(day) && time >= policy.access_start) ||
    (policy.access_days.includes((day + 6) % 7) && time <= policy.access_end)
  );
}
const auth: RequestHandler = (req, _res, next) => {
  if (!user(req) || Date.now() - (req.session.started || 0) > 8 * 3600000) {
    next(new HttpError(401, "Login required"));
    return;
  }
  next();
};
const tenantGuard: RequestHandler = (req, res, next) => {
  Promise.resolve(
    (async () => {
      if (!tenant(req)) fail(403, "Select a workspace");
      const { rows } = await withTenant(tenant(req), (c) =>
        c.query(
          "SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2 AND status='active'",
          [tenant(req), user(req)],
        ),
      );
      if (!rows.length) fail(403, "Workspace access revoked");
      req.role =
        req.apiKey && rows[0].role !== "viewer"
          ? "member"
          : (rows[0].role as Role);
    })(),
  ).then(() => next(), next);
};

const accessGuard: RequestHandler = (req, _res, next) => {
  (async () => {
    const { rows } = await withTenant(tenant(req), (c) =>
      c.query("SELECT * FROM tenant_policies WHERE tenant_id=$1", [
        tenant(req),
      ]),
    );
    const p = rows[0];
    if (!p) fail(403, "Workspace policy unavailable");
    if (p.require_trusted_device) {
      const token = parseCookies(req.headers.cookie || "").ws_device;
      const device = await withTenant(tenant(req), (c) =>
        c.query(
          "SELECT status FROM trusted_devices WHERE tenant_id=$1 AND user_id=$2 AND device_token_hash=$3",
          [tenant(req), user(req), hash(token || "")],
        ),
      );
      if (device.rows[0]?.status !== "approved") {
        await audit(req, "device.denied", "denied", "Device approval required");
        fail(403, "Device approval required. Ask a workspace administrator.");
      }
    }
    if (
      !withinHours(p) &&
      !(
        req.session.overrideTenant === tenant(req) &&
        (req.session.overrideUntil || 0) > Date.now()
      )
    ) {
      const override = await withTenant(tenant(req), (c) =>
        c.query(
          "UPDATE access_overrides SET used_at=now() WHERE id=(SELECT id FROM access_overrides WHERE tenant_id=$1 AND user_id=$2 AND used_at IS NULL AND expires_at>now() ORDER BY expires_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING expires_at",
          [tenant(req), user(req)],
        ),
      );
      if (!override.rows.length) {
        await audit(req, "hours.denied", "denied", "Outside access hours");
        fail(403, "Outside workspace access hours");
      }
      req.session.overrideTenant = tenant(req);
      req.session.overrideUntil = new Date(
        override.rows[0].expires_at as string,
      ).getTime();
      await audit(req, "breakglass.used");
    }
  })().then(() => next(), next);
};
function requireRole(action: Action): RequestHandler {
  return function roleGuard(req, _res, next) {
    if (can(req.role, action)) next();
    else
      audit(req, "permission.denied", "denied", action).then(
        () => next(new HttpError(403, "Permission denied")),
        next,
      );
  };
}
const step: RequestHandler = (req, _res, next) => {
  const fresh =
    !!req.session.stepup && Date.now() - req.session.stepup <= 300000;
  audit(
    req,
    "auth.stepup_check",
    fresh ? "allowed" : "denied",
    fresh ? "Fresh verification" : "Fresh verification required",
  ).then(
    () =>
      next(
        fresh ? undefined : new HttpError(403, "Fresh verification required"),
      ),
    next,
  );
};
function parseCookies(input: string) {
  return Object.fromEntries(
    input.split(";").map((v) => {
      const i = v.indexOf("=");
      return [v.slice(0, i).trim(), v.slice(i + 1)];
    }),
  );
}
export const app = express();
app.disable("x-powered-by");
app.use(
  helmet(),
  cors({ origin: config.WEB_ORIGIN, credentials: true }),
  express.json({ limit: "32kb" }),
);
app.use((req, res, next) => {
  req.requestId = randomUUID();
  res.setHeader("X-Request-Id", req.requestId);
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  next();
});
app.use(
  rateLimit({
    windowMs: 60000,
    limit: 300,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  }),
);
const Store = connectPg(session);
const browserSession = session({
  store: new Store({
    pool,
    tableName: "session",
    createTableIfMissing: false,
  }),
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  name: "ws_session",
  cookie: {
    httpOnly: true,
    secure: config.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1800000,
  },
});
app.use((req, res, next) => {
  // Bearer requests are stateless and cannot establish or reuse browser sessions.
  if (req.get("authorization")) {
    req.session = {} as Request["session"];
    next();
  } else browserSession(req, res, next);
});
app.use(bearerMiddleware(audit));
app.use(
  rateLimit({
    windowMs: 60000,
    limit: 180,
    skip: (req) => !user(req),
    keyGenerator: (req) => user(req),
    standardHeaders: "draft-7",
    legacyHeaders: false,
  }),
);
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  if (!req.apiKey && ["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    if (req.get("origin") !== config.WEB_ORIGIN) {
      next(new HttpError(403, "Invalid origin"));
      return;
    }
    const supplied = req.get("x-csrf-token") || "";
    const expected = req.session.csrf || "";
    if (
      !expected ||
      supplied.length !== expected.length ||
      !timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))
    ) {
      next(new HttpError(403, "Invalid CSRF token"));
      return;
    }
  }
  next();
});
app.get("/api/health", (_req, res) => res.json({ status: "ok" }));
app.get("/api/auth/csrf", (req, res) => {
  req.session.csrf ||= randomBytes(32).toString("hex");
  res.json({ csrf: req.session.csrf });
});
const loginLimit = rateLimit({
  windowMs: 900000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
app.post(
  "/api/auth/login",
  loginLimit,
  wrap(async (req, res) => {
    const body = z
      .object({
        email: z.string().email().max(254),
        password: z.string().max(200),
        totp: z.string().regex(/^\d{6}$/),
      })
      .strict()
      .safeParse(req.body);
    if (!body.success) fail(401, "Login failed");
    const b = body.data!;
    const client = await pool.connect();
    let uid: string | undefined;
    try {
      await client.query("BEGIN");
      const { rows } = await client.query(
        "SELECT * FROM users WHERE email=$1 FOR UPDATE",
        [b.email.toLowerCase()],
      );
      const u = rows[0];
      uid = u?.id as string | undefined;
      const validPassword = u
        ? await argon2.verify(u.password_hash as string, b.password)
        : await argon2.verify(dummyHash, b.password);
      const count = u
        ? counter(b.totp, decrypt(u.totp_secret_encrypted as string))
        : null;
      if (
        !u ||
        !validPassword ||
        !u.totp_enabled ||
        count === null ||
        count <= Number(u.last_used_counter) ||
        (u.locked_until && new Date(u.locked_until as string) > new Date())
      ) {
        if (u)
          await client.query(
            "UPDATE users SET failed_attempts=failed_attempts+1,locked_until=CASE WHEN failed_attempts+1>=3 THEN now()+interval '15 minutes' ELSE locked_until END WHERE id=$1",
            [uid],
          );
        await client.query("COMMIT");
        if (uid) {
          const memberships = await pool.query(
            "SELECT * FROM discover_workspaces($1)",
            [uid],
          );
          for (const membership of memberships.rows)
            await audit(
              req,
              u && Number(u.failed_attempts) + 1 >= 3
                ? "auth.lockout"
                : "auth.failed",
              "failed",
              "Login failed",
              undefined,
              membership.tenant_id as string,
              uid,
            );
        }
        fail(401, "Login failed");
      }
      await client.query(
        "UPDATE users SET failed_attempts=0,locked_until=NULL,last_used_counter=$2 WHERE id=$1",
        [uid, count],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
    await new Promise<void>((resolve, reject) =>
      req.session.regenerate((e) => (e ? reject(e) : resolve())),
    );
    req.session.userId = uid!;
    req.session.started = Date.now();
    req.session.csrf = randomBytes(32).toString("hex");
    let device = parseCookies(req.headers.cookie || "").ws_device;
    if (!device || !/^[a-f0-9]{64}$/.test(device)) {
      device = randomBytes(32).toString("hex");
      res.cookie("ws_device", device, {
        httpOnly: true,
        secure: config.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 365 * 86400000,
      });
    }
    const memberships = await pool.query(
      "SELECT * FROM discover_workspaces($1)",
      [uid],
    );
    for (const m of memberships.rows) {
      const added = await withTenant(m.tenant_id as string, (c) =>
        c.query(
          "INSERT INTO trusted_devices(id,tenant_id,user_id,device_token_hash,label) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING RETURNING id",
          [
            randomUUID(),
            m.tenant_id,
            uid,
            hash(device),
            req.get("user-agent")?.slice(0, 100) || "Browser",
          ],
        ),
      );
      if (added.rows.length)
        await audit(
          req,
          "device.pending",
          "allowed",
          "New device awaits review",
          String(added.rows[0].id),
          m.tenant_id as string,
        );
    }
    await audit(req, "auth.login");
    res.json({ csrf: req.session.csrf });
  }),
);
const dummyHash = await argon2.hash(
  "unusable-random-" + randomBytes(32).toString("hex"),
);
app.get(
  "/api/auth/me",
  auth,
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      "SELECT id,email FROM users WHERE id=$1",
      [user(req)],
    );
    res.json({ user: rows[0], tenantId: tenant(req) || null });
  }),
);
app.post(
  "/api/auth/logout",
  auth,
  wrap(async (req, res) => {
    await new Promise<void>((resolve, reject) =>
      req.session.destroy((e) => (e ? reject(e) : resolve())),
    );
    res.clearCookie("ws_session");
    res.json({ ok: true });
  }),
);
app.post(
  "/api/auth/stepup",
  auth,
  loginLimit,
  wrap(async (req, res) => {
    const { totp } = z
      .object({ totp: z.string().regex(/^\d{6}$/) })
      .strict()
      .parse(req.body);
    const { rows } = await pool.query(
      "SELECT totp_secret_encrypted FROM users WHERE id=$1",
      [user(req)],
    );
    const count = counter(
      totp,
      decrypt(rows[0].totp_secret_encrypted as string),
    );
    if (count === null) {
      await audit(req, "auth.stepup", "failed", "Verification failed");
      fail(401, "Verification failed");
    }
    const updated = await pool.query(
      "UPDATE users SET last_used_counter=$2 WHERE id=$1 AND last_used_counter<$2 AND (locked_until IS NULL OR locked_until<=now()) RETURNING id",
      [user(req), count],
    );
    if (!updated.rows.length) {
      await audit(req, "auth.stepup", "failed", "Verification failed");
      fail(401, "Verification failed");
    }
    req.session.stepup = Date.now();
    await audit(req, "auth.stepup");
    res.json({ ok: true });
  }),
);
app.get(
  "/api/workspaces",
  auth,
  wrap(async (req, res) => {
    res.json(
      (await pool.query("SELECT * FROM discover_workspaces($1)", [user(req)]))
        .rows,
    );
  }),
);
app.post(
  "/api/session/workspace",
  auth,
  wrap(async (req, res) => {
    const { tenantId } = z.object({ tenantId: uuid }).strict().parse(req.body);
    const { rows } = await withTenant(tenantId, (c) =>
      c.query(
        "SELECT role FROM memberships WHERE tenant_id=$1 AND user_id=$2 AND status='active'",
        [tenantId, user(req)],
      ),
    );
    if (!rows.length) fail(403, "Workspace unavailable");
    req.session.tenantId = tenantId;
    req.session.overrideUntil = 0;
    req.session.stepup = 0;
    await audit(req, "workspace.selected");
    res.json({ role: rows[0].role });
  }),
);
if (config.DEV_ONLY === "true" && config.NODE_ENV !== "production")
  app.get(
    "/api/dev/totp",
    wrap(async (req, res) => {
      const { email } = z
        .object({ email: z.string().email() })
        .parse(req.query);
      const { rows } = await pool.query(
        "SELECT totp_secret_encrypted FROM users WHERE email=$1",
        [email],
      );
      if (!rows.length) fail(404, "Not found");
      res.json({
        totp: authenticator.generate(
          decrypt(rows[0].totp_secret_encrypted as string),
        ),
      });
    }),
  );
if (config.DEV_ONLY === "true" && config.NODE_ENV !== "production")
  app.post(
    "/api/dev/bootstrap",
    wrap(async (req, res) => {
      z.object({}).strict().parse(req.body);
      res.cookie("ws_device", "a".repeat(64), {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 86400000,
      });
      res.json({ ok: true });
    }),
  );
export const routeManifest: {
  method: string;
  path: string;
  action: Action;
  stepup: boolean;
}[] = [];
function route(
  method: "get" | "post" | "patch" | "put" | "delete",
  path: string,
  action: Action,
  handler: (req: Request, res: Response) => Promise<unknown>,
  sensitive = false,
) {
  routeManifest.push({ method, path, action, stepup: sensitive });
  app[method](
    "/api" + path,
    auth,
    tenantGuard,
    accessGuard,
    requireRole(action),
    ...(sensitive ? [step] : []),
    wrap(handler),
  );
}
async function resource(
  req: Request,
  table: "projects" | "tasks",
  resourceId: string,
) {
  const { rows } = await withTenant(tenant(req), (c) =>
    c.query(`SELECT * FROM ${table} WHERE tenant_id=$1 AND id=$2`, [
      tenant(req),
      resourceId,
    ]),
  );
  if (!rows.length) {
    await audit(req, table + ".not_found", "denied", "Not found", resourceId);
    fail(404, "Not found");
  }
  return rows[0];
}
route("get", "/projects", "read", async (req, res) => {
  const { page, limit } = pagination.parse(req.query);
  res.json(
    (
      await withTenant(tenant(req), (c) =>
        c.query(
          "SELECT * FROM projects WHERE tenant_id=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3",
          [tenant(req), limit, (page - 1) * limit],
        ),
      )
    ).rows,
  );
});
const projectBody = z
  .object({
    name: z.string().trim().min(1).max(150),
    description: z.string().max(3000).default(""),
  })
  .strict();
route("post", "/projects", "edit", async (req, res) => {
  const b = projectBody.parse(req.body);
  const rid = randomUUID();
  const { rows } = await withTenant(tenant(req), (c) =>
    c.query(
      "INSERT INTO projects(id,tenant_id,name,description,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *",
      [rid, tenant(req), b.name, b.description, user(req)],
    ),
  );
  await audit(req, "project.created", "allowed", "", rid);
  res.status(201).json(rows[0]);
});
route("get", "/projects/:id", "read", async (req, res) =>
  res.json(await resource(req, "projects", id(req))),
);
route("patch", "/projects/:id", "edit", async (req, res) => {
  const rid = id(req);
  const b = projectBody.parse(req.body);
  await resource(req, "projects", rid);
  const { rows } = await withTenant(tenant(req), (c) =>
    c.query(
      "UPDATE projects SET name=$3,description=$4 WHERE tenant_id=$1 AND id=$2 RETURNING *",
      [tenant(req), rid, b.name, b.description],
    ),
  );
  await audit(req, "project.updated", "allowed", "", rid);
  res.json(rows[0]);
});
route("delete", "/projects/:id", "edit", async (req, res) => {
  const rid = id(req);
  await resource(req, "projects", rid);
  await withTenant(tenant(req), (c) =>
    c.query("DELETE FROM projects WHERE tenant_id=$1 AND id=$2", [
      tenant(req),
      rid,
    ]),
  );
  await audit(req, "project.deleted", "allowed", "", rid);
  res.json({ ok: true });
});
route("get", "/projects/:id/tasks", "read", async (req, res) => {
  const rid = id(req);
  await resource(req, "projects", rid);
  const { page, limit } = pagination.parse(req.query);
  res.json(
    (
      await withTenant(tenant(req), (c) =>
        c.query(
          "SELECT * FROM tasks WHERE tenant_id=$1 AND project_id=$2 ORDER BY created_at,id LIMIT $3 OFFSET $4",
          [tenant(req), rid, limit, (page - 1) * limit],
        ),
      )
    ).rows,
  );
});
const taskBody = z
  .object({
    title: z.string().trim().min(1).max(300),
    status: z.enum(["todo", "in_progress", "done"]).default("todo"),
    assignee_id: uuid.nullable().default(null),
  })
  .strict();
async function assignee(req: Request, uid: string | null) {
  if (!uid) return;
  const { rows } = await withTenant(tenant(req), (c) =>
    c.query(
      "SELECT id FROM memberships WHERE tenant_id=$1 AND user_id=$2 AND status='active'",
      [tenant(req), uid],
    ),
  );
  if (!rows.length) fail(400, "Assignee must be an active workspace member");
}
route("post", "/projects/:id/tasks", "edit", async (req, res) => {
  const rid = id(req);
  const b = taskBody.parse(req.body);
  await resource(req, "projects", rid);
  await assignee(req, b.assignee_id);
  const tid = randomUUID();
  res
    .status(201)
    .json(
      (
        await withTenant(tenant(req), (c) =>
          c.query(
            "INSERT INTO tasks(id,tenant_id,project_id,title,status,assignee_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
            [tid, tenant(req), rid, b.title, b.status, b.assignee_id],
          ),
        )
      ).rows[0],
    );
  await audit(req, "task.created", "allowed", "", tid);
});
route("patch", "/tasks/:id", "edit", async (req, res) => {
  const rid = id(req);
  const b = taskBody.partial().strict().parse(req.body);
  const old = await resource(req, "tasks", rid);
  if (b.assignee_id !== undefined) await assignee(req, b.assignee_id);
  res.json(
    (
      await withTenant(tenant(req), (c) =>
        c.query(
          "UPDATE tasks SET title=$3,status=$4,assignee_id=$5 WHERE tenant_id=$1 AND id=$2 RETURNING *",
          [
            tenant(req),
            rid,
            b.title ?? old.title,
            b.status ?? old.status,
            b.assignee_id === undefined ? old.assignee_id : b.assignee_id,
          ],
        ),
      )
    ).rows[0],
  );
  await audit(req, "task.updated", "allowed", "", rid);
});
route("delete", "/tasks/:id", "edit", async (req, res) => {
  const rid = id(req);
  await resource(req, "tasks", rid);
  await withTenant(tenant(req), (c) =>
    c.query("DELETE FROM tasks WHERE tenant_id=$1 AND id=$2", [
      tenant(req),
      rid,
    ]),
  );
  await audit(req, "task.deleted", "allowed", "", rid);
  res.json({ ok: true });
});
route("get", "/members", "members", async (req, res) => {
  const { page, limit } = pagination.parse(req.query);
  res.json(
    (
      await withTenant(tenant(req), (c) =>
        c.query(
          "SELECT m.*,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE tenant_id=$1 ORDER BY m.created_at,m.id LIMIT $2 OFFSET $3",
          [tenant(req), limit, (page - 1) * limit],
        ),
      )
    ).rows,
  );
});
route(
  "post",
  "/members/invite",
  "members",
  async (req, res) => {
    const b = z
      .object({
        email: z.string().email().max(254),
        password: z.string().min(12).max(200),
        role: z.enum(["admin", "member", "viewer"]),
      })
      .strict()
      .parse(req.body);
    const uid = randomUUID();
    const secret = authenticator.generateSecret();
    const pw = await argon2.hash(b.password);
    await withTenant(tenant(req), async (c) => {
      await c.query(
        "INSERT INTO users(id,email,password_hash,totp_secret_encrypted) VALUES($1,$2,$3,$4)",
        [uid, b.email.toLowerCase(), pw, encrypt(secret)],
      );
      await c.query(
        "INSERT INTO memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,$4)",
        [randomUUID(), tenant(req), uid, b.role],
      );
    });
    await audit(req, "member.invited", "allowed", "", uid);
    res.status(201).json({
      userId: uid,
      otpauth: authenticator.keyuri(b.email, "WorkSphere", secret),
    });
  },
  true,
);
async function changeMember(req: Request, revoke: boolean) {
  const rid = id(req);
  const role = revoke
    ? null
    : z
        .object({ role: z.enum(["admin", "member", "viewer"]) })
        .strict()
        .parse(req.body).role;
  await withTenant(tenant(req), async (c) => {
    await c.query("SELECT pg_advisory_xact_lock(hashtext($1))", [tenant(req)]);
    const { rows } = await c.query(
      "SELECT * FROM memberships WHERE tenant_id=$1 AND id=$2",
      [tenant(req), rid],
    );
    if (!rows.length) fail(404, "Not found");
    if (rows[0].role === "admin" && (revoke || role !== "admin")) {
      const admins = await c.query(
        "SELECT id FROM memberships WHERE tenant_id=$1 AND role='admin' AND status='active'",
        [tenant(req)],
      );
      if (admins.rows.length <= 1)
        fail(409, "Keep at least one active administrator");
    }
    await c.query(
      revoke
        ? "UPDATE memberships SET status='revoked' WHERE tenant_id=$1 AND id=$2"
        : "UPDATE memberships SET role=$3 WHERE tenant_id=$1 AND id=$2",
      revoke ? [tenant(req), rid] : [tenant(req), rid, role],
    );
  });
  await audit(
    req,
    revoke ? "member.revoked" : "member.role_changed",
    "allowed",
    "",
    rid,
  );
}
route(
  "patch",
  "/members/:id/role",
  "members",
  async (req, res) => {
    await changeMember(req, false);
    res.json({ ok: true });
  },
  true,
);
route(
  "post",
  "/members/:id/revoke",
  "members",
  async (req, res) => {
    z.object({}).strict().parse(req.body);
    await changeMember(req, true);
    res.json({ ok: true });
  },
  true,
);
route("get", "/policy", "policy", async (req, res) =>
  res.json(
    (
      await withTenant(tenant(req), (c) =>
        c.query("SELECT * FROM tenant_policies WHERE tenant_id=$1", [
          tenant(req),
        ]),
      )
    ).rows[0],
  ),
);
route(
  "put",
  "/policy",
  "policy",
  async (req, res) => {
    const b = z
      .object({
        access_days: z.array(z.number().int().min(0).max(6)).min(1).max(7),
        access_start: z
          .string()
          .regex(/^\d{2}:\d{2}(:\d{2})?$/)
          .refine(
            (v) => Number(v.slice(0, 2)) < 24 && Number(v.slice(3, 5)) < 60,
          ),
        access_end: z
          .string()
          .regex(/^\d{2}:\d{2}(:\d{2})?$/)
          .refine(
            (v) => Number(v.slice(0, 2)) < 24 && Number(v.slice(3, 5)) < 60,
          ),
        timezone: z
          .string()
          .max(100)
          .refine((v) => {
            try {
              new Intl.DateTimeFormat("en", { timeZone: v });
              return true;
            } catch {
              return false;
            }
          }),
        require_trusted_device: z.boolean(),
      })
      .strict()
      .parse(req.body);
    await withTenant(tenant(req), (c) =>
      c.query(
        "UPDATE tenant_policies SET access_days=$2,access_start=$3,access_end=$4,timezone=$5,require_trusted_device=$6 WHERE tenant_id=$1",
        [
          tenant(req),
          b.access_days,
          b.access_start,
          b.access_end,
          b.timezone,
          b.require_trusted_device,
        ],
      ),
    );
    await audit(req, "policy.changed");
    res.json({ ok: true });
  },
  true,
);
route(
  "post",
  "/overrides",
  "policy",
  async (req, res) => {
    const b = z.object({ userId: uuid }).strict().parse(req.body);
    await assignee(req, b.userId);
    await withTenant(tenant(req), (c) =>
      c.query(
        "INSERT INTO access_overrides(id,tenant_id,user_id,expires_at,created_by) VALUES($1,$2,$3,now()+interval '30 minutes',$4)",
        [randomUUID(), tenant(req), b.userId, user(req)],
      ),
    );
    await audit(req, "breakglass.created", "allowed", "", b.userId);
    res.status(201).json({ ok: true });
  },
  true,
);
route("get", "/devices", "devices", async (req, res) => {
  const { page, limit } = pagination.parse(req.query);
  res.json(
    (
      await withTenant(tenant(req), (c) =>
        c.query(
          "SELECT id,user_id,label,status,created_at,approved_by FROM trusted_devices WHERE tenant_id=$1 ORDER BY created_at DESC,id LIMIT $2 OFFSET $3",
          [tenant(req), limit, (page - 1) * limit],
        ),
      )
    ).rows,
  );
});
for (const operation of ["approve", "revoke"])
  route(
    "post",
    `/devices/:id/${operation}`,
    "devices",
    async (req, res) => {
      z.object({}).strict().parse(req.body);
      const rid = id(req);
      const result = await withTenant(tenant(req), (c) =>
        c.query(
          "UPDATE trusted_devices SET status=$3,approved_by=$4 WHERE tenant_id=$1 AND id=$2 RETURNING id",
          [
            tenant(req),
            rid,
            operation === "approve" ? "approved" : "revoked",
            user(req),
          ],
        ),
      );
      if (!result.rows.length) fail(404, "Not found");
      await audit(req, "device." + operation, "allowed", "", rid);
      res.json({ ok: true });
    },
    true,
  );
route("get", "/audit", "audit", async (req, res) => {
  const b = pagination
    .extend({
      outcome: z.enum(["allowed", "denied", "failed"]).optional(),
      action: z.string().max(100).optional(),
      from: z.string().datetime().optional(),
      to: z.string().datetime().optional(),
      family: z.enum(["content", "api_key"]).optional(),
      classification: z
        .enum(["internal", "confidential", "restricted"])
        .optional(),
    })
    .parse(req.query);
  res.json(
    (
      await withTenant(tenant(req), (c) =>
        c.query(
          "SELECT * FROM audit_events WHERE tenant_id=$1 AND ($2::text IS NULL OR outcome=$2) AND ($3::text IS NULL OR action=$3) AND ($4::timestamptz IS NULL OR created_at >= $4) AND ($5::timestamptz IS NULL OR created_at <= $5) AND ($8::text IS NULL OR action LIKE $8||'.%') AND ($9::text IS NULL OR reason LIKE '%'||$9||'%') ORDER BY created_at DESC,id LIMIT $6 OFFSET $7",
          [
            tenant(req),
            b.outcome ?? null,
            b.action ?? null,
            b.from ?? null,
            b.to ?? null,
            b.limit,
            (b.page - 1) * b.limit,
            b.family ?? null,
            b.classification ?? null,
          ],
        ),
      )
    ).rows,
  );
});
registerContent(app, {
  guards: [auth, tenantGuard, accessGuard, requireRole("read")],
  step,
  audit,
});
registerApiKeys(
  app,
  [auth, tenantGuard, accessGuard, requireRole("members")],
  step,
  audit,
);
registerExplorer(
  app,
  [auth, tenantGuard, accessGuard, requireRole("policy")],
  step,
  audit,
);
app.use((_req, _res, next) => next(new HttpError(404, "Not found")));
app.use((error: unknown, req: Request, res: Response, _next: NextFunction) => {
  void _next;
  const status =
    error instanceof HttpError
      ? error.status
      : (error as { code?: string }).code === "P0422"
        ? 422
        : error instanceof z.ZodError
          ? error.issues.some((issue) => issue.code === "unrecognized_keys")
            ? 422
            : 400
          : String((error as { code?: string }).code || "").startsWith("LIMIT_")
            ? (error as { code?: string }).code === "LIMIT_FILE_SIZE"
              ? 413
              : 422
            : 500;
  const message =
    error instanceof HttpError
      ? error.message
      : status === 400
        ? "Invalid request"
        : status === 422
          ? "Tenant data policy or request limit exceeded"
          : status === 413
            ? "File exceeds 10 MB limit"
            : "Internal server error";
  if (status >= 500)
    console.error(JSON.stringify({ requestId: req.requestId, status }));
  if (!res.headersSent)
    res.status(status).json({ error: message, requestId: req.requestId });
});
