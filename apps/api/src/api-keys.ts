import type { Express, Request, RequestHandler, Response } from "express";
import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { pool, withTenant } from "./db/pool.js";
import { z } from "zod";
import { isIP } from "node:net";
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      apiKey?: string;
    }
  }
}
type Audit = (
  req: Request,
  action: string,
  outcome?: string,
  reason?: string,
  resourceId?: string,
  tenantId?: string,
) => Promise<void>;
const scopes = z.enum([
  "content:read",
  "content:write",
  "projects:read",
  "projects:write",
  "tasks:read",
  "tasks:write",
]);
function digest(value: string) {
  const pepper =
    process.env.API_KEY_PEPPER ||
    (process.env.NODE_ENV !== "production"
      ? process.env.SESSION_SECRET
      : undefined);
  if (!pepper || pepper.length < 32)
    throw new Error("API_KEY_PEPPER must be configured");
  return createHmac("sha256", pepper).update(value).digest("hex");
}
const usages = new Map<string, { window: number; count: number }>();
export function bearerMiddleware(audit: Audit): RequestHandler {
  return (req, res, next) => {
    (async () => {
      const reject = () =>
        res
          .status(401)
          .json({ error: "Invalid API key", requestId: req.requestId });
      if (
        Object.keys(req.query).some((k) =>
          /^(api_?key|access_token|authorization)$/i.test(k),
        )
      ) {
        reject();
        return;
      }
      if (
        /ws_live_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}/.test(
          JSON.stringify(req.query),
        ) ||
        /ws_live_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}/.test(
          JSON.stringify(req.body ?? {}),
        )
      ) {
        reject();
        return;
      }
      const auth = req.get("authorization");
      if (!auth) {
        next();
        return;
      }
      const match =
        /^Bearer (ws_live_([A-Za-z0-9_-]{8})_[A-Za-z0-9_-]{43})$/.exec(auth);
      if (!match) {
        reject();
        return;
      }
      const k = (
        await pool.query("SELECT * FROM discover_api_key($1)", [match[2]])
      ).rows[0];
      const expected = Buffer.from(k?.key_hash || "0".repeat(64), "hex"),
        supplied = Buffer.from(digest(match[1]), "hex");
      if (!timingSafeEqual(expected, supplied) || !k) {
        if (k)
          await audit(
            req,
            "api_key.failure",
            "denied",
            "Invalid credentials",
            k.id,
            k.tenant_id,
          );
        reject();
        return;
      }
      req.apiKey = k.id;
      req.session.tenantId = k.tenant_id;
      req.session.userId = k.created_by;
      // Service identity never inherits a browser's step-up or access override.
      req.session.stepup = 0;
      req.session.overrideUntil = 0;
      req.session.started = Date.now();
      if (
        k.status !== "active" ||
        new Date(k.expires_at).getTime() <= Date.now()
      ) {
        await audit(
          req,
          "api_key.failure",
          "denied",
          "Expired or revoked key",
          k.id,
        );
        reject();
        return;
      }
      if (k.ip_allowlist?.length) {
        const allowed = await withTenant(k.tenant_id, (c) =>
          c.query("SELECT $1::inet <<= ANY($2::cidr[]) AS allowed", [
            req.ip?.replace(/^::ffff:/, ""),
            k.ip_allowlist,
          ]),
        );
        if (!allowed.rows[0].allowed) {
          await audit(req, "api_key.failure", "denied", "IP not allowed", k.id);
          reject();
          return;
        }
      }
      const minute = Math.floor(Date.now() / 60000),
        bucket = usages.get(k.id);
      if (!bucket || bucket.window !== minute)
        usages.set(k.id, { window: minute, count: 1 });
      else bucket.count++;
      if (usages.size > 10000)
        for (const [id, b] of usages)
          if (b.window !== minute) usages.delete(id);
      if (usages.get(k.id)!.count > k.rate_limit_per_min) {
        await audit(req, "api_key.spike", "denied", "Rate limit", k.id);
        res
          .status(429)
          .json({ error: "Rate limit exceeded", requestId: req.requestId });
        return;
      }
      const family = /^\/api\/projects\/[^/]+\/tasks(\/|$)/.test(req.path)
        ? "tasks"
        : /^\/api\/(projects|tasks|content)(\/|$)/.exec(req.path)?.[1];
      const forbidden = /\/(acl)(\/|$)/.test(req.path);
      const scope =
        family +
        ":" +
        (["GET", "HEAD"].includes(req.method) ? "read" : "write");
      if (!family || forbidden || !k.scopes.includes(scope)) {
        await audit(req, "api_key.failure", "denied", "Scope denied", k.id);
        res
          .status(403)
          .json({ error: "Permission denied", requestId: req.requestId });
        return;
      }
      if (k.last_used_ip !== req.ip)
        await audit(
          req,
          "api_key.new_ip",
          "denied",
          "Key used from a new IP",
          k.id,
        );
      await withTenant(k.tenant_id, (c) =>
        c.query(
          "UPDATE api_keys SET last_used_at=now(),last_used_ip=$1 WHERE id=$2",
          [req.ip, k.id],
        ),
      );
      res.on("finish", () => {
        void audit(
          req,
          "api_key.use",
          res.statusCode < 400 ? "allowed" : "denied",
          `${req.method} ${family}; status ${res.statusCode}`,
          k.id,
        ).catch(() =>
          console.error(
            JSON.stringify({ requestId: req.requestId, status: 500 }),
          ),
        );
      });
      next();
    })().catch(next);
  };
}
export function registerApiKeys(
  app: Express,
  guards: RequestHandler[],
  step: RequestHandler,
  audit: Audit,
) {
  const endpoint = (
    method: "get" | "post",
    path: string,
    fn: (req: Request, res: Response) => Promise<unknown>,
  ) =>
    app[method](
      "/api/api-keys" + path,
      ...guards,
      ...(method === "post" ? [step] : []),
      (req, res, next) => {
        if (req.role !== "admin") {
          res
            .status(403)
            .json({ error: "Permission denied", requestId: req.requestId });
          return;
        }
        fn(req, res).catch((e) => {
          if (e instanceof z.ZodError)
            res.status(422).json({
              error: "Invalid key settings",
              requestId: req.requestId,
            });
          else next(e);
        });
      },
    );
  const fields =
    "id,name,key_prefix,scopes,status,expires_at,last_used_at,last_used_ip,rate_limit_per_min,ip_allowlist,created_at";
  endpoint("get", "", async (req, res) => {
    res.json(
      (
        await withTenant(req.session.tenantId!, (c) =>
          c.query(
            `SELECT ${fields} FROM api_keys ORDER BY created_at DESC LIMIT 100`,
          ),
        )
      ).rows,
    );
    await audit(req, "api_key.list");
  });
  const body = z
    .object({
      name: z.string().trim().min(1).max(100),
      scopes: z.array(scopes).min(1).max(6),
      expires_in_days: z.number().int().min(1).max(365).default(90),
      rate_limit_per_min: z.number().int().min(1).max(300).default(60),
      ip_allowlist: z
        .array(
          z
            .string()
            .max(50)
            .regex(/^[a-fA-F0-9:.]+\/\d{1,3}$/)
            .refine((value) => {
              const [ip, prefix] = value.split("/"),
                family = isIP(ip);
              return !!family && Number(prefix) <= (family === 4 ? 32 : 128);
            }),
        )
        .max(20)
        .optional(),
    })
    .strict();
  async function create(req: Request, b: z.infer<typeof body>) {
    const id = randomUUID(),
      prefix = randomBytes(6).toString("base64url"),
      secret = `ws_live_${prefix}_${randomBytes(32).toString("base64url")}`;
    await withTenant(req.session.tenantId!, (c) =>
      c.query(
        "INSERT INTO api_keys(id,tenant_id,created_by,name,key_prefix,key_hash,scopes,expires_at,rate_limit_per_min,ip_allowlist) VALUES($1,$2,$3,$4,$5,$6,$7,now()+$8*interval '1 day',$9,$10)",
        [
          id,
          req.session.tenantId,
          req.session.userId,
          b.name,
          prefix,
          digest(secret),
          b.scopes,
          b.expires_in_days,
          b.rate_limit_per_min,
          b.ip_allowlist ?? null,
        ],
      ),
    );
    return { id, key: secret };
  }
  endpoint("post", "", async (req, res) => {
    const key = await create(req, body.parse(req.body));
    await audit(req, "api_key.create", "allowed", "", key.id);
    res.status(201).json(key);
  });
  endpoint("post", "/:id/revoke", async (req, res) => {
    const id = z.string().uuid().parse(req.params.id);
    z.object({}).strict().parse(req.body);
    await withTenant(req.session.tenantId!, (c) =>
      c.query("UPDATE api_keys SET status='revoked' WHERE id=$1", [id]),
    );
    await audit(req, "api_key.revoke", "allowed", "", id);
    res.json({ ok: true });
  });
  endpoint("post", "/:id/rotate", async (req, res) => {
    z.object({}).strict().parse(req.body);
    const id = z.string().uuid().parse(req.params.id);
    const old = (
      await withTenant(req.session.tenantId!, (c) =>
        c.query(
          "SELECT * FROM api_keys WHERE id=$1 AND status='active' AND expires_at>now()",
          [id],
        ),
      )
    ).rows[0];
    if (!old) {
      res.status(404).json({ error: "Not found", requestId: req.requestId });
      return;
    }
    const key = await create(req, {
      name: old.name,
      scopes: old.scopes,
      expires_in_days: 90,
      rate_limit_per_min: old.rate_limit_per_min,
      ip_allowlist: old.ip_allowlist ?? undefined,
    });
    await withTenant(req.session.tenantId!, (c) =>
      c.query(
        "UPDATE api_keys SET expires_at=least(expires_at,now()+interval '5 minutes') WHERE id=$1",
        [id],
      ),
    );
    await audit(
      req,
      "api_key.rotate",
      "allowed",
      "Old key expires within five minutes",
      id,
    );
    res.status(201).json(key);
  });
}
