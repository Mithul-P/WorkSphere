import type { Express, Request, Response, RequestHandler } from "express";
import multer from "multer";
import { rateLimit } from "express-rate-limit";
import { fileTypeFromBuffer } from "file-type";
import { createHash, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import { z } from "zod";
import { withTenant } from "./db/pool.js";
import {
  canAccessContent,
  contentPredicate,
  type ContentAction,
} from "./policy/content.js";
import { LocalDisk } from "./storage.js";
import { tenantKey, seal, open } from "./envelope.js";
type Audit = (
  req: Request,
  action: string,
  outcome?: string,
  reason?: string,
  resourceId?: string,
) => Promise<void>;
type Dependencies = {
  guards: RequestHandler[];
  step: RequestHandler;
  audit: Audit;
};
const storage = new LocalDisk();
const classification = z.enum(["internal", "confidential", "restricted"]);
const uuid = z.string().uuid();
const metadata =
  "i.id,i.project_id,i.owner_id,i.title,i.kind,i.classification,i.mime_type,i.size_bytes,i.sha256,i.scan_status,i.version,i.created_at,i.updated_at";
const hash = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
class ContentError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
function fail(status: number, message: string): never {
  throw new ContentError(status, message);
}
const actor = (req: Request) => ({
  id: req.session.userId!,
  role: req.role,
  tenantId: req.session.tenantId!,
  apiKey: req.apiKey,
});
const upload = multer({
  storage: multer.memoryStorage(),
  preservePath: true,
  limits: {
    fileSize: 10485760,
    files: 1,
    fields: 5,
    fieldSize: 1024,
    parts: 6,
  },
}).single("file");
export function registerContent(
  app: Express,
  { guards, step, audit }: Dependencies,
) {
  const endpoint = (
    method: "get" | "post" | "patch" | "delete" | "put",
    path: string,
    fn: (req: Request, res: Response) => Promise<unknown>,
    extra: RequestHandler[] = [],
  ) => {
    app[method]("/api" + path, ...guards, ...extra, (req, res, next) => {
      fn(req, res).catch(async (e) => {
        try {
          await audit(
            req,
            e instanceof ContentError && /quota/.test(e.message)
              ? "quota.exceeded"
              : "content.denied",
            "denied",
            e instanceof ContentError ? e.message : "Invalid content request",
            uuid.safeParse(req.params.id).success
              ? String(req.params.id)
              : undefined,
          );
        } catch {
          /* Original error is preserved. */
        }
        if (e instanceof ContentError)
          res
            .status(e.status)
            .json({ error: e.message, requestId: req.requestId });
        else if (e instanceof z.ZodError)
          res.status(422).json({
            error: "Invalid content request",
            requestId: req.requestId,
          });
        else next(e);
      });
    });
  };
  async function item(req: Request, action: ContentAction) {
    const id = uuid.parse(req.params.id);
    const row = await withTenant(req.session.tenantId!, async (c) => {
      const a = actor(req);
      if (!(await canAccessContent(c, a, id, "view"))) fail(404, "Not found");
      if (!(await canAccessContent(c, a, id, action)))
        fail(403, "Permission denied");
      const row = (
        await c.query("SELECT * FROM content_items WHERE id=$1", [id])
      ).rows[0];
      return row;
    });
    if (
      row.classification === "restricted" &&
      ["download", "share"].includes(action)
    ) {
      const fresh =
        !!req.session.stepup && Date.now() - req.session.stepup <= 300000;
      await audit(
        req,
        "auth.stepup_check",
        fresh ? "allowed" : "denied",
        "Restricted content",
        id,
      );
      if (!fresh) fail(403, "Fresh verification required");
    }
    return row;
  }
  endpoint("get", "/content", async (req, res) => {
    const b = z
      .object({
        page: z.coerce.number().int().min(1).max(10000).default(1),
        limit: z.coerce.number().int().min(1).max(100).default(30),
        search: z.string().max(150).default(""),
        classification: classification.optional(),
      })
      .strict()
      .parse(req.query);
    const rows = await withTenant(req.session.tenantId!, (c) =>
      c.query(
        `SELECT ${metadata} FROM content_items i WHERE ${contentPredicate} AND ($4='' OR i.title ILIKE '%'||$4||'%') AND ($5::text IS NULL OR i.classification=$5) ORDER BY i.created_at DESC,i.id LIMIT $6 OFFSET $7`,
        [
          req.session.userId!,
          req.role,
          "view",
          b.search,
          b.classification ?? null,
          b.limit,
          (b.page - 1) * b.limit,
          req.apiKey ?? null,
        ],
      ),
    );
    await audit(req, "content.list");
    res.json(rows.rows);
  });
  const save = async (req: Request, res: Response, version = false) => {
    if (req.role === "viewer") fail(403, "Permission denied");
    const existing = version ? await item(req, "edit") : null;
    const b = z
      .object({
        title: z.string().trim().min(1).max(150),
        classification: classification.optional(),
        kind: z.enum(["document", "file"]).default("file"),
        project_id: uuid.optional(),
      })
      .strict()
      .parse(req.body);
    let level = b.classification ?? "internal";
    if (req.apiKey && b.classification === "restricted")
      fail(403, "Permission denied");
    const f = req.file;
    if (!f || !f.size) fail(422, "A non-empty file is required");
    if (
      /[\\/\0]/.test(f.originalname) ||
      f.originalname.includes("..") ||
      /^[A-Za-z]:/.test(f.originalname)
    )
      fail(422, "Invalid file name");
    let type: Awaited<ReturnType<typeof fileTypeFromBuffer>>;
    try {
      type = await fileTypeFromBuffer(f.buffer);
    } catch {
      fail(422, "Unsupported file type");
    }
    let mime = type?.mime;
    if (!mime) {
      const decoded = new TextDecoder("utf-8", { fatal: true });
      try {
        const text = decoded.decode(f.buffer);
        if (
          [...text].some(
            (ch) =>
              ch.charCodeAt(0) < 32 && ![9, 10, 13].includes(ch.charCodeAt(0)),
          )
        )
          fail(422, "Unsupported file type");
      } catch {
        fail(422, "Unsupported file type");
      }
      mime = f.originalname.endsWith(".md")
        ? "text/markdown"
        : f.originalname.endsWith(".csv")
          ? "text/csv"
          : "text/plain";
    }
    const allowed = [
      "application/pdf",
      "image/png",
      "image/jpeg",
      "text/plain",
      "text/markdown",
      "text/csv",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ];
    if (!allowed.includes(mime)) fail(422, "Unsupported file type");
    const tid = req.session.tenantId!,
      id = existing?.id || randomUUID();
    let key: string | undefined;
    try {
      await withTenant(tid, async (c) => {
        await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
          tid,
        ]);
        await c.query(
          "INSERT INTO tenant_data_policy(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
          [tid],
        );
        const p = (
          await c.query(
            "SELECT * FROM tenant_data_policy WHERE tenant_id=$1 FOR UPDATE",
            [tid],
          )
        ).rows[0];
        level = b.classification ?? p.default_classification;
        if (req.apiKey && level === "restricted")
          fail(403, "Permission denied");
        const used = (
          await c.query(
            "SELECT coalesce(sum(size_bytes),0) AS bytes,count(*) AS rows FROM content_versions",
          )
        ).rows[0];
        const count = (
          await c.query(
            "SELECT count(*) FROM content_items WHERE deleted_at IS NULL",
          )
        ).rows[0].count;
        if (
          !p.allow_content_kinds.includes(b.kind) ||
          !p.allowed_mime_types.includes(mime) ||
          Number(used.bytes) + f.size > Number(p.max_storage_bytes) ||
          (!version && Number(count) >= p.max_rows_per_table)
        )
          fail(422, "Tenant data policy or quota exceeded");
        if (
          b.project_id &&
          !(await c.query("SELECT 1 FROM projects WHERE id=$1", [b.project_id]))
            .rows.length
        )
          fail(422, "Invalid project");
        key = await storage.put(
          tid,
          seal(f.buffer, await tenantKey(c, tid, true), tid),
        );
        const digest = hash(f.buffer),
          v = existing ? existing.version + 1 : 1;
        if (version)
          await c.query(
            "UPDATE content_items SET storage_key=$1,sha256=$2,size_bytes=$3,mime_type=$4,version=$5,scan_status='clean',updated_at=now() WHERE id=$6",
            [key, digest, f.size, mime, v, id],
          );
        else {
          await c.query(
            "INSERT INTO content_items(id,tenant_id,owner_id,title,kind,classification,project_id,mime_type,size_bytes,sha256,storage_key,scan_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'clean')",
            [
              id,
              tid,
              req.session.userId!,
              b.title,
              b.kind,
              level,
              b.project_id ?? null,
              mime,
              f.size,
              digest,
              key,
            ],
          );
          // Restricted owners need an explicit grant as required by the classification rule.
          if (level === "restricted")
            await c.query(
              "INSERT INTO content_acl(id,tenant_id,item_id,principal_type,principal_id,permission,granted_by) VALUES($1,$2,$3,'user',$4,'manage',$5)",
              [randomUUID(), tid, id, req.session.userId!, req.session.userId!],
            );
          if (req.apiKey)
            await c.query(
              "INSERT INTO content_acl(id,tenant_id,item_id,principal_type,principal_id,permission,granted_by) VALUES($1,$2,$3,'api_key',$4,'manage',$5)",
              [randomUUID(), tid, id, req.apiKey, req.session.userId],
            );
        }
        await c.query(
          "INSERT INTO content_versions(id,tenant_id,item_id,version,storage_key,sha256,size_bytes,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
          [randomUUID(), tid, id, v, key, digest, f.size, req.session.userId!],
        );
      });
    } catch (e) {
      if (key) await storage.remove(tid, key).catch(() => {});
      throw e;
    }
    await audit(
      req,
      version ? "content.version" : "content.upload",
      "allowed",
      level,
      id,
    );
    res.status(201).json({ id });
  };
  const uploadLimit = rateLimit({
    windowMs: 60000,
    limit: 20,
    keyGenerator: (req) => req.session.userId!,
  });
  endpoint("post", "/content", (req, res) => save(req, res), [
    uploadLimit,
    upload,
  ]);
  endpoint(
    "post",
    "/content/:id/versions",
    (req, res) => save(req, res, true),
    [uploadLimit, upload],
  );
  endpoint("get", "/content/:id", async (req, res) => {
    const row = await item(req, "view");
    const publicRow = Object.fromEntries(
      Object.entries(row).filter(
        ([k]) => !["storage_key", "tenant_id", "deleted_at"].includes(k),
      ),
    );
    const permissions = await withTenant(req.session.tenantId!, async (c) => {
      const actions: ContentAction[] = [
        "view",
        "download",
        "edit",
        "share",
        "manage",
      ];
      const allowed = [];
      for (const action of actions)
        if (await canAccessContent(c, actor(req), row.id, action))
          allowed.push(action);
      return allowed;
    });
    await audit(req, "content.view", "allowed", row.classification, row.id);
    res.json({ ...publicRow, permissions });
  });
  endpoint("get", "/content/:id/versions", async (req, res) => {
    const row = await item(req, "view");
    res.json(
      (
        await withTenant(req.session.tenantId!, (c) =>
          c.query(
            "SELECT id,version,sha256,size_bytes,created_by,created_at FROM content_versions WHERE item_id=$1 ORDER BY version DESC LIMIT 100",
            [row.id],
          ),
        )
      ).rows,
    );
    await audit(req, "content.versions", "allowed", "", row.id);
  });
  const serve = async (req: Request, res: Response) => {
    const row = await item(req, "download");
    const preview = req.path.endsWith("/preview");
    if (
      preview &&
      !["application/pdf", "image/png", "image/jpeg"].includes(row.mime_type)
    )
      fail(422, "This file type is download-only");
    let bytes: Buffer;
    try {
      bytes = await withTenant(req.session.tenantId!, async (c) => {
        await c.query(
          "SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))",
          [req.session.tenantId],
        );
        const current = (
          await c.query(
            "SELECT * FROM content_items WHERE id=$1 AND deleted_at IS NULL",
            [row.id],
          )
        ).rows[0];
        if (!current) fail(404, "Not found");
        if (!(await canAccessContent(c, actor(req), row.id, "download")))
          fail(403, "Permission denied");
        if (
          current.classification === "restricted" &&
          (!req.session.stepup || Date.now() - req.session.stepup > 300000)
        )
          fail(403, "Fresh verification required");
        Object.assign(row, current);
        const key = await tenantKey(c, req.session.tenantId!);
        return open(
          await storage.get(req.session.tenantId!, current.storage_key),
          key,
          req.session.tenantId!,
        );
      });
    } catch (error) {
      if (error instanceof ContentError) throw error;
      await audit(
        req,
        "content.hash_mismatch",
        "failed",
        "Encrypted file integrity failure",
        row.id,
      );
      fail(409, "File integrity check failed");
    }
    if (hash(bytes) !== row.sha256) {
      await audit(
        req,
        "content.hash_mismatch",
        "failed",
        "Integrity failure",
        row.id,
      );
      fail(409, "File integrity check failed");
    }
    await audit(
      req,
      preview ? "content.preview" : "content.download",
      "allowed",
      `${row.classification}; ${row.size_bytes} bytes; version ${row.version}`,
      row.id,
    );
    res.set({
      "Content-Type": row.mime_type,
      "Content-Disposition": `${preview ? "inline" : "attachment"}; filename="download"`,
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "private, no-store",
      "Content-Security-Policy": "default-src 'none'; sandbox",
    });
    Readable.from(bytes).pipe(res);
  };
  const downloadLimit = rateLimit({
    windowMs: 60000,
    limit: 30,
    keyGenerator: (req) => req.session.userId!,
  });
  endpoint("get", "/content/:id/download", serve, [downloadLimit]);
  endpoint("get", "/content/:id/preview", serve, [downloadLimit]);
  endpoint("patch", "/content/:id", async (req, res) => {
    const row = await item(req, "edit");
    const b = z
      .object({
        title: z.string().trim().min(1).max(150).optional(),
        classification: classification.optional(),
      })
      .strict()
      .parse(req.body);
    if (b.classification && b.classification !== row.classification)
      await item(req, "manage");
    await withTenant(req.session.tenantId!, (c) =>
      c.query(
        "UPDATE content_items SET title=coalesce($1,title),classification=coalesce($2,classification),updated_at=now() WHERE id=$3",
        [b.title, b.classification, row.id],
      ),
    );
    await audit(
      req,
      b.classification ? "content.classification" : "content.edit",
      "allowed",
      b.classification || "",
      row.id,
    );
    res.json({ ok: true });
  });
  endpoint("delete", "/content/:id", async (req, res) => {
    const row = await item(req, "manage");
    await withTenant(req.session.tenantId!, (c) =>
      c.query("UPDATE content_items SET deleted_at=now() WHERE id=$1", [
        row.id,
      ]),
    );
    await audit(req, "content.delete", "allowed", "", row.id);
    res.json({ ok: true });
  });
  endpoint("get", "/content/:id/acl", async (req, res) => {
    const row = await item(req, "share");
    res.json(
      (
        await withTenant(req.session.tenantId!, (c) =>
          c.query(
            "SELECT id,principal_type,principal_id,permission,expires_at FROM content_acl WHERE item_id=$1 ORDER BY created_at LIMIT 100",
            [row.id],
          ),
        )
      ).rows,
    );
    await audit(req, "content.acl", "allowed", "", row.id);
  });
  endpoint("put", "/content/:id/acl", async (req, res) => {
    const row = await item(req, "share");
    const b = z
      .object({
        principal_type: z.enum(["user", "role", "api_key"]),
        principal_id: z.string().max(50),
        permission: z.enum(["view", "download", "edit", "share", "manage"]),
        expires_at: z.string().datetime().optional(),
      })
      .strict()
      .parse(req.body);
    if (req.role !== "admin" && b.permission === "manage")
      fail(403, "Permission denied");
    await withTenant(req.session.tenantId!, async (c) => {
      if (
        b.principal_type === "user" &&
        (!uuid.safeParse(b.principal_id).success ||
          !(
            await c.query(
              "SELECT 1 FROM memberships WHERE user_id=$1 AND status='active'",
              [b.principal_id],
            )
          ).rows.length)
      )
        fail(422, "Invalid principal");
      if (
        b.principal_type === "role" &&
        !["admin", "member", "viewer"].includes(b.principal_id)
      )
        fail(422, "Invalid principal");
      if (
        b.principal_type === "api_key" &&
        (!uuid.safeParse(b.principal_id).success ||
          !(
            await c.query(
              "SELECT 1 FROM api_keys WHERE id=$1 AND status='active' AND expires_at>now()",
              [b.principal_id],
            )
          ).rows.length)
      )
        fail(422, "Invalid principal");
      await c.query(
        "INSERT INTO content_acl(id,tenant_id,item_id,principal_type,principal_id,permission,granted_by,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,item_id,principal_type,principal_id,permission) DO UPDATE SET expires_at=excluded.expires_at",
        [
          randomUUID(),
          req.session.tenantId!,
          row.id,
          b.principal_type,
          b.principal_id,
          b.permission,
          req.session.userId!,
          b.expires_at ?? null,
        ],
      );
    });
    await audit(req, "content.share", "allowed", b.permission, row.id);
    res.json({ ok: true });
  });
  endpoint("delete", "/content/:id/acl/:aclId", async (req, res) => {
    const row = await item(req, "share");
    await withTenant(req.session.tenantId!, (c) =>
      c.query("DELETE FROM content_acl WHERE item_id=$1 AND id=$2", [
        row.id,
        uuid.parse(req.params.aclId),
      ]),
    );
    await audit(req, "content.unshare", "allowed", "", row.id);
    res.json({ ok: true });
  });
  endpoint(
    "post",
    "/admin/keys/rotate",
    async (req, res) => {
      if (req.role !== "admin") fail(403, "Permission denied");
      z.object({}).strict().parse(req.body);
      const id = randomUUID();
      await withTenant(req.session.tenantId!, async (c) => {
        await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
          req.session.tenantId,
        ]);
        if (
          (
            await c.query(
              "SELECT 1 FROM key_rotation_jobs WHERE status IN ('queued','running')",
            )
          ).rows.length
        )
          fail(409, "A rotation is already pending");
        await c.query(
          "INSERT INTO key_rotation_jobs(id,tenant_id,created_by) VALUES($1,$2,$3)",
          [id, req.session.tenantId, req.session.userId],
        );
      });
      await audit(req, "key.rotation_queued", "allowed", "", id);
      res.status(202).json({ id, status: "queued" });
    },
    [step],
  );
  endpoint("get", "/admin/keys/rotation", async (req, res) => {
    if (req.role !== "admin") fail(403, "Permission denied");
    res.json(
      (
        await withTenant(req.session.tenantId!, (c) =>
          c.query(
            "SELECT id,status,completed_versions,created_at,finished_at FROM key_rotation_jobs ORDER BY created_at DESC LIMIT 10",
          ),
        )
      ).rows,
    );
  });
}
