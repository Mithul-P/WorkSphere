import type { Express, Request, Response, RequestHandler } from "express";
import { z } from "zod";
import { rateLimit } from "express-rate-limit";
import { withTenant } from "./db/pool.js";
type Audit = (
  req: Request,
  action: string,
  outcome?: string,
  reason?: string,
  resourceId?: string,
) => Promise<void>;
export const datasets = {
  projects: [
    "id",
    "tenant_id",
    "name",
    "description",
    "created_by",
    "created_at",
  ],
  tasks: [
    "id",
    "tenant_id",
    "project_id",
    "title",
    "status",
    "assignee_id",
    "created_at",
  ],
  content_items: [
    "id",
    "tenant_id",
    "project_id",
    "owner_id",
    "title",
    "kind",
    "classification",
    "mime_type",
    "size_bytes",
    "scan_status",
    "version",
    "created_at",
  ],
  members: ["id", "tenant_id", "user_id", "role", "status", "created_at"],
  api_keys: [
    "id",
    "tenant_id",
    "name",
    "key_prefix",
    "scopes",
    "status",
    "expires_at",
    "last_used_at",
    "created_at",
  ],
  audit: [
    "id",
    "tenant_id",
    "actor_user_id",
    "action",
    "outcome",
    "resource_type",
    "resource_id",
    "reason",
    "request_id",
    "created_at",
  ],
} as const;
export function csvCell(value: unknown) {
  const text =
    value === null || value === undefined
      ? ""
      : typeof value === "object"
        ? JSON.stringify(value)
        : String(value);
  const safe = /^[\s]*[=+@-]/.test(text) ? "'" + text : text;
  return '"' + safe.replaceAll('"', '""') + '"';
}
export function registerExplorer(
  app: Express,
  guards: RequestHandler[],
  step: RequestHandler,
  audit: Audit,
) {
  const endpoint = (
    method: "get" | "put",
    path: string,
    fn: (req: Request, res: Response) => Promise<unknown>,
    extra: RequestHandler[] = [],
  ) =>
    app[method]("/api" + path, ...guards, ...extra, (req, res, next) => {
      if (req.role !== "admin") {
        res
          .status(403)
          .json({ error: "Permission denied", requestId: req.requestId });
        return;
      }
      fn(req, res).catch((e) => {
        if (e instanceof z.ZodError)
          res.status(422).json({
            error: "Invalid explorer or policy request",
            requestId: req.requestId,
          });
        else next(e);
      });
    });
  endpoint("get", "/explorer", async (req, res) => {
    const result = await withTenant(req.session.tenantId!, async (c) => {
      const rows = [];
      for (const [name, columns] of Object.entries(datasets)) {
        // Dataset identifiers come exclusively from this fixed allow-list.
        const count = (
          await c.query(
            `SELECT count(*) FROM explorer_${name}${name === "content_items" ? " WHERE content_can_access($1::uuid,$2::text,id,'view',null::uuid)" : ""}`,
            name === "content_items" ? [req.session.userId, req.role] : [],
          )
        ).rows[0].count;
        rows.push({ name, columns, count: Number(count) });
      }
      return rows;
    });
    await audit(req, "explorer.list");
    res.json(result);
  });
  endpoint("get", "/security-alerts", async (req, res) => {
    const rows = await withTenant(req.session.tenantId!, async (c) => {
      const events = (
        await c.query(
          "SELECT actor_user_id, count(*) FILTER(WHERE action='content.download')::int AS downloads,count(*) FILTER(WHERE action='content.denied')::int AS denied FROM audit_events WHERE created_at>now()-interval '5 minutes' GROUP BY actor_user_id HAVING count(*) FILTER(WHERE action='content.download')>=10 OR count(*) FILTER(WHERE action='content.denied')>=10 LIMIT 30",
        )
      ).rows;
      const recent = (
        await c.query(
          "SELECT action,reason,created_at FROM audit_events WHERE created_at>now()-interval '5 minutes' AND (action IN ('api_key.new_ip','api_key.spike','quota.exceeded','content.hash_mismatch') OR (action IN ('content.download','content.view','content.share') AND reason LIKE '%restricted%')) ORDER BY created_at DESC LIMIT 30",
        )
      ).rows;
      const quota = (
        await c.query(
          "SELECT coalesce(sum(v.size_bytes),0) AS used,p.max_storage_bytes FROM tenant_data_policy p LEFT JOIN content_versions v ON v.tenant_id=p.tenant_id GROUP BY p.max_storage_bytes",
        )
      ).rows[0];
      return {
        events,
        recent,
        quota_near_limit: quota
          ? Number(quota.used) >= Number(quota.max_storage_bytes) * 0.8
          : false,
      };
    });
    res.json(rows);
  });
  async function query(req: Request, exporting = false) {
    const dataset = z
      .enum([
        "projects",
        "tasks",
        "content_items",
        "members",
        "api_keys",
        "audit",
      ])
      .parse(req.params.dataset);
    const b = z
      .object({
        page: z.coerce.number().int().min(1).max(10000).default(1),
        filter: z.string().max(150).default(""),
        sort: z.enum(["created_at", "id"]).default("created_at"),
        direction: z.enum(["asc", "desc"]).default("desc"),
      })
      .strict()
      .parse(req.query);
    const columns = datasets[dataset];
    const rows = await withTenant(req.session.tenantId!, (c) =>
      c.query(
        `SELECT ${columns.join(",")} FROM explorer_${dataset} WHERE ($1='' OR concat_ws(' ',${columns.join(",")}) ILIKE '%'||$1||'%')${dataset === "content_items" ? " AND content_can_access($4::uuid,$5::text,id,'view',null::uuid)" + (exporting ? " AND classification<>'restricted'" : "") : ""} ORDER BY ${b.sort} ${b.direction},id LIMIT $2 OFFSET $3`,
        [
          b.filter,
          exporting ? 1000 : 30,
          exporting ? 0 : (b.page - 1) * 30,
          ...(dataset === "content_items"
            ? [req.session.userId, req.role]
            : []),
        ],
      ),
    );
    return { dataset, columns, rows: rows.rows };
  }
  endpoint(
    "get",
    "/explorer/:dataset/export.csv",
    async (req, res) => {
      const r = await query(req, true);
      // Restricted content is excluded even though the explorer contains metadata only.
      const rows = r.rows.filter((row) => row.classification !== "restricted");
      await audit(
        req,
        "explorer.export",
        "allowed",
        `${r.dataset}; ${rows.length} rows; cap 1000`,
      );
      res
        .set({
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="${r.dataset}.csv"`,
          "Cache-Control": "private, no-store",
        })
        .send(
          [
            r.columns.map(csvCell).join(","),
            ...rows.map((row) =>
              r.columns.map((col) => csvCell(row[col])).join(","),
            ),
          ].join("\r\n"),
        );
    },
    [
      step,
      rateLimit({
        windowMs: 60000,
        limit: 5,
        keyGenerator: (req) => req.session.userId!,
      }),
    ],
  );
  endpoint("get", "/explorer/:dataset", async (req, res) => {
    const r = await query(req);
    await audit(req, "explorer.view", "allowed", r.dataset);
    res.json(r);
  });
  endpoint("get", "/data-policy", async (req, res) => {
    const r = await withTenant(req.session.tenantId!, async (c) => {
      await c.query(
        "INSERT INTO tenant_data_policy(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
        [req.session.tenantId],
      );
      const policy = (await c.query("SELECT * FROM tenant_data_policy"))
        .rows[0];
      const used = (
        await c.query(
          "SELECT coalesce(sum(size_bytes),0) AS storage_bytes,count(*) AS versions FROM content_versions",
        )
      ).rows[0];
      return { policy, usage: used };
    });
    res.json(r);
  });
  endpoint(
    "put",
    "/data-policy",
    async (req, res) => {
      const b = z
        .object({
          allow_content_kinds: z.array(z.enum(["document", "file"])).max(2),
          allowed_mime_types: z
            .array(z.string().min(1).max(150))
            .min(1)
            .max(20),
          max_storage_bytes: z.number().int().min(1).max(1099511627776),
          max_rows_per_table: z.number().int().min(1).max(1000000),
          max_custom_fields: z.number().int().min(0).max(100),
          default_classification: z
            .enum(["internal", "confidential", "restricted"])
            .default("internal"),
        })
        .strict()
        .parse(req.body);
      await withTenant(req.session.tenantId!, (c) =>
        c.query(
          "UPDATE tenant_data_policy SET allow_content_kinds=$1,allowed_mime_types=$2,max_storage_bytes=$3,max_rows_per_table=$4,max_custom_fields=$5,default_classification=$7 WHERE tenant_id=$6",
          [
            b.allow_content_kinds,
            b.allowed_mime_types,
            b.max_storage_bytes,
            b.max_rows_per_table,
            b.max_custom_fields,
            req.session.tenantId,
            b.default_classification,
          ],
        ),
      );
      await audit(req, "policy.data_changed");
      res.json({ ok: true });
    },
    [step],
  );
}
