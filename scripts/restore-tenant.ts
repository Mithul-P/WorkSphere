import "dotenv/config";
import pg from "pg";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { z } from "zod";
import { open, seal, tenantKey } from "../apps/api/src/envelope.js";
import { LocalDisk } from "../apps/api/src/storage.js";
const tid = z.string().uuid().parse(process.argv[2]),
  input = process.argv[3];
if (!input || process.argv[4] !== "--confirm-restore")
  throw new Error(
    "Usage: npm run tenant:restore -- TENANT_UUID backup.ws-export --confirm-restore",
  );
const secret = process.env.OFFBOARD_EXPORT_KEY;
if (!secret || !/^[a-fA-F0-9]{64}$/.test(secret))
  throw new Error("Set OFFBOARD_EXPORT_KEY to the independent archive key");
const archive = JSON.parse(
  open(await readFile(input), Buffer.from(secret, "hex"), tid).toString(),
) as Record<string, unknown>;
const tenant = z
  .object({
    id: z.literal(tid),
    name: z.string().min(1),
    slug: z.string().min(1),
    created_at: z.string(),
  })
  .strict()
  .parse(archive.tenant);
const tables = {
  memberships: ["id", "tenant_id", "user_id", "role", "status", "created_at"],
  tenant_policies: [
    "tenant_id",
    "access_days",
    "access_start",
    "access_end",
    "timezone",
    "require_trusted_device",
  ],
  tenant_data_policy: [
    "tenant_id",
    "allow_content_kinds",
    "allowed_mime_types",
    "max_storage_bytes",
    "max_rows_per_table",
    "max_custom_fields",
    "default_classification",
  ],
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
    "sha256",
    "storage_key",
    "scan_status",
    "version",
    "deleted_at",
    "created_at",
    "updated_at",
  ],
  content_versions: [
    "id",
    "tenant_id",
    "item_id",
    "version",
    "storage_key",
    "sha256",
    "size_bytes",
    "created_by",
    "created_at",
  ],
  content_acl: [
    "id",
    "tenant_id",
    "item_id",
    "principal_type",
    "principal_id",
    "permission",
    "granted_by",
    "expires_at",
    "created_at",
  ],
  audit_events: [
    "id",
    "tenant_id",
    "actor_user_id",
    "action",
    "resource_type",
    "resource_id",
    "outcome",
    "reason",
    "request_id",
    "ip",
    "user_agent",
    "created_at",
  ],
} as const;
const db = new pg.Pool({
    connectionString: process.env.OWNER_DATABASE_URL,
    max: 1,
  }),
  c = await db.connect(),
  storage = new LocalDisk(),
  paths: string[] = [];
try {
  await c.query("BEGIN");
  await c.query("SELECT set_config('app.tenant_id',$1,true)", [tid]);
  await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [tid]);
  if (
    (
      await c.query("SELECT 1 FROM tenants WHERE id=$1 OR slug=$2", [
        tid,
        tenant.slug,
      ])
    ).rows.length
  )
    throw new Error(
      "Restore requires an absent tenant and unused slug; existing data is never overwritten",
    );
  await c.query(
    "INSERT INTO tenants(id,name,slug,created_at) VALUES($1,$2,$3,$4)",
    [tid, tenant.name, tenant.slug, tenant.created_at],
  );
  await c.query(
    "INSERT INTO tenant_data_policy(tenant_id,max_rows_per_table) VALUES($1,1000000)",
    [tid],
  );
  const versions = z
      .array(z.record(z.unknown()))
      .parse(archive.content_versions),
    files = z.record(z.string()).parse(archive.files);
  const key = await tenantKey(c, tid, true),
    storageKeys = new Map<string, string>();
  for (const version of versions) {
    const id = z.string().uuid().parse(version.id),
      bytes = Buffer.from(z.string().parse(files[id]), "base64");
    if (
      !bytes.length ||
      bytes.length > 10485760 ||
      createHash("sha256").update(bytes).digest("hex") !== version.sha256
    )
      throw new Error("Archive file failed integrity validation");
    const path = await storage.put(tid, seal(bytes, key, tid));
    paths.push(path);
    storageKeys.set(id, path);
  }
  for (const [table, columns] of Object.entries(tables)) {
    if (table === "tenant_data_policy") continue;
    for (const row of z.array(z.record(z.unknown())).parse(archive[table])) {
      if (row.tenant_id !== tid) throw new Error("Archive tenant mismatch");
      // Key credentials, old device trust and overrides are intentionally invalidated.
      if (table === "content_acl" && row.principal_type === "api_key") continue;
      if (table === "content_versions")
        row.storage_key = storageKeys.get(String(row.id));
      if (table === "content_items") {
        const version = versions.find(
          (v) => v.item_id === row.id && v.version === row.version,
        );
        if (!version)
          throw new Error("Archive is missing a current file version");
        row.storage_key = storageKeys.get(String(version.id));
      }
      await c.query(
        `INSERT INTO ${table}(${columns.join(",")}) VALUES(${columns.map((_, i) => "$" + (i + 1)).join(",")})`,
        columns.map((col) => row[col] ?? null),
      );
    }
  }
  const policies = z
    .array(z.record(z.unknown()))
    .parse(archive.tenant_data_policy);
  if (policies.length) {
    const p = policies[0];
    if (p.tenant_id !== tid) throw new Error("Archive tenant mismatch");
    const columns = tables.tenant_data_policy.filter(
      (column) => column !== "tenant_id",
    );
    await c.query(
      `UPDATE tenant_data_policy SET ${columns.map((column, i) => column + "=$" + (i + 1)).join(",")} WHERE tenant_id=$${columns.length + 1}`,
      [...columns.map((column) => p[column]), tid],
    );
  }
  await c.query("COMMIT");
  key.fill(0);
  console.log(
    "Tenant restored with new file encryption. API keys, device approvals and access overrides were not restored; issue fresh credentials and approvals.",
  );
} catch (error) {
  await c.query("ROLLBACK");
  for (const path of paths) await storage.remove(tid, path).catch(() => {});
  throw error;
} finally {
  c.release();
  await db.end();
}
