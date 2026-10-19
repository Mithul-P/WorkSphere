import "dotenv/config";
import pg from "pg";
import { z } from "zod";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { tenantKey, open, seal } from "../apps/api/src/envelope.js";
import { LocalDisk } from "../apps/api/src/storage.js";
// Explicit operator command; this file is never imported into the HTTP server.
const tid = z.string().uuid().parse(process.argv[2]);
const output = process.argv[3];
if (
  !output ||
  !output.endsWith(".ws-export") ||
  process.argv[4] !== "--confirm-delete"
)
  throw new Error(
    "Usage: npm run tenant:offboard -- TENANT_UUID output.ws-export --confirm-delete",
  );
const exportKey = process.env.OFFBOARD_EXPORT_KEY;
if (!exportKey || !/^[a-fA-F0-9]{64}$/.test(exportKey))
  throw new Error(
    "Set a separate OFFBOARD_EXPORT_KEY (64 hex characters) before offboarding",
  );
const db = new pg.Pool({
  connectionString: process.env.OWNER_DATABASE_URL,
  max: 1,
});
const c = await db.connect(),
  storage = new LocalDisk();
const tables = [
  "key_rotation_jobs",
  "content_acl",
  "content_versions",
  "content_items",
  "api_keys",
  "tasks",
  "projects",
  "trusted_devices",
  "access_overrides",
  "tenant_data_policy",
  "tenant_policies",
  "audit_events",
  "memberships",
];
let committed = false;
try {
  await c.query("BEGIN");
  await c.query("SELECT set_config('app.tenant_id',$1,true)", [tid]);
  await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [tid]);
  // Block changes during the export/delete transaction, including non-upload routes.
  for (const table of [...tables, "tenant_keys"])
    await c.query(`LOCK TABLE ${table} IN EXCLUSIVE MODE`);
  const exists = (
    await c.query("SELECT id,name,slug,created_at FROM tenants WHERE id=$1", [
      tid,
    ])
  ).rows[0];
  if (!exists) throw new Error("Tenant not found");
  const data: Record<string, unknown> = { tenant: exists },
    files: Record<string, string> = {};
  const versions = (
    await c.query(
      "SELECT id,storage_key FROM content_versions WHERE tenant_id=$1",
      [tid],
    )
  ).rows;
  const key = versions.length ? await tenantKey(c, tid) : null;
  for (const v of versions)
    files[v.id] = open(
      await storage.get(tid, v.storage_key),
      key!,
      tid,
    ).toString("base64");
  for (const table of tables) {
    const rows = (
      await c.query(`SELECT * FROM ${table} WHERE tenant_id=$1`, [tid])
    ).rows;
    // Exports omit bearer hashes, secrets, device tokens and internal paths.
    data[table] = rows.map((row) =>
      Object.fromEntries(
        Object.entries(row).filter(
          ([name]) =>
            !["key_hash", "device_token_hash", "storage_key"].includes(name),
        ),
      ),
    );
  }
  data.files = files;
  const archive = seal(
    Buffer.from(JSON.stringify(data)),
    Buffer.from(exportKey, "hex"),
    tid,
  );
  // Never overwrite an existing backup. Verify the new encrypted archive before deletion.
  open(archive, Buffer.from(exportKey, "hex"), tid);
  await writeFile(resolve(output), archive, { flag: "wx", mode: 0o600 });
  for (const table of tables)
    await c.query(`DELETE FROM ${table} WHERE tenant_id=$1`, [tid]);
  await c.query("DELETE FROM tenant_keys WHERE tenant_id=$1", [tid]);
  await c.query("DELETE FROM session WHERE sess->>'tenantId'=$1", [tid]);
  await c.query("DELETE FROM tenants WHERE id=$1", [tid]);
  await c.query("COMMIT");
  committed = true;
  if (key) key.fill(0);
  for (const v of versions) await storage.remove(tid, v.storage_key);
  console.log(
    "Encrypted export verified; live tenant rows, file versions and DEK removed. Retained backups require separate retention and key-destruction procedures.",
  );
} catch (error) {
  if (!committed) await c.query("ROLLBACK");
  if (committed)
    console.error(
      "Rows and DEK removed; some encrypted files may need operator cleanup.",
    );
  throw error;
} finally {
  c.release();
  await db.end();
}
