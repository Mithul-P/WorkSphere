import { it, expect, afterAll } from "vitest";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { randomUUID, randomBytes, createHash } from "node:crypto";
import pg from "pg";
import { pool, withTenant } from "../src/db/pool.js";
import { tenantKey, seal, open } from "../src/envelope.js";
import { LocalDisk } from "../src/storage.js";
const owner = new pg.Pool({ connectionString: process.env.OWNER_DATABASE_URL });
const tid = randomUUID(),
  user = "20000000-0000-4000-8000-000000000001",
  item = randomUUID(),
  version = randomUUID();
const root = await mkdtemp(join(tmpdir(), "worksphere-offboard-test-")),
  exportKey = randomBytes(32).toString("hex"),
  archivePath = join(root, "backup.ws-export");
function run(script: string, args: string[]) {
  return new Promise<void>((done, reject) => {
    const p = spawn(
      process.execPath,
      ["node_modules/tsx/dist/cli.mjs", script, ...args],
      {
        env: {
          ...process.env,
          STORAGE_ROOT: root,
          OFFBOARD_EXPORT_KEY: exportKey,
        },
        windowsHide: true,
        stdio: "pipe",
      },
    );
    let output = "";
    p.stderr.on("data", (chunk) => {
      output += chunk.toString();
    });
    p.on("error", reject);
    p.on("exit", (code) => (code === 0 ? done() : reject(new Error(output))));
  });
}
afterAll(async () => {
  const c = await owner.connect();
  try {
    await c.query("BEGIN");
    await c.query("SELECT set_config('app.tenant_id',$1,true)", [tid]);
    for (const table of [
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
      "tenant_keys",
      "memberships",
    ])
      await c.query(`DELETE FROM ${table} WHERE tenant_id=$1`, [tid]);
    await c.query("DELETE FROM tenants WHERE id=$1", [tid]);
    await c.query("COMMIT");
  } finally {
    c.release();
    await owner.end();
    await pool.end();
    if (resolve(root).startsWith(resolve(tmpdir()) + sep))
      await rm(root, { recursive: true, force: true });
  }
});
it("exports, destroys the live DEK, and restores a tenant from an independently encrypted archive", async () => {
  await owner.query(
    "INSERT INTO tenants(id,name,slug) VALUES($1,'Backup fixture',$2)",
    [tid, tid],
  );
  const bytes = Buffer.from("recoverable tenant document"),
    storage = new LocalDisk(root);
  let original: Buffer = Buffer.alloc(0);
  await withTenant(tid, async (c) => {
    await c.query(
      "INSERT INTO memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,'admin')",
      [randomUUID(), tid, user],
    );
    await c.query("INSERT INTO tenant_policies(tenant_id) VALUES($1)", [tid]);
    await c.query("INSERT INTO tenant_data_policy(tenant_id) VALUES($1)", [
      tid,
    ]);
    original = seal(bytes, await tenantKey(c, tid, true), tid);
    const key = await storage.put(tid, original),
      sha = createHash("sha256").update(bytes).digest("hex");
    await c.query(
      "INSERT INTO content_items(id,tenant_id,owner_id,title,kind,mime_type,size_bytes,sha256,storage_key,scan_status) VALUES($1,$2,$3,'Backup test','document','text/plain',$4,$5,$6,'clean')",
      [item, tid, user, bytes.length, sha, key],
    );
    await c.query(
      "INSERT INTO content_versions(id,tenant_id,item_id,version,storage_key,sha256,size_bytes,created_by) VALUES($1,$2,$3,1,$4,$5,$6,$7)",
      [version, tid, item, key, sha, bytes.length, user],
    );
  });
  await run("scripts/offboard.ts", [tid, archivePath, "--confirm-delete"]);
  await expect(withTenant(tid, (c) => tenantKey(c, tid))).rejects.toThrow(
    /unavailable/,
  );
  expect(
    (await owner.query("SELECT 1 FROM tenants WHERE id=$1", [tid])).rows,
  ).toHaveLength(0);
  const archive = open(
    await readFile(archivePath),
    Buffer.from(exportKey, "hex"),
    tid,
  );
  const json = JSON.parse(archive.toString());
  expect(Buffer.from(json.files[version], "base64")).toEqual(bytes);
  expect(json.tenant.id).toBe(tid);
  await run("scripts/restore-tenant.ts", [
    tid,
    archivePath,
    "--confirm-restore",
  ]);
  await withTenant(tid, async (c) => {
    const row = (
        await c.query("SELECT storage_key FROM content_items WHERE id=$1", [
          item,
        ])
      ).rows[0],
      key = await tenantKey(c, tid);
    expect(open(await storage.get(tid, row.storage_key), key, tid)).toEqual(
      bytes,
    );
    expect(() => open(original, key, tid)).toThrow();
  });
}, 30000);
