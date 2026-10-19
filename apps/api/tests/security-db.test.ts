import { describe, it, expect, afterAll } from "vitest";
import pg from "pg";
import { randomUUID } from "node:crypto";
import { pool, withTenant } from "../src/db/pool.js";
import { auditDatabase } from "../src/db/audit.js";
const owner = new pg.Pool({ connectionString: process.env.OWNER_DATABASE_URL });
const A = "10000000-0000-4000-8000-000000000001",
  B = "10000000-0000-4000-8000-000000000002";
afterAll(async () => {
  await pool.end();
  await owner.end();
});
describe("security extension database boundary", () => {
  it("passes audit and detects an unprotected tenant table", async () => {
    expect(await auditDatabase(pool)).toEqual([]);
    const c = await owner.connect();
    try {
      await c.query("BEGIN");
      await c.query("CREATE TABLE security_audit_probe(tenant_id uuid)");
      expect((await auditDatabase(c)).join(" ")).toMatch(
        /security_audit_probe/,
      );
    } finally {
      await c.query("ROLLBACK");
      c.release();
    }
  });
  it("rejects changing tenant_id even with another valid tenant context", async () => {
    await expect(
      withTenant(A, (c) =>
        c.query("UPDATE projects SET tenant_id=$1 WHERE tenant_id=$2", [B, A]),
      ),
    ).rejects.toThrow(/immutable/);
  });
  it("blocks application DDL and secret catalog access", async () => {
    await expect(
      pool.query("CREATE TABLE forbidden_test(id int)"),
    ).rejects.toThrow(/permission denied/);
    await expect(pool.query("SELECT * FROM pg_authid")).rejects.toThrow(
      /permission denied/,
    );
    await expect(
      pool.query("ALTER TABLE projects ADD COLUMN forbidden int"),
    ).rejects.toThrow(/owner/);
  });
  it("readonly can inspect tenant views but cannot read secret columns", async () => {
    const c = await owner.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL ROLE worksphere_readonly");
      await c.query("SELECT set_config('app.tenant_id',$1,true)", [A]);
      expect(
        (await c.query("SELECT DISTINCT tenant_id FROM explorer_projects"))
          .rows,
      ).toEqual([{ tenant_id: A }]);
      await expect(c.query("SELECT key_hash FROM api_keys")).rejects.toThrow(
        /permission denied/,
      );
    } finally {
      await c.query("ROLLBACK");
      c.release();
    }
  });
  it("isolates new content tables across reused pool connections", async () => {
    await Promise.all(
      Array.from({ length: 30 }, (_, i) =>
        withTenant(i % 2 ? A : B, async (c) => {
          expect(
            (
              await c.query("SELECT * FROM content_items WHERE tenant_id<>$1", [
                i % 2 ? A : B,
              ])
            ).rows,
          ).toEqual([]);
          expect(
            (
              await c.query("SELECT * FROM content_acl WHERE tenant_id<>$1", [
                i % 2 ? A : B,
              ])
            ).rows,
          ).toEqual([]);
        }),
      ),
    );
  });
  it("rejects content ownership outside the tenant at database level", async () => {
    await expect(
      withTenant(A, (c) =>
        c.query(
          `INSERT INTO content_items(id,tenant_id,owner_id,title,kind,mime_type,size_bytes,sha256,storage_key,scan_status) VALUES($1,$2,$3,'test','file','text/plain',1,$4,'test','clean')`,
          [
            randomUUID(),
            A,
            "20000000-0000-4000-8000-000000000004",
            "a".repeat(64),
          ],
        ),
      ),
    ).rejects.toThrow(/foreign key/);
  });
});
