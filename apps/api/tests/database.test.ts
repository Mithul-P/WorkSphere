import { describe, it, expect, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { pool, withTenant } from "../src/db/pool.js";
const A = "10000000-0000-4000-8000-000000000001",
  B = "10000000-0000-4000-8000-000000000002",
  BP = "30000000-0000-4000-8000-000000000003";
afterAll(() => pool.end());
describe("real PostgreSQL RLS", () => {
  it("has no context by default and denies unscoped reads", async () => {
    expect((await pool.query("SELECT * FROM projects")).rows).toEqual([]);
  });
  it("application role is neither owner, superuser nor bypassrls", async () => {
    const r = await pool.query(
      "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user",
    );
    expect(r.rows[0]).toEqual({ rolsuper: false, rolbypassrls: false });
    expect(
      (
        await pool.query(
          "SELECT 1 FROM pg_tables WHERE tablename='projects' AND tableowner=current_user",
        )
      ).rows,
    ).toHaveLength(0);
  });
  it("hides other tenant and fails WITH CHECK", async () => {
    expect(
      (
        await withTenant(A, (c) =>
          c.query("SELECT * FROM projects WHERE id=$1", [BP]),
        )
      ).rows,
    ).toHaveLength(0);
    await expect(
      withTenant(A, (c) =>
        c.query(
          "INSERT INTO projects(id,tenant_id,name,created_by) VALUES($1,$2,$3,$4)",
          [randomUUID(), B, "attack", "20000000-0000-4000-8000-000000000001"],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });
  it("does not leak context across concurrent pooled transactions", async () => {
    await Promise.all(
      Array.from({ length: 40 }, (_, i) =>
        withTenant(i % 2 ? A : B, async (c) => {
          const { rows } = await c.query(
            "SELECT DISTINCT tenant_id FROM projects",
          );
          expect(rows).toEqual([{ tenant_id: i % 2 ? A : B }]);
        }),
      ),
    );
    expect((await pool.query("SELECT * FROM projects")).rows).toHaveLength(0);
  });
  it("composite foreign key rejects cross tenant project assignment", async () => {
    await expect(
      withTenant(A, (c) =>
        c.query(
          "INSERT INTO tasks(id,tenant_id,project_id,title) VALUES($1,$2,$3,'attack')",
          [randomUUID(), A, BP],
        ),
      ),
    ).rejects.toThrow(/foreign key/);
  });
  it("audit log is append only", async () => {
    await expect(
      withTenant(A, (c) => c.query("DELETE FROM audit_events")),
    ).rejects.toThrow(/permission denied/);
  });
});
