import { describe, it, expect, beforeAll, afterAll } from "vitest";
import request from "supertest";
import pg from "pg";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { authenticator, decrypt } from "../src/crypto.js";
import { pool, withTenant } from "../src/db/pool.js";
import { tenantKey, open } from "../src/envelope.js";
import { rotateTenantFiles, runRotationJob } from "../src/key-lifecycle.js";
const A = "10000000-0000-4000-8000-000000000001",
  B = "10000000-0000-4000-8000-000000000002";
const uid = (n: number) => `20000000-0000-4000-8000-00000000000${n}`;
const owner = new pg.Pool({ connectionString: process.env.OWNER_DATABASE_URL });
const root = await mkdtemp(join(tmpdir(), "worksphere-content-test-"));
process.env.STORAGE_ROOT = root;
const { app } = await import("../src/app.js");
async function login(name: string, n: number) {
  const agent = request.agent(app);
  await owner.query(
    "UPDATE users SET failed_attempts=0,locked_until=NULL,last_used_counter=-1 WHERE id=$1",
    [uid(n)],
  );
  const secret = decrypt(
    (
      await owner.query("SELECT totp_secret_encrypted FROM users WHERE id=$1", [
        uid(n),
      ])
    ).rows[0].totp_secret_encrypted,
  );
  let csrf = (await agent.get("/api/auth/csrf")).body.csrf;
  const r = await agent
    .post("/api/auth/login")
    .set("Origin", process.env.WEB_ORIGIN!)
    .set("X-CSRF-Token", csrf)
    .send({
      email: name + "@worksphere.test",
      password: "Demo-WorkSphere-2026!",
      totp: authenticator.generate(secret),
    });
  expect(r.status).toBe(200);
  csrf = r.body.csrf;
  const write = (method: "post" | "put" | "patch" | "delete", path: string) =>
    agent[method](path)
      .set("Origin", process.env.WEB_ORIGIN!)
      .set("X-CSRF-Token", csrf);
  expect(
    (
      await write("post", "/api/session/workspace").send({
        tenantId: n === 4 ? B : A,
      })
    ).status,
  ).toBe(200);
  const step = async () => {
    await owner.query("UPDATE users SET last_used_counter=-1 WHERE id=$1", [
      uid(n),
    ]);
    expect(
      (
        await write("post", "/api/auth/stepup").send({
          totp: authenticator.generate(secret),
        })
      ).status,
    ).toBe(200);
  };
  return { agent, write, step };
}
let alice: Awaited<ReturnType<typeof login>>,
  bob: Awaited<ReturnType<typeof login>>,
  carol: Awaited<ReturnType<typeof login>>,
  dave: Awaited<ReturnType<typeof login>>;
let itemId: string;
const upload = (
  client: typeof alice,
  fields: Record<string, string> = {},
  bytes = Buffer.from("private project notes"),
  name = "notes.txt",
) => {
  let r = client.write("post", "/api/content").field("title", "Notes");
  for (const [k, v] of Object.entries(fields)) r = r.field(k, v);
  return r.attach("file", bytes, name);
};
beforeAll(async () => {
  for (const t of [A, B])
    await withTenant(t, (c) =>
      c.query(
        "UPDATE tenant_policies SET require_trusted_device=false,access_days=ARRAY[0,1,2,3,4,5,6],access_start='00:00',access_end='23:59:59'",
      ),
    );
  alice = await login("alice", 1);
  bob = await login("bob", 2);
  carol = await login("carol", 3);
  dave = await login("dave", 4);
});
afterAll(async () => {
  await withTenant(A, (c) =>
    c.query(
      "UPDATE tenant_policies SET require_trusted_device=true,access_days=ARRAY[1,2,3,4,5],access_start='09:00',access_end='18:00'",
    ),
  );
  await pool.end();
  await owner.end();
  if (
    resolve(root).startsWith(resolve(tmpdir()) + "\\") ||
    resolve(root).startsWith(resolve(tmpdir()) + "/")
  )
    await rm(root, { recursive: true, force: true });
});
describe("secure tenant content", () => {
  it("uploads a confidential item and never returns storage paths", async () => {
    const r = await upload(alice, { classification: "confidential" });
    expect(r.status).toBe(201);
    itemId = r.body.id;
    const detail = await alice.agent.get(`/api/content/${itemId}`);
    expect(detail.status).toBe(200);
    expect(detail.body.storage_key).toBeUndefined();
  });
  it("uses uniform 404 for foreign content, versions, downloads and ACL", async () => {
    for (const suffix of ["", "/download", "/versions", "/acl"])
      expect(
        (await dave.agent.get(`/api/content/${itemId}${suffix}`)).status,
      ).toBe(404);
    expect((await bob.agent.get(`/api/content/${itemId}`)).status).toBe(404);
    expect(
      (await bob.agent.get("/api/content")).body.some(
        (r: { id: string }) => r.id === itemId,
      ),
    ).toBe(false);
  });
  it("rejects cross-company grants in API and database", async () => {
    expect(
      (
        await alice.write("put", `/api/content/${itemId}/acl`).send({
          principal_type: "user",
          principal_id: uid(4),
          permission: "view",
        })
      ).status,
    ).toBe(422);
    await expect(
      withTenant(A, (c) =>
        c.query(
          "INSERT INTO content_acl(id,tenant_id,item_id,principal_type,principal_id,permission,granted_by) VALUES($1,$2,$3,'user',$4,'view',$5)",
          [randomUUID(), A, itemId, uid(4), uid(1)],
        ),
      ),
    ).rejects.toThrow(/Invalid content principal/);
  });
  it("grants view while preserving the viewer role ceiling", async () => {
    expect(
      (
        await alice.write("put", `/api/content/${itemId}/acl`).send({
          principal_type: "user",
          principal_id: uid(3),
          permission: "manage",
        })
      ).status,
    ).toBe(200);
    expect((await carol.agent.get(`/api/content/${itemId}`)).status).toBe(200);
    for (const method of ["patch", "delete"] as const)
      expect(
        (
          await carol
            .write(method, `/api/content/${itemId}`)
            .send(method === "patch" ? { title: "attack" } : {})
        ).status,
      ).toBe(403);
  });
  it("expires and revokes ACL entries immediately", async () => {
    const grant = {
      principal_type: "user",
      principal_id: uid(2),
      permission: "view",
    };
    expect(
      (
        await alice
          .write("put", `/api/content/${itemId}/acl`)
          .send({ ...grant, expires_at: "2020-01-01T00:00:00.000Z" })
      ).status,
    ).toBe(200);
    expect((await bob.agent.get(`/api/content/${itemId}`)).status).toBe(404);
    await alice.write("put", `/api/content/${itemId}/acl`).send(grant);
    expect((await bob.agent.get(`/api/content/${itemId}`)).status).toBe(200);
    const acl = (await alice.agent.get(`/api/content/${itemId}/acl`)).body.find(
      (r: { principal_id: string }) => r.principal_id === uid(2),
    );
    await alice
      .write("delete", `/api/content/${itemId}/acl/${acl.id}`)
      .send({});
    expect((await bob.agent.get(`/api/content/${itemId}`)).status).toBe(404);
  });
  it("sets download headers and rejects unauthenticated downloads", async () => {
    const r = await alice.agent.get(`/api/content/${itemId}/download`);
    expect(r.status).toBe(200);
    expect(r.headers["content-disposition"]).toContain("attachment");
    expect(r.headers["cache-control"]).toContain("no-store");
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
    expect(
      (await request(app).get(`/api/content/${itemId}/download`)).status,
    ).toBe(401);
  });
  it("blocks quarantine and detects file tampering", async () => {
    await withTenant(A, (c) =>
      c.query(
        "UPDATE content_items SET scan_status='quarantined' WHERE id=$1",
        [itemId],
      ),
    );
    expect(
      (await alice.agent.get(`/api/content/${itemId}/download`)).status,
    ).toBe(403);
    await withTenant(A, (c) =>
      c.query("UPDATE content_items SET scan_status='clean' WHERE id=$1", [
        itemId,
      ]),
    );
    const key = (
      await withTenant(A, (c) =>
        c.query("SELECT storage_key FROM content_items WHERE id=$1", [itemId]),
      )
    ).rows[0].storage_key;
    const path = join(root, A, key);
    const bytes = await readFile(path);
    await writeFile(path, Buffer.from("tampered"));
    expect(
      (await alice.agent.get(`/api/content/${itemId}/download`)).status,
    ).toBe(409);
    await writeFile(path, bytes);
  });
  it("requires step-up for restricted downloads", async () => {
    const r = await upload(alice, { classification: "restricted" });
    expect(r.status).toBe(201);
    expect(
      (await alice.agent.get(`/api/content/${r.body.id}/download`)).status,
    ).toBe(403);
  });
  it("stores encrypted bytes, rotates without losing reads, and fails after key destruction", async () => {
    const before = (
      await withTenant(A, (c) =>
        c.query("SELECT storage_key FROM content_items WHERE id=$1", [itemId]),
      )
    ).rows[0].storage_key;
    expect(
      (await readFile(join(root, A, before))).includes(
        Buffer.from("private project notes"),
      ),
    ).toBe(false);
    const result = await withTenant(A, (c) =>
      rotateTenantFiles(c, A, async () => {}),
    );
    await result.cleanup();
    expect(
      (await alice.agent.get(`/api/content/${itemId}/download`)).status,
    ).toBe(200);
    const key = (
      await withTenant(A, (c) =>
        c.query("SELECT storage_key FROM content_items WHERE id=$1", [itemId]),
      )
    ).rows[0].storage_key;
    const bytes = await readFile(join(root, A, key));
    const other = await withTenant(B, (c) => tenantKey(c, B, true));
    expect(() => open(bytes, other, B)).toThrow();
    await expect(
      withTenant(A, async (c) => {
        await c.query("DELETE FROM tenant_keys");
        await expect(tenantKey(c, A)).rejects.toThrow(/unavailable/);
        throw new Error("rollback key destruction test");
      }),
    ).rejects.toThrow(/rollback/);
  });
  it("rejects binary spoofing, empty files, unknown fields and quota violations", async () => {
    expect(
      (await upload(alice, {}, Buffer.from([77, 90, 0, 0, 1, 2]), "fake.pdf"))
        .status,
    ).toBe(422);
    expect((await upload(alice, {}, Buffer.alloc(0))).status).toBe(422);
    expect((await upload(alice, { tenant_id: B })).status).toBe(422);
    await withTenant(A, (c) =>
      c.query(
        "INSERT INTO tenant_data_policy(tenant_id) VALUES($1) ON CONFLICT DO NOTHING",
        [A],
      ),
    );
    await withTenant(A, (c) =>
      c.query("UPDATE tenant_data_policy SET max_storage_bytes=1"),
    );
    expect((await upload(alice)).status).toBe(422);
    await withTenant(A, (c) =>
      c.query("UPDATE tenant_data_policy SET max_storage_bytes=209715200"),
    );
  });
  it("hides soft-deleted items", async () => {
    expect(
      (await alice.write("delete", `/api/content/${itemId}`).send({})).status,
    ).toBe(200);
    expect((await alice.agent.get(`/api/content/${itemId}`)).status).toBe(404);
  });
  it("creates a hash-only key, restricts scopes, and never creates a browser session", async () => {
    await dave.step();
    const r = await dave
      .write("post", "/api/api-keys")
      .send({ name: "Read-only integration", scopes: ["projects:read"] });
    expect(r.status).toBe(201);
    expect(r.body.key).toMatch(/^ws_live_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}$/);
    const key = r.body.key;
    const stored = (
      await withTenant(B, (c) =>
        c.query("SELECT key_hash FROM api_keys WHERE id=$1", [r.body.id]),
      )
    ).rows[0];
    expect(stored.key_hash).not.toBe(key);
    const projects = await request(app)
      .get("/api/projects")
      .set("Authorization", "Bearer " + key);
    expect(projects.status).toBe(200);
    expect(projects.headers["set-cookie"]).toBeUndefined();
    expect(
      projects.body.every((row: { tenant_id: string }) => row.tenant_id === B),
    ).toBe(true);
    expect(
      (
        await request(app)
          .post("/api/projects")
          .set("Authorization", "Bearer " + key)
          .send({ name: "attack" })
      ).status,
    ).toBe(403);
    expect(
      (
        await request(app)
          .get("/api/members")
          .set("Authorization", "Bearer " + key)
      ).status,
    ).toBe(403);
    expect(
      (await request(app).get("/api/projects?api_key=" + key)).status,
    ).toBe(401);
    const list = await dave.agent.get("/api/api-keys");
    expect(JSON.stringify(list.body)).not.toContain(key);
    expect(JSON.stringify(list.body)).not.toContain("key_hash");
    await dave.write("post", `/api/api-keys/${r.body.id}/revoke`).send({});
    const denied = await request(app)
      .get("/api/projects")
      .set("Authorization", "Bearer " + key);
    expect(denied.status).toBe(401);
    expect(denied.body.error).toBe("Invalid API key");
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer ws_live_abcdefgh_" + "a".repeat(43))
      ).body.error,
    ).toBe(denied.body.error);
  });
  it("explores only this tenant through safe columns and validates identifiers", async () => {
    const hidden = await upload(bob, { classification: "confidential" });
    expect(hidden.status).toBe(201);
    const content = await alice.agent.get("/api/explorer/content_items");
    expect(content.status).toBe(200);
    expect(
      content.body.rows.some(
        (row: { id: string }) => row.id === hidden.body.id,
      ),
    ).toBe(false);
    const datasets = await alice.agent.get("/api/explorer");
    expect(datasets.status).toBe(200);
    expect(
      datasets.body.find(
        (row: { name: string }) => row.name === "content_items",
      ).count,
    ).toBe((await alice.agent.get("/api/content")).body.length);
    expect((await bob.agent.get("/api/explorer")).status).toBe(403);
    const r = await dave.agent.get("/api/explorer/projects");
    expect(r.status).toBe(200);
    expect(
      r.body.rows.every((row: { tenant_id: string }) => row.tenant_id === B),
    ).toBe(true);
    const keys = await dave.agent.get("/api/explorer/api_keys");
    expect(keys.status).toBe(200);
    expect(JSON.stringify(keys.body)).not.toMatch(
      /key_hash|encrypted_dek|password_hash|storage_key|totp_secret/,
    );
    expect(
      (await dave.agent.get("/api/explorer/projects?sort=password_hash"))
        .status,
    ).toBe(422);
    expect((await dave.agent.get("/api/explorer/users")).status).toBe(422);
    expect(
      (
        await dave.agent.get(
          "/api/explorer/projects?filter=%27%3BDROP%20TABLE%20projects%3B--",
        )
      ).status,
    ).toBe(200);
    expect(
      (await alice.agent.get("/api/explorer/projects/export.csv")).status,
    ).toBe(403);
    await dave.step();
    expect(
      (await dave.agent.get("/api/explorer/projects/export.csv")).status,
    ).toBe(200);
  });
  it("enforces key expiry, IP restrictions, rotation grace and per-key rate limits", async () => {
    await dave.step();
    const make = async (extra: Record<string, unknown> = {}) => {
      const result = await dave
        .write("post", "/api/api-keys")
        .send({ name: "Security checks", scopes: ["projects:read"], ...extra });
      expect(result.status).toBe(201);
      return result.body;
    };
    const expired = await make();
    await withTenant(B, (c) =>
      c.query(
        "UPDATE api_keys SET expires_at=now()-interval '1 second' WHERE id=$1",
        [expired.id],
      ),
    );
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer " + expired.key)
      ).status,
    ).toBe(401);
    const blocked = await make({ ip_allowlist: ["192.0.2.0/24"] });
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer " + blocked.key)
      ).status,
    ).toBe(401);
    const limited = await make({ rate_limit_per_min: 1 });
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer " + limited.key)
      ).status,
    ).toBe(200);
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer " + limited.key)
      ).status,
    ).toBe(429);
    const original = await make();
    const rotated = await dave
      .write("post", `/api/api-keys/${original.id}/rotate`)
      .send({});
    expect(rotated.status).toBe(201);
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer " + original.key)
      ).status,
    ).toBe(200);
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer " + rotated.body.key)
      ).status,
    ).toBe(200);
    await withTenant(B, (c) =>
      c.query(
        "UPDATE api_keys SET expires_at=now()-interval '1 second' WHERE id=$1",
        [original.id],
      ),
    );
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Authorization", "Bearer " + original.key)
      ).status,
    ).toBe(401);
  });
  it("requires service-principal ACLs and never gives API keys restricted content", async () => {
    await alice.step();
    const created = await alice
      .write("post", "/api/api-keys")
      .send({ name: "Content reader", scopes: ["content:read"] });
    expect(created.status).toBe(201);
    const file = await upload(alice, { classification: "confidential" });
    expect(file.status).toBe(201);
    const path = `/api/content/${file.body.id}`;
    expect(
      (
        await request(app)
          .get(path)
          .set("Authorization", "Bearer " + created.body.key)
      ).status,
    ).toBe(404);
    expect(
      (
        await alice.write("put", path + "/acl").send({
          principal_type: "api_key",
          principal_id: created.body.id,
          permission: "download",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await request(app)
          .get(path)
          .set("Authorization", "Bearer " + created.body.key)
      ).status,
    ).toBe(200);
    await alice.write("patch", path).send({ classification: "restricted" });
    expect(
      (
        await request(app)
          .get(path)
          .set("Authorization", "Bearer " + created.body.key)
      ).status,
    ).toBe(404);
  });
  it("queues and completes a durable encryption rotation job", async () => {
    await dave.step();
    const uploadResult = await upload(dave);
    expect(uploadResult.status).toBe(201);
    const queued = await dave.write("post", "/api/admin/keys/rotate").send({});
    expect(queued.status).toBe(202);
    await runRotationJob(B, queued.body.id);
    const jobs = await dave.agent.get("/api/admin/keys/rotation");
    expect(jobs.body[0].status).toBe("completed");
    expect(
      (await dave.agent.get(`/api/content/${uploadResult.body.id}/download`))
        .status,
    ).toBe(200);
  });
  it("rejects oversized files, enforces row quotas, and reports tenant alerts", async () => {
    expect(
      (await upload(alice, {}, Buffer.alloc(10485761, 65), "large.txt")).status,
    ).toBe(413);
    const count = Number(
      (await withTenant(A, (c) => c.query("SELECT count(*) FROM projects")))
        .rows[0].count,
    );
    await withTenant(A, (c) =>
      c.query("UPDATE tenant_data_policy SET max_rows_per_table=$1", [count]),
    );
    expect(
      (
        await alice
          .write("post", "/api/projects")
          .send({ name: "Beyond quota" })
      ).status,
    ).toBe(422);
    await withTenant(A, (c) =>
      c.query("UPDATE tenant_data_policy SET max_rows_per_table=10000"),
    );
    expect((await alice.agent.get("/api/security-alerts")).status).toBe(200);
    expect((await carol.agent.get("/api/security-alerts")).status).toBe(403);
  });
});
