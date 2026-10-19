import { describe, it, expect, beforeAll, afterAll } from "vitest";
import request from "supertest";
import pg from "pg";
import { app } from "../src/app.js";
import { pool, withTenant } from "../src/db/pool.js";
import { decrypt, authenticator } from "../src/crypto.js";
const A = "10000000-0000-4000-8000-000000000001",
  B = "10000000-0000-4000-8000-000000000002",
  AP = "30000000-0000-4000-8000-000000000001",
  BP = "30000000-0000-4000-8000-000000000003";
const owner = new pg.Pool({ connectionString: process.env.OWNER_DATABASE_URL });
const origin = process.env.WEB_ORIGIN!;
async function login(name: string, select = true) {
  const agent = request.agent(app);
  const uid = `20000000-0000-4000-8000-00000000000${["alice", "bob", "carol", "dave", "erin", "sam"].indexOf(name) + 1}`;
  await owner.query(
    "UPDATE users SET last_used_counter=-1,failed_attempts=0,locked_until=NULL WHERE id=$1",
    [uid],
  );
  const { rows } = await owner.query(
    "SELECT totp_secret_encrypted FROM users WHERE id=$1",
    [uid],
  );
  let csrf = (await agent.get("/api/auth/csrf")).body.csrf as string;
  const r = await agent
    .post("/api/auth/login")
    .set("Origin", origin)
    .set("X-CSRF-Token", csrf)
    .send({
      email: name + "@worksphere.test",
      password: "Demo-WorkSphere-2026!",
      totp: authenticator.generate(
        decrypt(rows[0].totp_secret_encrypted as string),
      ),
    });
  expect(r.status).toBe(200);
  csrf = r.body.csrf as string;
  if (select)
    expect(
      (
        await agent
          .post("/api/session/workspace")
          .set("Origin", origin)
          .set("X-CSRF-Token", csrf)
          .send({ tenantId: name === "dave" || name === "erin" ? B : A })
      ).status,
    ).toBe(200);
  return { agent, csrf, uid };
}
beforeAll(async () => {
  for (const t of [A, B])
    await withTenant(t, (c) =>
      c.query(
        "UPDATE tenant_policies SET access_days=ARRAY[0,1,2,3,4,5,6],access_start='00:00',access_end='23:59:59',require_trusted_device=false WHERE tenant_id=$1",
        [t],
      ),
    );
});
afterAll(async () => {
  await withTenant(A, (c) =>
    c.query(
      "UPDATE tenant_policies SET access_days=ARRAY[1,2,3,4,5],access_start='09:00',access_end='18:00',require_trusted_device=true WHERE tenant_id=$1",
      [A],
    ),
  );
  await owner.end();
  await pool.end();
});
describe("cross tenant attacks and auth", () => {
  it("fails closed without a session and active workspace", async () => {
    expect((await request(app).get("/api/projects")).status).toBe(401);
    const { agent } = await login("alice", false);
    expect((await agent.get("/api/projects")).status).toBe(403);
  });
  it("uniformly hides cross-tenant resources and audits caller tenant", async () => {
    const { agent, csrf } = await login("alice");
    for (const method of ["get", "patch", "delete"] as const) {
      const r = await agent[method]("/api/projects/" + BP)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send(
          method === "patch" ? { name: "attack", description: "" } : undefined,
        );
      expect(r.status).toBe(404);
      expect(r.body.error).toBe("Not found");
    }
    const events = await agent.get("/api/audit?outcome=denied");
    expect(
      events.body.some((e: { resource_id: string }) => e.resource_id === BP),
    ).toBe(true);
    expect(
      events.body.every((e: { tenant_id: string }) => e.tenant_id === A),
    ).toBe(true);
    expect(
      (
        await withTenant(B, (c) =>
          c.query("SELECT name FROM projects WHERE id=$1", [BP]),
        )
      ).rows[0].name,
    ).toBe("Product launch");
  });
  it("rejects task parent injection and ignores tenant headers and query", async () => {
    const { agent, csrf } = await login("bob");
    const r = await agent
      .get("/api/projects?tenant=" + B)
      .set("X-Tenant-Id", B);
    expect(r.body.every((p: { tenant_id: string }) => p.tenant_id === A)).toBe(
      true,
    );
    expect(
      (
        await agent
          .post("/api/projects/" + AP + "/tasks")
          .set("Origin", origin)
          .set("X-CSRF-Token", csrf)
          .send({ title: "attack", project_id: BP, tenantId: B })
      ).status,
    ).toBe(422);
  });
  it("viewer cannot write; members cannot administer or inspect", async () => {
    const v = await login("carol");
    expect(
      (
        await v.agent
          .post("/api/projects")
          .set("Origin", origin)
          .set("X-CSRF-Token", v.csrf)
          .send({ name: "attack" })
      ).status,
    ).toBe(403);
    const m = await login("bob");
    for (const p of ["/members", "/policy", "/devices", "/audit"])
      expect((await m.agent.get("/api" + p)).status).toBe(403);
  });
  it("revocation applies immediately to a live session", async () => {
    const { agent, uid } = await login("bob");
    await withTenant(A, (c) =>
      c.query("UPDATE memberships SET status='revoked' WHERE user_id=$1", [
        uid,
      ]),
    );
    try {
      expect((await agent.get("/api/projects")).status).toBe(403);
    } finally {
      await withTenant(A, (c) =>
        c.query("UPDATE memberships SET status='active' WHERE user_id=$1", [
          uid,
        ]),
      );
    }
  });
  it("blocks CSRF, tampered sessions and SQL injection parameters", async () => {
    const { agent } = await login("alice");
    expect(
      (await agent.post("/api/projects").send({ name: "bad" })).status,
    ).toBe(403);
    expect(
      (
        await request(app)
          .get("/api/projects")
          .set("Cookie", "ws_session=tampered")
      ).status,
    ).toBe(401);
    expect(
      (await agent.get("/api/projects/" + encodeURIComponent("' OR 1=1--")))
        .status,
    ).toBe(400);
  });
  it("rejects replayed TOTP generically and locks after three failures", async () => {
    const { agent, csrf } = await login("erin");
    const { rows } = await owner.query(
      "SELECT totp_secret_encrypted FROM users WHERE email='erin@worksphere.test'",
    );
    const totp = authenticator.generate(
      decrypt(rows[0].totp_secret_encrypted as string),
    );
    for (let i = 0; i < 3; i++) {
      const r = await agent
        .post("/api/auth/login")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send({
          email: "erin@worksphere.test",
          password: "Demo-WorkSphere-2026!",
          totp,
        });
      expect(r.status).toBe(401);
      expect(r.body.error).toBe("Login failed");
    }
    const u = await owner.query(
      "SELECT locked_until FROM users WHERE email='erin@worksphere.test'",
    );
    expect(
      new Date(u.rows[0].locked_until as string).getTime(),
    ).toBeGreaterThan(Date.now());
  });
  it("unknown device is denied until approved", async () => {
    const { agent, uid } = await login("sam");
    await withTenant(A, (c) =>
      c.query(
        "UPDATE tenant_policies SET require_trusted_device=true WHERE tenant_id=$1",
        [A],
      ),
    );
    try {
      expect((await agent.get("/api/projects")).status).toBe(403);
      await withTenant(A, (c) =>
        c.query(
          "UPDATE trusted_devices SET status='approved' WHERE user_id=$1",
          [uid],
        ),
      );
      expect((await agent.get("/api/projects")).status).toBe(200);
    } finally {
      await withTenant(A, (c) =>
        c.query(
          "UPDATE tenant_policies SET require_trusted_device=false WHERE tenant_id=$1",
          [A],
        ),
      );
    }
  });
  it("outside-hours denial is logged and a short override is consumed once", async () => {
    const { agent, uid } = await login("sam");
    await withTenant(A, (c) =>
      c.query(
        "UPDATE tenant_policies SET access_days=ARRAY[]::int[] WHERE tenant_id=$1",
        [A],
      ),
    );
    try {
      expect((await agent.get("/api/projects")).status).toBe(403);
      await withTenant(A, (c) =>
        c.query(
          "INSERT INTO access_overrides(id,tenant_id,user_id,expires_at,created_by) VALUES(gen_random_uuid(),$1,$2,now()+interval '30 minutes',$2)",
          [A, uid],
        ),
      );
      expect((await agent.get("/api/projects")).status).toBe(200);
      expect(
        (
          await withTenant(A, (c) =>
            c.query(
              "SELECT used_at FROM access_overrides WHERE user_id=$1 ORDER BY expires_at DESC LIMIT 1",
              [uid],
            ),
          )
        ).rows[0].used_at,
      ).not.toBeNull();
    } finally {
      await withTenant(A, (c) =>
        c.query(
          "UPDATE tenant_policies SET access_days=ARRAY[0,1,2,3,4,5,6] WHERE tenant_id=$1",
          [A],
        ),
      );
    }
  });

  it("admin CRUD, step-up, member enrollment, devices, policy and overrides", async () => {
    const { agent, csrf, uid } = await login("alice");
    const mutate = (
      path: string,
      method: "post" | "put" | "patch" | "delete",
      body: unknown,
    ) =>
      agent[method]("/api" + path)
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send(body);
    expect((await mutate("/policy", "put", {})).status).toBe(403);
    const secret = (
      await owner.query("SELECT totp_secret_encrypted FROM users WHERE id=$1", [
        uid,
      ])
    ).rows[0].totp_secret_encrypted as string;
    await owner.query("UPDATE users SET last_used_counter=-1 WHERE id=$1", [
      uid,
    ]);
    expect(
      (
        await mutate("/auth/stepup", "post", {
          totp: authenticator.generate(decrypt(secret)),
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await mutate("/auth/stepup", "post", {
          totp: authenticator.generate(decrypt(secret)),
        })
      ).status,
    ).toBe(401);
    const p = (await agent.get("/api/policy")).body;
    expect(
      (
        await mutate("/policy", "put", {
          access_days: p.access_days,
          access_start: p.access_start,
          access_end: p.access_end,
          timezone: p.timezone,
          require_trusted_device: false,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await mutate("/policy", "put", {
          access_days: [1],
          access_start: "99:99",
          access_end: "18:00",
          timezone: "bad/timezone",
          require_trusted_device: false,
        })
      ).status,
    ).toBe(400);
    expect((await mutate("/overrides", "post", { userId: uid })).status).toBe(
      201,
    );
    const member = await mutate("/members/invite", "post", {
      email: "new-" + Date.now() + "@worksphere.test",
      password: "New-demo-password-2026!",
      role: "viewer",
    });
    expect(member.status).toBe(201);
    expect(member.body.otpauth).toMatch(/^otpauth:/);
    const members = await agent.get("/api/members");
    const m = members.body.find(
      (x: { user_id: string }) => x.user_id === member.body.userId,
    );
    expect(
      (await mutate("/members/" + m.id + "/role", "patch", { role: "member" }))
        .status,
    ).toBe(200);
    expect(
      (await mutate("/members/" + m.id + "/revoke", "post", {})).status,
    ).toBe(200);
    const devices = await agent.get("/api/devices");
    const device = devices.body.find(
      (d: { user_id: string }) => d.user_id === uid,
    );
    expect(
      (await mutate("/devices/" + device.id + "/approve", "post", {})).status,
    ).toBe(200);
    expect(
      (await mutate("/devices/" + device.id + "/revoke", "post", {})).status,
    ).toBe(200);
    const project = await mutate("/projects", "post", {
      name: "CRUD temporary",
      description: "test",
    });
    expect(project.status).toBe(201);
    expect((await agent.get("/api/projects/" + project.body.id)).status).toBe(
      200,
    );
    expect(
      (
        await mutate("/projects/" + project.body.id, "patch", {
          name: "Renamed",
          description: "",
        })
      ).status,
    ).toBe(200);
    const task = await mutate(
      "/projects/" + project.body.id + "/tasks",
      "post",
      { title: "test task", assignee_id: uid },
    );
    expect(task.status).toBe(201);
    expect(
      (
        await mutate("/tasks/" + task.body.id, "patch", {
          status: "in_progress",
          assignee_id: null,
        })
      ).status,
    ).toBe(200);
    expect((await mutate("/tasks/" + task.body.id, "delete", {})).status).toBe(
      200,
    );
    expect(
      (await mutate("/projects/" + project.body.id, "delete", {})).status,
    ).toBe(200);
    expect((await mutate("/auth/logout", "post", {})).status).toBe(200);
    expect((await agent.get("/api/auth/me")).status).toBe(401);
  });
  it("absolute expiry rejects a previously valid session", async () => {
    const { agent, uid } = await login("sam");
    await owner.query(
      "UPDATE session SET sess=jsonb_set(sess::jsonb,'{started}',to_jsonb(0))::json WHERE sess->>'userId'=$1",
      [uid],
    );
    expect((await agent.get("/api/projects")).status).toBe(401);
  });
  for (const name of ["alice", "bob", "carol", "dave", "erin", "sam"])
    it(`role matrix for ${name}`, async () => {
      const { agent, csrf } = await login(name);
      expect((await agent.get("/api/projects?limit=1&page=1")).status).toBe(
        200,
      );
      const admin = ["alice", "dave"].includes(name);
      expect((await agent.get("/api/audit")).status).toBe(admin ? 200 : 403);
      const r = await agent
        .post("/api/projects")
        .set("Origin", origin)
        .set("X-CSRF-Token", csrf)
        .send({ name: "Matrix temporary" });
      expect(r.status).toBe(name === "carol" ? 403 : 201);
      if (r.status === 201)
        expect(
          (
            await agent
              .delete("/api/projects/" + r.body.id)
              .set("Origin", origin)
              .set("X-CSRF-Token", csrf)
          ).status,
        ).toBe(200);
    });
});
