import pg from "pg";
import argon2 from "argon2";
import { randomUUID } from "node:crypto";
import { authenticator, encrypt, hash } from "../crypto.js";
const db = new pg.Pool({
  connectionString: process.env.OWNER_DATABASE_URL,
  max: 1,
});
const password = process.env.SEED_PASSWORD || "Demo-WorkSphere-2026!";
if (process.env.NODE_ENV === "production")
  throw new Error("Demo seed is disabled in production");
export const tenants = [
  "10000000-0000-4000-8000-000000000001",
  "10000000-0000-4000-8000-000000000002",
];
const names = ["alice", "bob", "carol", "dave", "erin", "sam"];
try {
  for (let i = 0; i < 2; i++)
    await db.query(
      "INSERT INTO tenants(id,name,slug) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
      [
        tenants[i],
        i ? "Globex Ltd" : "Acme Corp",
        i ? "workspace-beta" : "workspace-alpha",
      ],
    );
  for (let i = 0; i < names.length; i++) {
    const uid = `20000000-0000-4000-8000-00000000000${i + 1}`;
    const email = names[i] + "@worksphere.test";
    const secret = authenticator.generateSecret();
    await db.query(
      "INSERT INTO users(id,email,password_hash,totp_secret_encrypted) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING id",
      [uid, email, await argon2.hash(password), encrypt(secret)],
    );
    for (const t of i === 5 ? [0, 1] : [i < 3 ? 0 : 1]) {
      await db.query("SELECT set_config('app.tenant_id',$1,false)", [
        tenants[t],
      ]);
      const role = i === 0 || i === 3 ? "admin" : i === 2 ? "viewer" : "member";
      await db.query(
        "INSERT INTO memberships(id,tenant_id,user_id,role) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
        [randomUUID(), tenants[t], uid, role],
      );
    }
  }
  for (let t = 0; t < 2; t++) {
    await db.query("SELECT set_config('app.tenant_id',$1,false)", [tenants[t]]);
    await db.query(
      "INSERT INTO tenant_policies(tenant_id,access_days,access_start,access_end,timezone,require_trusted_device) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
      [
        tenants[t],
        t ? [0, 1, 2, 3, 4, 5, 6] : [1, 2, 3, 4, 5],
        t ? "00:00" : "09:00",
        t ? "23:59:59" : "18:00",
        "Asia/Kolkata",
        !t,
      ],
    );
    for (let p = 0; p < 2; p++) {
      const pid = `30000000-0000-4000-8000-00000000000${t * 2 + p + 1}`;
      await db.query(
        "INSERT INTO projects(id,tenant_id,name,description,created_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        [
          pid,
          tenants[t],
          ["Product launch", "Security review"][p],
          t ? "Globex private workspace" : "Acme private workspace",
          `20000000-0000-4000-8000-00000000000${t ? 4 : 1}`,
        ],
      );
      for (let j = 0; j < 3; j++)
        await db.query(
          "INSERT INTO tasks(id,tenant_id,project_id,title,status) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
          [
            `40000000-0000-4000-8000-${String(t * 6 + p * 3 + j + 1).padStart(12, "0")}`,
            tenants[t],
            pid,
            ["Plan the release", "Review tenant access", "Ship the milestone"][
              j
            ],
            ["todo", "in_progress", "done"][j],
          ],
        );
      console.log(`Project ${pid} in tenant ${tenants[t]}`);
    }
  }
  // Explicit development bootstrap: a documented token approves Alice's first local browser only.
  await db.query("SELECT set_config('app.tenant_id',$1,false)", [tenants[0]]);
  if (process.env.NODE_ENV !== "production")
    await db.query(
      "INSERT INTO trusted_devices(id,tenant_id,user_id,device_token_hash,label,status) VALUES($1,$2,$3,$4,'Local demo bootstrap','approved') ON CONFLICT DO NOTHING",
      [
        randomUUID(),
        tenants[0],
        "20000000-0000-4000-8000-000000000001",
        hash("a".repeat(64)),
      ],
    );
  console.log(
    "Seed complete. Existing users, credentials and policies were preserved.",
  );
} finally {
  await db.end();
}
