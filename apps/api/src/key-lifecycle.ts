import type pg from "pg";
import { randomBytes, randomUUID } from "node:crypto";
import { pool, withTenant } from "./db/pool.js";
import { LocalDisk } from "./storage.js";
import { tenantKey, wrapTenantKey, seal, open } from "./envelope.js";
// Copy-on-write rotation: old paths remain usable until the database transaction
// commits. The caller holds the tenant advisory lock, also used by uploads.
export async function rotateTenantFiles(
  c: pg.PoolClient,
  tid: string,
  progress: (count: number) => Promise<void>,
) {
  const storage = new LocalDisk(),
    oldKey = await tenantKey(c, tid),
    newKey = randomBytes(32);
  const versions = (
    await c.query(
      "SELECT id,storage_key,item_id,version FROM content_versions ORDER BY id",
    )
  ).rows;
  const created: string[] = [],
    retired: string[] = [];
  try {
    for (const v of versions) {
      const plaintext = open(
        await storage.get(tid, v.storage_key),
        oldKey,
        tid,
      );
      const next = await storage.put(tid, seal(plaintext, newKey, tid));
      created.push(next);
      retired.push(v.storage_key);
      await c.query("UPDATE content_versions SET storage_key=$1 WHERE id=$2", [
        next,
        v.id,
      ]);
      await c.query(
        "UPDATE content_items SET storage_key=$1 WHERE id=$2 AND version=$3",
        [next, v.item_id, v.version],
      );
      await progress(created.length);
    }
    await c.query(
      "UPDATE tenant_keys SET encrypted_dek=$1,key_version=key_version+1,rotated_at=now() WHERE tenant_id=$2",
      [wrapTenantKey(newKey, tid), tid],
    );
    return {
      count: versions.length,
      cleanup: async () => {
        for (const key of retired)
          await storage.remove(tid, key).catch(() => {});
      },
    };
  } catch (e) {
    for (const key of created) await storage.remove(tid, key).catch(() => {});
    throw e;
  }
}
export async function runRotationJob(tid: string, id: string) {
  const event = async (
    action: string,
    outcome: string,
    reason: string,
    actor: string,
  ) =>
    withTenant(tid, (c) =>
      c.query(
        "INSERT INTO audit_events(id,tenant_id,actor_user_id,action,resource_type,resource_id,outcome,reason) VALUES($1,$2,$3,$4,'key',$5,$6,$7)",
        [randomUUID(), tid, actor, action, id, outcome, reason],
      ),
    );
  let actor: string | undefined;
  try {
    const result = await withTenant(tid, async (c) => {
      await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))", [
        tid,
      ]);
      const job = (
        await c.query(
          "SELECT * FROM key_rotation_jobs WHERE id=$1 AND status IN ('queued','running')",
          [id],
        )
      ).rows[0];
      if (!job) return null;
      actor = job.created_by;
      if (
        !(
          await c.query(
            "SELECT 1 FROM memberships WHERE user_id=$1 AND role='admin' AND status='active'",
            [actor],
          )
        ).rows.length
      )
        throw new Error("Rotation administrator no longer active");
      await tenantKey(c, tid, true);
      const result = await rotateTenantFiles(c, tid, async (count) => {
        await withTenant(tid, (p) =>
          p.query(
            "UPDATE key_rotation_jobs SET status='running',completed_versions=$1 WHERE id=$2",
            [count, id],
          ),
        );
        await event(
          "key.rotation_progress",
          "allowed",
          `${count} file versions`,
          job.created_by,
        );
      });
      await c.query(
        "UPDATE key_rotation_jobs SET status='completed',completed_versions=$1,finished_at=now() WHERE id=$2",
        [result.count, id],
      );
      return result;
    });
    if (result) {
      await result.cleanup();
      await event(
        "key.rotated",
        "allowed",
        `${result.count} file versions`,
        actor!,
      );
    }
  } catch {
    await withTenant(tid, (c) =>
      c.query(
        "UPDATE key_rotation_jobs SET status='failed',finished_at=now() WHERE id=$1",
        [id],
      ),
    );
    if (actor)
      await event(
        "key.rotation_failed",
        "failed",
        "Rotation rolled back; retry after checking storage and keys",
        actor,
      );
  }
}
export function startRotationWorker() {
  let running = false;
  const sweep = async () => {
    if (running) return;
    running = true;
    try {
      for (const tenant of (await pool.query("SELECT id FROM tenants")).rows) {
        const jobs = (
          await withTenant(tenant.id, (c) =>
            c.query(
              "SELECT id FROM key_rotation_jobs WHERE status IN ('queued','running') ORDER BY created_at LIMIT 1",
            ),
          )
        ).rows;
        for (const job of jobs) await runRotationJob(tenant.id, job.id);
      }
    } catch {
      console.error("Key rotation worker could not inspect pending jobs");
    } finally {
      running = false;
    }
  };
  const timer = setInterval(() => void sweep(), 10000);
  timer.unref();
  void sweep();
  return () => clearInterval(timer);
}
