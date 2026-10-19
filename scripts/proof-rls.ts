import "dotenv/config";
import pg from "pg";
const db = new pg.Client({ connectionString: process.env.OWNER_DATABASE_URL });
await db.connect();
try {
  try {
    await db.query("BEGIN");
    const before = await db.query("SELECT id FROM projects");
    if (before.rows.length)
      throw new Error(
        "Expected FORCE RLS to deny the non-superuser owner before proof",
      );
    await db.query("ALTER TABLE projects DISABLE ROW LEVEL SECURITY");
    const result = await db.query("SELECT id FROM projects");
    if (!result.rows.length) throw new Error("Proof needs seeded projects");
    console.log(
      `Isolation assertion SELECT projects = 0 rows would FAIL: ${result.rows.length} rows became visible without tenant context. Proof runs as non-superuser table owner under FORCE RLS.`,
    );
    console.log("Rolling back the entire DDL transaction to restore RLS.");
  } finally {
    await db.query("ROLLBACK");
  }
  const restored = await db.query("SELECT id FROM projects");
  if (restored.rows.length) throw new Error("RLS restoration failed");
} finally {
  await db.end();
}
