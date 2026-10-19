import "dotenv/config";
import pg from "pg";
import { auditDatabase } from "../apps/api/src/db/audit.js";
const db = new pg.Pool({ connectionString: process.env.DATABASE_URL });
try {
  const issues = await auditDatabase(db);
  for (const issue of issues) console.error(issue);
  if (issues.length) process.exitCode = 1;
  else
    console.log(
      "Database audit passed: tenant RLS, immutable boundaries, role privileges, PUBLIC grants and append-only audit.",
    );
} finally {
  await db.end();
}
