import "dotenv/config";
import pg from "pg";
import { readFile, readdir } from "node:fs/promises";
const owner = new pg.Pool({ connectionString: process.env.OWNER_DATABASE_URL });
try {
  const directory = new URL("./migrations/", import.meta.url);
  for (const name of (await readdir(directory))
    .filter((n) => /^\d+\.sql$/.test(n))
    .sort()) {
    await owner.query("BEGIN");
    try {
      await owner.query(await readFile(new URL(name, directory), "utf8"));
      await owner.query("COMMIT");
    } catch (error) {
      await owner.query("ROLLBACK");
      throw error;
    }
  }
  console.log("Migration complete");
} finally {
  await owner.end();
}
