import EmbeddedPostgres from "embedded-postgres";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
const test = process.argv.includes("test");
const browserTest = process.argv.includes("browser");
const databasePort = Number(
  process.env.LOCAL_DB_PORT || (test || browserTest ? 56543 : 55432),
);
const webPort = Number(
  process.env.LOCAL_WEB_PORT || (browserTest ? 5174 : 5173),
);
const apiPort = Number(
  process.env.LOCAL_API_PORT || (browserTest ? 3001 : 3000),
);
const dir = await mkdtemp(resolve(tmpdir(), "worksphere-pg-"));
const pg = new EmbeddedPostgres({
  databaseDir: dir,
  user: "bootstrap_admin",
  password: "local_bootstrap_password",
  port: databasePort,
  persistent: false,
  onLog: (message) => {
    if (/FATAL/.test(message)) console.error(message);
  },
  onError: (error) => console.error(error),
});
const env = {
  ...process.env,
  DATABASE_URL: `postgres://worksphere_app:local_app_password@localhost:${databasePort}/worksphere`,
  OWNER_DATABASE_URL: `postgres://worksphere_owner:local_owner_password@localhost:${databasePort}/worksphere`,
  SESSION_SECRET: randomBytes(32).toString("hex"),
  TOTP_ENCRYPTION_KEY: "0123456789abcdef".repeat(4),
  WEB_ORIGIN: `http://localhost:${webPort}`,
  PORT: String(apiPort),
  NODE_ENV: test ? "test" : "development",
  DEV_ONLY: test ? "false" : "true",
  API_PROXY: `http://localhost:${apiPort}`,
  STORAGE_ROOT: resolve(dir, "content"),
};
async function run(args: string[]) {
  await new Promise<void>((resolve, reject) => {
    const p = spawn(process.execPath, args, {
      env,
      stdio: "inherit",
      windowsHide: true,
    });
    p.on("error", reject);
    p.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error("Command failed: " + code)),
    );
  });
}
try {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("worksphere");
  const client = pg.getPgClient("worksphere");
  await client.connect();
  await client.query(
    "CREATE ROLE worksphere_owner LOGIN PASSWORD 'local_owner_password' NOSUPERUSER NOBYPASSRLS; CREATE ROLE worksphere_app LOGIN PASSWORD 'local_app_password' NOSUPERUSER NOBYPASSRLS; CREATE ROLE worksphere_readonly NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; ALTER DATABASE worksphere OWNER TO worksphere_owner;",
  );
  await client.query(await readFile(resolve("db/security.sql"), "utf8"));
  await client.end();
  await run(["node_modules/tsx/dist/cli.mjs", "apps/api/src/db/migrate.ts"]);
  await run(["node_modules/tsx/dist/cli.mjs", "apps/api/src/db/seed.ts"]);
  if (test) {
    await run(["node_modules/tsx/dist/cli.mjs", "scripts/db-audit.ts"]);
    await run(["node_modules/vitest/vitest.mjs", "run", "--coverage"]);
    await run(["node_modules/tsx/dist/cli.mjs", "scripts/proof-rls.ts"]);
  } else {
    console.log(
      "LOCAL TEMPORARY DEMO: http://localhost:5173 — data is removed on exit. Ctrl+C to stop.",
    );
    const api = spawn(
      process.execPath,
      ["node_modules/tsx/dist/cli.mjs", "apps/api/src/server.ts"],
      { env, stdio: "inherit", windowsHide: true },
    );
    const web = spawn(
      process.execPath,
      [
        resolve("node_modules/vite/bin/vite.js"),
        "--host",
        "127.0.0.1",
        "--port",
        String(webPort),
        "--strictPort",
      ],
      { cwd: resolve("apps/web"), env, stdio: "inherit", windowsHide: true },
    );
    process.on("SIGINT", () => {
      api.kill();
      web.kill();
    });
    try {
      if (browserTest) {
        let ready = false;
        for (let i = 0; i < 60; i++) {
          try {
            ready = (await fetch(`http://localhost:${webPort}/api/health`)).ok;
            if (ready) break;
          } catch {
            /* Backend is still starting. */
          }
          await new Promise((r) => setTimeout(r, 500));
        }
        if (!ready) throw new Error("Web startup timed out");
        await run(["node_modules/@playwright/test/cli.js", "test"]);
      } else
        await new Promise<void>((r) => {
          api.on("exit", () => r());
          web.on("exit", () => r());
        });
    } finally {
      api.kill();
      web.kill();
    }
  }
} finally {
  await pg.stop();
}
