import "dotenv/config";
import pg from "pg";
import { test, expect } from "@playwright/test";
const owner = new pg.Pool({ connectionString: process.env.OWNER_DATABASE_URL });
async function policy(open: boolean) {
  const c = await owner.connect();
  try {
    await c.query("BEGIN");
    await c.query(
      "SELECT set_config('app.tenant_id','10000000-0000-4000-8000-000000000001',true)",
    );
    await c.query(
      open
        ? "UPDATE tenant_policies SET access_days=ARRAY[0,1,2,3,4,5,6],access_start='00:00',access_end='23:59:59',require_trusted_device=false"
        : "UPDATE tenant_policies SET access_days=ARRAY[1,2,3,4,5],access_start='09:00',access_end='18:00',require_trusted_device=true",
    );
    await c.query("COMMIT");
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}
test.beforeAll(async () => {
  await owner.query(
    "UPDATE users SET last_used_counter=-1,failed_attempts=0,locked_until=NULL WHERE email IN ('dave@worksphere.test','carol@worksphere.test')",
  );
  await policy(true);
});
test.afterAll(async () => {
  await policy(false);
  await owner.end();
});
test("workspace board and viewer read-only controls", async ({
  browser,
}, testInfo) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto("/");
  await page.getByText("Local demo tools").click();
  await page.getByLabel("Email address").fill("dave@worksphere.test");
  await page.getByRole("button", { name: "Get current demo code" }).click();
  await expect(page.getByLabel("Authenticator code")).toHaveValue(/\d{6}/);
  await page.getByRole("button", { name: "Sign in →" }).click();
  await page.getByRole("button", { name: /Globex Ltd/ }).click();
  await expect(
    page.getByRole("heading", { name: "Projects & tasks" }),
  ).toBeVisible();
  await page.getByRole("button", { name: /Product launch/ }).click();
  await expect(
    page.getByText("Plan the release", { exact: true }),
  ).toBeVisible();
  const saved = page.waitForResponse(
    (r) => r.url().includes("/api/tasks/") && r.request().method() === "PATCH",
  );
  await page
    .getByRole("combobox", { name: "Status for Plan the release" })
    .selectOption("done");
  expect((await saved).status()).toBe(200);
  await expect(
    page.locator(".lane-2").getByText("Plan the release", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Product launch/ }),
  ).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("board.png"),
    fullPage: true,
  });
  expect(
    (
      await page.request.get(
        "/api/projects/30000000-0000-4000-8000-000000000001",
      )
    ).status(),
  ).toBe(404);
  await page.getByRole("link", { name: /Security Inspector/ }).click();
  await expect(
    page.getByRole("heading", { name: "Tenant Security Inspector" }),
  ).toBeVisible();
  await context.close();
  const viewer = await browser.newContext();
  const v = await viewer.newPage();
  await v.goto("/");
  await v.getByText("Local demo tools").click();
  await v.getByLabel("Email address").fill("carol@worksphere.test");
  await v.getByRole("button", { name: "Get current demo code" }).click();
  await expect(v.getByLabel("Authenticator code")).toHaveValue(/\d{6}/);
  await v.getByRole("button", { name: "Sign in →" }).click();
  await v.getByRole("button", { name: /Acme Corp/ }).click();
  await v.getByRole("button", { name: /Product launch/ }).click();
  await expect(v.getByText("Plan the release", { exact: true })).toBeVisible();
  await expect(v.getByRole("button", { name: "+ Create project" })).toHaveCount(
    0,
  );
  const csrf = (await (await v.request.get("/api/auth/csrf")).json())
    .csrf as string;
  expect(
    (
      await v.request.patch("/api/tasks/40000000-0000-4000-8000-000000000001", {
        headers: { Origin: process.env.WEB_ORIGIN || "http://localhost:5173", "X-CSRF-Token": csrf },
        data: { status: "done" },
      })
    ).status(),
  ).toBe(403);
  await viewer.close();
});
