import "dotenv/config";
import pg from "pg";
import { test, expect, type Page } from "@playwright/test";
test.setTimeout(90000);
const owner = new pg.Pool({ connectionString: process.env.OWNER_DATABASE_URL });
const A = "10000000-0000-4000-8000-000000000001";
async function policy(open: boolean) {
  const c = await owner.connect();
  try {
    await c.query("BEGIN");
    await c.query("SELECT set_config('app.tenant_id',$1,true)", [A]);
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
async function login(page: Page, name: string, company: string) {
  await owner.query(
    "UPDATE users SET last_used_counter=-1,failed_attempts=0,locked_until=NULL WHERE email=$1",
    [name + "@worksphere.test"],
  );
  await page.goto("/");
  await page.getByText("Local demo tools").click();
  await page.getByLabel("Email address").fill(name + "@worksphere.test");
  await page
    .getByLabel("Password", { exact: true })
    .fill("Demo-WorkSphere-2026!");
  await page.getByRole("button", { name: "Get current demo code" }).click();
  await expect(page.getByLabel("Authenticator code")).toHaveValue(/\d{6}/);
  await page.getByRole("button", { name: "Sign in →" }).click();
  await page.getByRole("button", { name: new RegExp(company) }).click();
  await expect(
    page.getByRole("heading", { name: "Projects & tasks" }),
  ).toBeVisible();
}
test.beforeAll(async () => policy(true));
test.afterAll(async () => {
  await policy(false);
  await owner.end();
});
test("confidential sharing, viewer ceiling, foreign 404, inspector and explorer", async ({
  browser,
}, testInfo) => {
  const contexts = await Promise.all(
    Array.from({ length: 4 }, () => browser.newContext()),
  );
  try {
    const [alice, bob, carol, dave] = await Promise.all(
      contexts.map((c) => c.newPage()),
    );
    await login(alice, "alice", "Acme Corp");
    await alice.getByRole("link", { name: /Content library/ }).click();
    await alice
      .getByLabel("Title", { exact: true })
      .fill("Confidential planning");
    await alice
      .getByRole("combobox", { name: "Upload classification" })
      .selectOption("confidential");
    await alice
      .getByLabel("Upload file", { exact: true })
      .setInputFiles({
        name: "plan.txt",
        mimeType: "text/plain",
        buffer: Buffer.from("Confidential team plan"),
      });
    const created = alice.waitForResponse(
      (r) =>
        r.url().endsWith("/api/content") && r.request().method() === "POST",
    );
    await alice.getByRole("button", { name: "Upload securely" }).click();
    const response = await created;
    expect(response.status()).toBe(201);
    const id = (await response.json()).id;
    await alice
      .getByRole("button", { name: /▣ Confidential planning/ })
      .click();
    await expect(
      alice.getByRole("heading", { name: "Confidential planning" }),
    ).toBeVisible();
    for (const uid of [
      "20000000-0000-4000-8000-000000000002",
      "20000000-0000-4000-8000-000000000003",
    ]) {
      await alice.getByLabel("Principal UUID").fill(uid);
      const shared = alice.waitForResponse(
        (r) =>
          r.url().endsWith(`/content/${id}/acl`) &&
          r.request().method() === "PUT",
      );
      await alice.getByRole("button", { name: "Save grant" }).click();
      expect((await shared).status()).toBe(200);
    }
    await alice.screenshot({
      path: testInfo.outputPath("content-sharing.png"),
      fullPage: true,
    });
    await login(bob, "bob", "Acme Corp");
    await bob.getByRole("link", { name: /Content library/ }).click();
    await expect(
      bob.getByRole("button", { name: /▣ Confidential planning/ }),
    ).toBeVisible();
    await login(carol, "carol", "Acme Corp");
    await carol.getByRole("link", { name: /Content library/ }).click();
    await carol
      .getByRole("button", { name: /▣ Confidential planning/ })
      .click();
    await expect(
      carol.getByRole("button", { name: "Rename", exact: true }),
    ).toHaveCount(0);
    await expect(
      carol.getByRole("button", { name: "Upload securely" }),
    ).toHaveCount(0);
    await login(dave, "dave", "Globex Ltd");
    expect((await dave.request.get(`/api/content/${id}`)).status()).toBe(404);
    await dave.getByRole("link", { name: /Security Inspector/ }).click();
    await dave
      .getByRole("button", { name: "Content Activity", exact: true })
      .click();
    await expect(
      dave.getByText("content.denied", { exact: true }).first(),
    ).toBeVisible();
    await alice.getByRole("link", { name: /Security Inspector/ }).click();
    await alice
      .getByRole("button", { name: "Content Activity", exact: true })
      .click();
    await expect(
      alice.getByText("content.share", { exact: true }).first(),
    ).toBeVisible();
    await alice.getByRole("link", { name: /Data Explorer/ }).click();
    await expect(
      alice.getByText("Showing data for Acme Corp only"),
    ).toBeVisible();
    await expect(alice.locator(".dataset-list")).toContainText("content items");
    await alice.screenshot({
      path: testInfo.outputPath("data-explorer.png"),
      fullPage: true,
    });
    await alice.setViewportSize({ width: 390, height: 844 });
    await alice.screenshot({
      path: testInfo.outputPath("data-explorer-mobile.png"),
      fullPage: true,
    });
  } finally {
    await Promise.all(contexts.map((c) => c.close()));
  }
});
