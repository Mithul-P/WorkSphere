import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "scripts",
  testMatch: "*.spec.ts",
  use: {
    baseURL: process.env.WEB_ORIGIN || "http://localhost:5173",
    headless: true,
  },
  reporter: "list",
  workers: 1,
});
