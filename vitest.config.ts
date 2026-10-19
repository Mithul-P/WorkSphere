import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    setupFiles: ["apps/api/tests/setup.ts"],
    include: ["apps/api/tests/**/*.test.ts"],
    fileParallelism: false,
    coverage: {
      provider: "v8",
      include: ["apps/api/src/**/*.ts"],
      exclude: ["**/seed.ts", "**/migrate.ts", "**/server.ts"],
    },
    testTimeout: 30000,
  },
});
