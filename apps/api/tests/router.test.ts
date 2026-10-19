import { it, expect } from "vitest";
import { app } from "../src/app.js";
type Layer = {
  route?: { path: string; stack: { handle: { name: string } }[] };
};
it("walks the actual Express router and rejects routes missing guards", () => {
  const special = new Map<string, string[]>([
    ["/api/health", []],
    ["/api/auth/csrf", []],
    ["/api/auth/login", []],
    ["/api/auth/logout", ["auth"]],
    ["/api/auth/stepup", ["auth"]],
    ["/api/auth/me", ["auth"]],
    ["/api/workspaces", ["auth"]],
    ["/api/session/workspace", ["auth"]],
  ]);
  const router = (app as unknown as { _router: { stack: Layer[] } })._router;
  for (const layer of router.stack) {
    if (!layer.route) continue;
    const path = layer.route.path;
    const handlers = layer.route.stack.map((s) => s.handle.name);
    for (const needed of special.get(path) || [
      "auth",
      "tenantGuard",
      "accessGuard",
      "roleGuard",
    ])
      expect(handlers, path).toContain(needed);
  }
});
