import { describe, it, expect } from "vitest";
import {
  can,
  permissions,
  type Role,
  type Action,
} from "../src/policy/permissions.js";
import { encrypt, decrypt, counter, authenticator } from "../src/crypto.js";
import { withinHours, routeManifest } from "../src/app.js";
describe("central policy", () => {
  for (const role of ["admin", "member", "viewer"] as Role[])
    for (const action of permissions.admin as readonly Action[])
      it(`${role} ${action}`, () =>
        expect(can(role, action)).toBe(
          role === "admin" ||
            action === "read" ||
            (role === "member" && action === "edit"),
        ));
  it("encrypts with unique authenticated nonces", () => {
    const a = encrypt("secret"),
      b = encrypt("secret");
    expect(a).not.toBe(b);
    expect(decrypt(a)).toBe("secret");
    expect(() => decrypt(a.slice(0, -2) + "00")).toThrow();
  });
  it("accepts current TOTP and rejects invalid code", () => {
    const secret = authenticator.generateSecret();
    expect(counter(authenticator.generate(secret), secret)).not.toBeNull();
    expect(counter("invalid", secret)).toBeNull();
  });
  it("handles local, closed, and overnight access windows", () => {
    const p = {
      timezone: "Asia/Kolkata",
      access_days: [1],
      access_start: "09:00:00",
      access_end: "18:00:00",
    };
    expect(withinHours(p, new Date("2026-10-19T06:00:00Z"))).toBe(true);
    expect(withinHours(p, new Date("2026-10-19T23:00:00Z"))).toBe(false);
    expect(
      withinHours(
        { ...p, access_start: "22:00:00", access_end: "03:00:00" },
        new Date("2026-10-19T20:00:00Z"),
      ),
    ).toBe(true);
  });
  it("registers authorization for every tenant route and stepup for sensitive mutations", () => {
    expect(routeManifest.length).toBeGreaterThanOrEqual(20);
    for (const r of routeManifest) {
      expect(permissions.admin).toContain(r.action);
      if (
        ["members", "policy", "devices"].includes(r.action) &&
        r.method !== "get"
      )
        expect(r.stepup).toBe(true);
    }
  });
});
