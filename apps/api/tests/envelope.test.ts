import { it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { seal, open } from "../src/envelope.js";
it("encrypts with fresh nonces and binds ciphertext to tenant and key", () => {
  const bytes = Buffer.from("private file contents"),
    a = randomBytes(32),
    b = randomBytes(32);
  const first = seal(bytes, a, "tenant-a"),
    second = seal(bytes, a, "tenant-a");
  expect(first.equals(second)).toBe(false);
  expect(first.includes(bytes)).toBe(false);
  expect(open(first, a, "tenant-a")).toEqual(bytes);
  expect(() => open(first, b, "tenant-a")).toThrow();
  expect(() => open(first, a, "tenant-b")).toThrow();
  const damaged = Buffer.from(first);
  damaged[damaged.length - 1] ^= 1;
  expect(() => open(damaged, a, "tenant-a")).toThrow();
});
