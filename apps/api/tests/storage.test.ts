import { it, expect } from "vitest";
import { mkdtemp, rm, mkdir, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { LocalDisk } from "../src/storage.js";
it("rejects traversal, absolute paths, null bytes and linked tenant directories", async () => {
  const dir = await mkdtemp(join(tmpdir(), "worksphere-path-test-")),
    tid = randomUUID();
  try {
    const storage = new LocalDisk(dir);
    for (const key of [
      "../escape",
      "/etc/passwd",
      "C:\\escape",
      "2026/..",
      `2026/${randomUUID()}\0`,
    ])
      await expect(storage.get(tid, key)).rejects.toThrow(
        /Invalid storage path/,
      );
    const outside = join(dir, "other");
    await mkdir(outside);
    await symlink(
      outside,
      join(dir, tid),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(storage.put(tid, Buffer.from("test"))).rejects.toThrow(
      /Symlink/,
    );
  } finally {
    if (resolve(dir).startsWith(resolve(tmpdir())))
      await rm(dir, { recursive: true, force: true });
  }
});
