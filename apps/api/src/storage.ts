import {
  mkdir,
  lstat,
  realpath,
  writeFile,
  readFile,
  unlink,
} from "node:fs/promises";
import { resolve, join, sep, isAbsolute } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
export interface ContentStorage {
  put(tenantId: string, bytes: Buffer): Promise<string>;
  get(tenantId: string, key: string): Promise<Buffer>;
  remove(tenantId: string, key: string): Promise<void>;
}
export class LocalDisk implements ContentStorage {
  constructor(
    private root = resolve(
      process.env.STORAGE_ROOT ||
        fileURLToPath(new URL("../../../.worksphere-storage", import.meta.url)),
    ),
  ) {}
  private async path(tenantId: string, key: string) {
    if (
      !/^[a-f0-9-]{36}$/.test(tenantId) ||
      !/^\d{4}\/[a-f0-9-]{36}$/.test(key) ||
      isAbsolute(key) ||
      key.includes("..") ||
      key.includes("\0")
    )
      throw new Error("Invalid storage path");
    await mkdir(this.root, { recursive: true });
    const root = await realpath(this.root);
    const tenantRoot = join(root, tenantId);
    const target = resolve(tenantRoot, key);
    if (!target.startsWith(tenantRoot + sep))
      throw new Error("Invalid storage path");
    for (const segment of [
      tenantRoot,
      join(tenantRoot, key.split("/")[0]),
      target,
    ]) {
      try {
        if ((await lstat(segment)).isSymbolicLink())
          throw new Error("Symlink rejected");
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      }
    }
    return target;
  }
  async put(tenantId: string, bytes: Buffer) {
    const key = `${new Date().getUTCFullYear()}/${randomUUID()}`;
    const path = await this.path(tenantId, key);
    await mkdir(resolve(path, ".."), { recursive: true });
    await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
    return key;
  }
  async get(tenantId: string, key: string) {
    return readFile(await this.path(tenantId, key));
  }
  async remove(tenantId: string, key: string) {
    await unlink(await this.path(tenantId, key));
  }
}
