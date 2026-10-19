import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type pg from "pg";
function masterKey() {
  const value =
    process.env.FILE_KEK ||
    (process.env.NODE_ENV !== "production"
      ? process.env.TOTP_ENCRYPTION_KEY
      : undefined);
  if (!value || !/^[a-fA-F0-9]{64}$/.test(value))
    throw new Error("FILE_KEK must be configured");
  return Buffer.from(value, "hex");
}
export function seal(bytes: Buffer, key: Buffer, context: string): Buffer {
  const nonce = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
  return Buffer.concat([
    Buffer.from("WS01"),
    nonce,
    cipher.getAuthTag(),
    ciphertext,
  ]);
}
export function open(bytes: Buffer, key: Buffer, context: string): Buffer {
  if (bytes.length < 32 || bytes.subarray(0, 4).toString() !== "WS01")
    throw new Error("Invalid encrypted content");
  const cipher = createDecipheriv("aes-256-gcm", key, bytes.subarray(4, 16));
  cipher.setAAD(Buffer.from(context));
  cipher.setAuthTag(bytes.subarray(16, 32));
  return Buffer.concat([cipher.update(bytes.subarray(32)), cipher.final()]);
}
export async function tenantKey(
  c: pg.PoolClient,
  tenantId: string,
  create = false,
) {
  let row = (
    await c.query("SELECT encrypted_dek FROM tenant_keys WHERE tenant_id=$1", [
      tenantId,
    ])
  ).rows[0];
  if (!row && create) {
    const encrypted = seal(randomBytes(32), masterKey(), tenantId).toString(
      "base64",
    );
    await c.query(
      "INSERT INTO tenant_keys(tenant_id,encrypted_dek) VALUES($1,$2) ON CONFLICT DO NOTHING",
      [tenantId, encrypted],
    );
    row = (
      await c.query(
        "SELECT encrypted_dek FROM tenant_keys WHERE tenant_id=$1",
        [tenantId],
      )
    ).rows[0];
  }
  if (!row) throw new Error("Tenant encryption key unavailable");
  try {
    return open(
      Buffer.from(row.encrypted_dek, "base64"),
      masterKey(),
      tenantId,
    );
  } catch (error) {
    const previous = process.env.FILE_KEK_PREVIOUS;
    if (!previous || !/^[a-fA-F0-9]{64}$/.test(previous)) throw error;
    return open(
      Buffer.from(row.encrypted_dek, "base64"),
      Buffer.from(previous, "hex"),
      tenantId,
    );
  }
}
export const wrapTenantKey = (key: Buffer, tenantId: string) =>
  seal(key, masterKey(), tenantId).toString("base64");
