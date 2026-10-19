import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHash,
} from "node:crypto";
import { authenticator } from "otplib";
import { config } from "./config.js";
authenticator.options = { step: 30, window: 1 };
export const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
export function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv(
    "aes-256-gcm",
    Buffer.from(config.TOTP_ENCRYPTION_KEY, "hex"),
    iv,
  );
  return [
    iv.toString("hex"),
    cipher.update(value, "utf8", "hex") + cipher.final("hex"),
    cipher.getAuthTag().toString("hex"),
  ].join(".");
}
export function decrypt(value: string) {
  const [iv, data, tag] = value.split(".");
  const cipher = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(config.TOTP_ENCRYPTION_KEY, "hex"),
    Buffer.from(iv, "hex"),
  );
  cipher.setAuthTag(Buffer.from(tag, "hex"));
  return cipher.update(data, "hex", "utf8") + cipher.final("utf8");
}
export function counter(code: string, secret: string): number | null {
  const delta = authenticator.checkDelta(code, secret);
  return delta === null ? null : Math.floor(Date.now() / 30000) + delta;
}
export { authenticator };
