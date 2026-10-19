import "dotenv/config";
import { z } from "zod";
export const config = z
  .object({
    DATABASE_URL: z.string().min(1),
    SESSION_SECRET: z.string().min(32),
    TOTP_ENCRYPTION_KEY: z.string().regex(/^[a-fA-F0-9]{64}$/),
    WEB_ORIGIN: z.string().url(),
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
    PORT: z.coerce.number().default(3000),
    DEV_ONLY: z.string().default("false"),
  })
  .parse(process.env);
if (config.NODE_ENV === "production" && config.DEV_ONLY === "true")
  throw new Error("DEV_ONLY must be disabled in production");
if (
  config.NODE_ENV === "production" &&
  (!/^[a-fA-F0-9]{64}$/.test(process.env.FILE_KEK || "") ||
    (process.env.API_KEY_PEPPER || "").length < 32)
)
  throw new Error(
    "Production requires independent FILE_KEK and API_KEY_PEPPER secrets",
  );
