import "dotenv/config";
import { randomBytes } from "node:crypto";
process.env.DATABASE_URL ||=
  "postgres://worksphere_app:local_app_password@localhost:5432/worksphere";
process.env.OWNER_DATABASE_URL ||=
  "postgres://worksphere_owner:local_owner_password@localhost:5432/worksphere";
process.env.SESSION_SECRET ||= randomBytes(32).toString("hex");
process.env.TOTP_ENCRYPTION_KEY ||= randomBytes(32).toString("hex");
process.env.WEB_ORIGIN ||= "http://localhost:5173";
process.env.NODE_ENV = "test";
process.env.DEV_ONLY = "false";
