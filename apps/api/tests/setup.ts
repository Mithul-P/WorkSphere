import "dotenv/config";
process.env.DATABASE_URL ||=
  "postgres://worksphere_app:local_app_password@localhost:5432/worksphere";
process.env.OWNER_DATABASE_URL ||=
  "postgres://worksphere_owner:local_owner_password@localhost:5432/worksphere";
process.env.SESSION_SECRET ||= "test-session-secret-at-least-32-characters";
process.env.TOTP_ENCRYPTION_KEY ||= "0123456789abcdef".repeat(4);
process.env.WEB_ORIGIN ||= "http://localhost:5173";
process.env.NODE_ENV = "test";
process.env.DEV_ONLY = "false";
