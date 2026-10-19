import { setTimeout as delay } from "node:timers/promises";
const base = process.env.API_URL || "http://localhost:3000";
const origin = process.env.WEB_ORIGIN || "http://localhost:5173";
let cookies = new Map<string, string>();
let csrf = "";
async function call(path: string, method = "GET", body?: unknown) {
  const response = await fetch(base + "/api" + path, {
    method,
    headers: {
      Origin: origin,
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
      Cookie: [...cookies].map(([k, v]) => k + "=" + v).join("; "),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  for (const line of response.headers.getSetCookie()) {
    const [key, value] = line.split(";")[0].split("=");
    cookies.set(key, value);
  }
  const data = await response.json();
  if (data.csrf) csrf = data.csrf;
  return { status: response.status, data };
}
async function signIn(name: string) {
  cookies = new Map();
  csrf = "";
  await call("/auth/csrf");
  if (name === "alice") cookies.set("ws_device", "a".repeat(64));
  const code = await call("/dev/totp?email=" + name + "@worksphere.test");
  const login = await call("/auth/login", "POST", {
    email: name + "@worksphere.test",
    password: process.env.SEED_PASSWORD || "Demo-WorkSphere-2026!",
    totp: code.data.totp,
  });
  if (login.status !== 200)
    throw new Error(
      "Login failed: wait for a fresh 30-second code or reset a demo lockout",
    );
  await call("/session/workspace", "POST", {
    tenantId: "10000000-0000-4000-8000-000000000001",
  });
}
await signIn("alice");
const projects = await call("/projects");
if (projects.status !== 200)
  throw new Error(
    "Acme policy denied access; run during Acme hours or use documented recovery",
  );
const tasks = await call("/projects/" + projects.data[0].id + "/tasks");
const changed = await call("/tasks/" + tasks.data[0].id, "PATCH", {
  status: "done",
});
if (changed.status !== 200) throw new Error("Task update failed");
const attack = await call("/projects/30000000-0000-4000-8000-000000000003");
if (attack.status !== 404)
  throw new Error("Cross-tenant attack unexpectedly succeeded");
console.log("Alice completed a task; cross-tenant access returned 404.");
console.log("Inspector:", (await call("/audit?outcome=denied")).data);
await signIn("carol");
if (
  (await call("/tasks/" + tasks.data[0].id, "PATCH", { status: "todo" }))
    .status !== 403
)
  throw new Error("Viewer write unexpectedly succeeded");
console.log(
  "Viewer write blocked. Automated DB/API tests cover additional isolation cases.",
);
await delay(50);
