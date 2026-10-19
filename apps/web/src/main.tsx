import React, { useState, useEffect, useCallback, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  BrowserRouter,
  NavLink,
  Routes,
  Route,
  useNavigate,
} from "react-router-dom";
import "./style.css";
import {
  ContentLibrary,
  ApiKeys,
  DataExplorer,
  DataPolicy,
  SecurityAlerts,
} from "./security-pages.js";
type Row = Record<string, string | number | boolean | number[] | null>;
type Workspace = {
  tenant_id: string;
  name: string;
  slug: string;
  role: string;
};
let csrf = "";
let csrfInitialization: Promise<void> | null = null;
async function api<T = Row[]>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  if (!csrf) {
    // Share initialization so React StrictMode cannot race two session cookies.
    csrfInitialization ||= fetch("/api/auth/csrf", { credentials: "include" })
      .then(async (r) => {
        if (!r.ok) throw new Error("Could not initialize secure session");
        csrf = (await r.json()).csrf as string;
      })
      .finally(() => {
        csrfInitialization = null;
      });
    await csrfInitialization;
  }
  const r = await fetch("/api" + path, {
    method,
    credentials: "include",
    headers: {
      ...(body instanceof FormData
        ? {}
        : { "Content-Type": "application/json" }),
      "X-CSRF-Token": csrf,
    },
    body:
      body === undefined
        ? undefined
        : body instanceof FormData
          ? body
          : JSON.stringify(body),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || "Request failed");
  if (d.csrf) csrf = d.csrf;
  return d as T;
}
function ErrorBox({ error }: { error: string }) {
  return error ? (
    <div className="error" role="alert">
      {error}
    </div>
  ) : null;
}
function Title({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="page-title">
      <span className="eyebrow">YOUR WORK. YOUR SPACE.</span>
      <h1>{title}</h1>
      <p className="muted">{sub}</p>
    </div>
  );
}
function useRows(path: string) {
  const generation = useRef(0);
  const [rows, setRows] = useState<Row[]>([]),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  const refresh = useCallback(async () => {
    const request = ++generation.current;
    setLoading(true);
    try {
      const result = await api(path);
      if (request === generation.current) {
        setRows(result);
        setError("");
      }
    } catch (e) {
      if (request === generation.current) setError((e as Error).message);
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    void refresh();
    return () => {
      generation.current++;
    };
  }, [refresh]);
  return { rows, error, loading, refresh };
}
function Pager({
  page,
  setPage,
  count,
}: {
  page: number;
  setPage: (n: number) => void;
  count: number;
}) {
  return (
    <div className="pager">
      <button disabled={page === 1} onClick={() => setPage(page - 1)}>
        ← Previous
      </button>
      <small>Page {page}</small>
      <button disabled={count < 30} onClick={() => setPage(page + 1)}>
        Next →
      </button>
    </div>
  );
}
function App() {
  const [logged, setLogged] = useState(false),
    [checking, setChecking] = useState(true),
    [workspaces, setWorkspaces] = useState<Workspace[]>([]),
    [active, setActive] = useState<Workspace | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [email, setEmail] = useState("alice@worksphere.test"),
    [password, setPassword] = useState("Demo-WorkSphere-2026!"),
    [totp, setTotp] = useState("");
  const navigate = useNavigate();
  const load = useCallback(async () => {
    const me = await api<{ tenantId: string | null }>("/auth/me");
    const ws = await api<Workspace[]>("/workspaces");
    setLogged(true);
    setWorkspaces(ws);
    setActive(ws.find((w) => w.tenant_id === me.tenantId) || null);
  }, []);
  useEffect(() => {
    load()
      .catch(() => {})
      .finally(() => setChecking(false));
  }, [load]);
  async function login(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/auth/login", "POST", { email, password, totp });
      await load();
      navigate("/");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function choose(ws: Workspace) {
    try {
      await api("/session/workspace", "POST", { tenantId: ws.tenant_id });
      setActive(ws);
      navigate("/");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  if (checking) return <div className="loading">Opening WorkSphere…</div>;
  if (!logged)
    return (
      <div className="login">
        <section className="login-story">
          <div className="brand">◈ WorkSphere</div>
          <div>
            <span className="eyebrow">A SPACE FOR YOUR NEXT BIG THING</span>
            <h1>
              Great work.
              <br />
              Shared space.
              <br />
              <em>Clear boundaries.</em>
            </h1>
            <p>
              Your team’s projects, people and security.
              <br />
              Connected in one thoughtful workspace.
            </p>
            <div className="pill">◉ Tenant isolation at every layer</div>
          </div>
          <small>SYNTAX SYNDICATE / ADVANTIX HACKATHON</small>
        </section>
        <section className="login-form">
          <div className="form-wrap">
            <span className="eyebrow">WELCOME BACK</span>
            <h2>Make room for good work.</h2>
            <p className="muted">Sign in securely to your workspace.</p>
            <form onSubmit={login}>
              <label>
                Email address
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </label>
              <label>
                Authenticator code
                <input
                  value={totp}
                  onChange={(e) => setTotp(e.target.value)}
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  placeholder="000000"
                  required
                />
              </label>
              <ErrorBox error={error} />
              <button disabled={busy} className="primary">
                {busy ? "Signing in…" : "Sign in →"}
              </button>
            </form>
            {import.meta.env.DEV && (
              <details className="demo">
                <summary>Local demo tools</summary>
                <p>
                  Demo accounts: alice, bob, carol, dave, erin, sam
                  @worksphere.test.
                </p>
                <button
                  onClick={() =>
                    void api<{ totp: string }>(
                      "/dev/totp?email=" + encodeURIComponent(email),
                    )
                      .then((d) => setTotp(d.totp))
                      .catch((e) => setError(e.message))
                  }
                >
                  Get current demo code
                </button>
                <button
                  onClick={() => {
                    void api("/dev/bootstrap", "POST", {})
                      .then(() =>
                        setError(
                          "Local Alice device installed. Acme access hours still apply.",
                        ),
                      )
                      .catch((e) => setError(e.message));
                  }}
                >
                  Bootstrap Alice’s device
                </button>
                <p>
                  Acme: Mon–Fri, 09:00–18:00 India time. Globex: all days. See
                  README for recovery.
                </p>
              </details>
            )}
            <p className="secure-note">
              ⌑ Password + authenticator · Server verified access
            </p>
          </div>
        </section>
      </div>
    );
  if (!active)
    return (
      <main className="picker">
        <div className="brand">◈ WorkSphere</div>
        <Title
          title="Where will you work today?"
          sub="Each workspace is a separate, protected space for your team."
        />
        <ErrorBox error={error} />
        <div className="workspace-grid">
          {workspaces.map((w) => (
            <button
              className="workspace-card"
              key={w.tenant_id}
              onClick={() => void choose(w)}
            >
              <span className="avatar">{w.name[0]}</span>
              <h2>{w.name}</h2>
              <p>
                {w.slug} <span className="badge">{w.role}</span>
              </p>
              <span className="link">Open workspace →</span>
            </button>
          ))}
        </div>
        <button
          onClick={() =>
            void api("/auth/logout", "POST", {}).then(() => setLogged(false))
          }
        >
          Sign out
        </button>
      </main>
    );
  const admin = active.role === "admin";
  return (
    <div className="shell">
      <aside>
        <div className="brand">◈ WorkSphere</div>
        <button className="workspace-switch" onClick={() => setActive(null)}>
          <span className="avatar">{active.name[0]}</span>
          <span>
            {active.name}
            <small>{active.role} · Switch workspace ↗</small>
          </span>
        </button>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          <NavLink to="/" end>
            ▦ Projects & tasks
          </NavLink>
          <NavLink to="/content">▣ Content library</NavLink>
          {admin && (
            <>
              <NavLink to="/members">♧ Members</NavLink>
              <span className="nav-label">TRUST & ACCESS</span>
              <NavLink to="/settings">⚙ Security settings</NavLink>
              <NavLink to="/inspector">◎ Security Inspector</NavLink>
              <NavLink to="/api-keys">⌘ API keys</NavLink>
              <NavLink to="/explorer">▤ Data Explorer</NavLink>
            </>
          )}
        </nav>
        <div className="sidebar-bottom">
          <div className="isolation">
            <b>◉ Workspace protected</b>
            <small>Tenant-scoped access is active</small>
          </div>
          <button
            onClick={() =>
              void api("/auth/logout", "POST", {}).then(() => {
                setLogged(false);
                setActive(null);
                csrf = "";
              })
            }
          >
            Sign out ↗
          </button>
        </div>
      </aside>
      <div className="content">
        <header>
          <span>
            Workspace / <b>{active.name}</b>
          </span>
          <span className="badge">{active.role}</span>
        </header>
        <main>
          <Routes>
            <Route
              path="/content"
              element={
                <ContentLibrary
                  api={api}
                  company={active.name}
                  editable={active.role !== "viewer"}
                  verification={<Stepup />}
                />
              }
            />
            <Route
              path="/api-keys"
              element={
                admin ? (
                  <ApiKeys
                    api={api}
                    company={active.name}
                    editable
                    verification={<Stepup />}
                  />
                ) : (
                  <p>Permission denied</p>
                )
              }
            />
            <Route
              path="/explorer"
              element={
                admin ? (
                  <DataExplorer
                    api={api}
                    company={active.name}
                    editable
                    verification={<Stepup />}
                  />
                ) : (
                  <p>Permission denied</p>
                )
              }
            />
            <Route
              path="/"
              element={
                <Board
                  key={active.tenant_id}
                  editable={active.role !== "viewer"}
                />
              }
            />
            <Route
              path="/members"
              element={admin ? <Members /> : <p>Permission denied</p>}
            />
            <Route
              path="/settings"
              element={admin ? <Settings /> : <p>Permission denied</p>}
            />
            <Route
              path="/inspector"
              element={admin ? <Inspector /> : <p>Permission denied</p>}
            />
            <Route path="*" element={<h2>Not found</h2>} />
          </Routes>
        </main>
        <footer>
          WorkSphere <span>Built for focus. Designed around trust.</span>
        </footer>
      </div>
    </div>
  );
}
function Board({ editable }: { editable: boolean }) {
  const [page, setPage] = useState(1),
    [selected, setSelected] = useState(""),
    [name, setName] = useState(""),
    [description, setDescription] = useState(""),
    [title, setTitle] = useState(""),
    [taskPage, setTaskPage] = useState(1),
    [error, setError] = useState("");
  const projects = useRows("/projects?page=" + page),
    tasks = useRows(
      selected
        ? `/projects/${selected}/tasks?page=${taskPage}`
        : "/projects?limit=1",
    );
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      await projects.refresh();
      if (selected) await tasks.refresh();
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const current = projects.rows.find((p) => p.id === selected);
  return (
    <>
      <Title
        title="Projects & tasks"
        sub="Bring your team’s ideas into focus, one task at a time."
      />
      <ErrorBox error={error || projects.error || tasks.error} />
      <div className="stats">
        <div>
          <span className="stat-icon">▦</span>
          <b>{projects.rows.length}</b>
          <small>Projects on this page</small>
        </div>
        <div>
          <span className="stat-icon teal">✓</span>
          <b>
            {selected
              ? tasks.rows.filter((t) => t.status === "done").length
              : "—"}
          </b>
          <small>Completed tasks on this page</small>
        </div>
        <div className="trust-card">
          <span className="eyebrow">YOUR WORK, IN ITS OWN SPACE</span>
          <h3>Collaboration with confidence.</h3>
          <p>Every request is checked against your workspace membership.</p>
        </div>
      </div>
      <div className="board-layout">
        <section className="panel project-panel">
          <h3>Your projects</h3>
          {projects.loading ? (
            <p>Loading…</p>
          ) : !projects.rows.length ? (
            <p>No projects yet.</p>
          ) : (
            projects.rows.map((p) => (
              <button
                key={String(p.id)}
                className={
                  "project-button " + (selected === p.id ? "selected" : "")
                }
                onClick={() => {
                  setSelected(String(p.id));
                  setTaskPage(1);
                }}
              >
                <span>▧</span>
                <div>
                  <b>{String(p.name)}</b>
                  <small>{String(p.description)}</small>
                </div>
                <span>›</span>
              </button>
            ))
          )}
          <Pager page={page} setPage={setPage} count={projects.rows.length} />
          {editable && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  await api("/projects", "POST", { name, description });
                  setName("");
                  setDescription("");
                });
              }}
            >
              <h4>New project</h4>
              <input
                aria-label="Project name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Project name"
                required
                maxLength={150}
              />
              <textarea
                aria-label="Project description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Short description"
              />
              <button className="primary">+ Create project</button>
            </form>
          )}
        </section>
        <section className="task-panel">
          {selected ? (
            <>
              <div className="section-heading">
                <div>
                  <span className="eyebrow">PROJECT BOARD</span>
                  <h2>{String(current?.name || "Project")}</h2>
                </div>
                {editable && (
                  <div>
                    <button
                      onClick={() => {
                        const value = window.prompt(
                          "Project name",
                          String(current?.name || ""),
                        );
                        if (value)
                          void act(() =>
                            api("/projects/" + selected, "PATCH", {
                              name: value,
                              description: current?.description || "",
                            }),
                          );
                      }}
                    >
                      Rename
                    </button>
                    <button
                      className="danger"
                      onClick={() => {
                        if (window.confirm("Delete project and its tasks?"))
                          void act(async () => {
                            await api("/projects/" + selected, "DELETE");
                            setSelected("");
                          });
                      }}
                    >
                      Delete
                    </button>
                  </div>
                )}
              </div>
              {editable && (
                <form
                  className="inline-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void act(async () => {
                      await api("/projects/" + selected + "/tasks", "POST", {
                        title,
                      });
                      setTitle("");
                    });
                  }}
                >
                  <input
                    aria-label="Task title"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="What needs to happen next?"
                    required
                    maxLength={300}
                  />
                  <button className="primary">+ Add task</button>
                </form>
              )}
              <div className="kanban">
                {["todo", "in_progress", "done"].map((status, i) => (
                  <section className={"lane lane-" + i} key={status}>
                    <h3>
                      <span className="dot" />
                      {["To do", "In progress", "Done"][i]}{" "}
                      <small>
                        {tasks.rows.filter((t) => t.status === status).length}
                      </small>
                    </h3>
                    {tasks.rows
                      .filter((t) => t.status === status)
                      .map((t) => (
                        <article className="task-card" key={String(t.id)}>
                          <span className="task-label">WORKSPACE TASK</span>
                          <h4>{String(t.title)}</h4>
                          <p className="muted">
                            {t.assignee_id
                              ? "Assigned · " + String(t.assignee_id).slice(-6)
                              : "Unassigned"}
                          </p>
                          {editable && (
                            <>
                              <select
                                aria-label={"Status for " + t.title}
                                value={String(t.status)}
                                onChange={(e) =>
                                  void act(() =>
                                    api("/tasks/" + t.id, "PATCH", {
                                      status: e.target.value,
                                    }),
                                  )
                                }
                              >
                                <option value="todo">To do</option>
                                <option value="in_progress">In progress</option>
                                <option value="done">Done</option>
                              </select>
                              <div className="task-actions">
                                <button
                                  onClick={() => {
                                    const v = window.prompt(
                                      "Task title",
                                      String(t.title),
                                    );
                                    if (v)
                                      void act(() =>
                                        api("/tasks/" + t.id, "PATCH", {
                                          title: v,
                                        }),
                                      );
                                  }}
                                >
                                  Edit
                                </button>
                                <button
                                  onClick={() => {
                                    const v = window.prompt(
                                      "Active member user UUID; blank to unassign",
                                      String(t.assignee_id || ""),
                                    );
                                    if (v !== null)
                                      void act(() =>
                                        api("/tasks/" + t.id, "PATCH", {
                                          assignee_id: v || null,
                                        }),
                                      );
                                  }}
                                >
                                  Assign
                                </button>
                                <button
                                  className="danger"
                                  onClick={() => {
                                    if (window.confirm("Delete task?"))
                                      void act(() =>
                                        api("/tasks/" + t.id, "DELETE"),
                                      );
                                  }}
                                >
                                  ×
                                </button>
                              </div>
                            </>
                          )}
                        </article>
                      ))}
                    {!tasks.loading &&
                      !tasks.rows.some((t) => t.status === status) && (
                        <div className="empty-lane">Room for what’s next</div>
                      )}
                  </section>
                ))}
              </div>
              <Pager
                page={taskPage}
                setPage={setTaskPage}
                count={tasks.rows.length}
              />
            </>
          ) : (
            <div className="empty-board">
              <span>▦</span>
              <h2>Your next milestone starts here.</h2>
              <p>Select a project to see its task board.</p>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
function Stepup() {
  const [code, setCode] = useState(""),
    [message, setMessage] = useState("");
  return (
    <section className="stepup">
      <div>
        <b>Verify sensitive changes</b>
        <small>
          A fresh code unlocks changes for 5 minutes. Each code works once.
        </small>
      </div>
      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          void api("/auth/stepup", "POST", { totp: code })
            .then(() => {
              setMessage("Verified for 5 minutes");
              setCode("");
            })
            .catch((e) => setMessage(e.message));
        }}
      >
        <input
          aria-label="Fresh authenticator code"
          placeholder="6-digit code"
          pattern="[0-9]{6}"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          required
        />
        <button>Verify</button>
      </form>
      {import.meta.env.DEV && (
        <button
          onClick={() =>
            void api<{ user: { email: string } }>("/auth/me")
              .then((me) =>
                api<{ totp: string }>(
                  "/dev/totp?email=" + encodeURIComponent(me.user.email),
                ),
              )
              .then((d) => setCode(d.totp))
              .catch((e) => setMessage(e.message))
          }
        >
          Fill demo verification code
        </button>
      )}
      {message && <span role="status">{message}</span>}
    </section>
  );
}
function Members() {
  const [page, setPage] = useState(1);
  const data = useRows("/members?page=" + page);
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [role, setRole] = useState("member"),
    [message, setMessage] = useState("");
  const act = async (path: string, method: string, body: unknown) => {
    try {
      const result = await api<Row>(path, method, body);
      setMessage(
        result.otpauth
          ? "Save this authenticator URL now: " + result.otpauth
          : "Saved",
      );
      await data.refresh();
    } catch (e) {
      setMessage((e as Error).message);
    }
  };
  return (
    <>
      <Title
        title="Members"
        sub="Give the right people the right access. Changes apply to their next request."
      />
      <Stepup />
      <ErrorBox error={data.error} />
      {message && <p className="notice break-word">{message}</p>}
      <div className="panel table-wrap">
        <table>
          <thead>
            <tr>
              <th>Person / User ID</th>
              <th>Role</th>
              <th>Status</th>
              <th>Access</th>
            </tr>
          </thead>
          <tbody>
            {data.rows.map((m) => (
              <tr key={String(m.id)}>
                <td>
                  <b>{String(m.email)}</b>
                  <small>{String(m.user_id)}</small>
                </td>
                <td>
                  <select
                    aria-label={"Role for " + m.email}
                    value={String(m.role)}
                    onChange={(e) =>
                      void act("/members/" + m.id + "/role", "PATCH", {
                        role: e.target.value,
                      })
                    }
                  >
                    {["admin", "member", "viewer"].map((r) => (
                      <option key={r}>{r}</option>
                    ))}
                  </select>
                </td>
                <td>
                  <span className="badge">{String(m.status)}</span>
                </td>
                <td>
                  <button
                    className="danger"
                    disabled={m.status === "revoked"}
                    onClick={() => {
                      if (window.confirm("Revoke this membership?"))
                        void act("/members/" + m.id + "/revoke", "POST", {});
                    }}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pager page={page} setPage={setPage} count={data.rows.length} />
      </div>
      <form
        className="panel invite-form"
        onSubmit={(e) => {
          e.preventDefault();
          void act("/members/invite", "POST", { email, password, role });
        }}
      >
        <h3>Add a demo member</h3>
        <p className="muted">
          Creates a new account. Share the authenticator URL securely; email
          delivery is outside the MVP.
        </p>
        <label>
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </label>
        <label>
          Temporary password
          <input
            type="password"
            minLength={12}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        <select
          aria-label="New member role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          {["admin", "member", "viewer"].map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
        <button className="primary">Create member</button>
      </form>
    </>
  );
}
function Settings() {
  const [policy, setPolicy] = useState<Row | null>(null),
    [error, setError] = useState(""),
    [message, setMessage] = useState(""),
    [uid, setUid] = useState(""),
    [page, setPage] = useState(1);
  const devices = useRows("/devices?page=" + page);
  useEffect(() => {
    void api<Row>("/policy")
      .then(setPolicy)
      .catch((e) => setError(e.message));
  }, []);
  const act = async (path: string, method: string, body: unknown) => {
    try {
      await api(path, method, body);
      setMessage("Saved");
      setError("");
      await devices.refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  };
  return (
    <>
      <Title
        title="Security settings"
        sub="Set when your team can work, and which devices can join."
      />
      <Stepup />
      <DataPolicy api={api} />
      <ErrorBox error={error || devices.error} />
      {message && <p className="notice">{message}</p>}
      <div className="settings-grid">
        {policy && (
          <form
            className="panel"
            onSubmit={(e) => {
              e.preventDefault();
              void act("/policy", "PUT", {
                access_days: policy.access_days,
                access_start: policy.access_start,
                access_end: policy.access_end,
                timezone: policy.timezone,
                require_trusted_device: policy.require_trusted_device,
              });
            }}
          >
            <h3>Access hours</h3>
            <p className="muted">
              Server time decides access. Overnight windows belong to the day
              they start.
            </p>
            <div className="days">
              {["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].map((d, i) => (
                <label key={d}>
                  <input
                    type="checkbox"
                    checked={(policy.access_days as number[]).includes(i)}
                    onChange={(e) =>
                      setPolicy({
                        ...policy,
                        access_days: e.target.checked
                          ? [...(policy.access_days as number[]), i]
                          : (policy.access_days as number[]).filter(
                              (x) => x !== i,
                            ),
                      })
                    }
                  />
                  {d}
                </label>
              ))}
            </div>
            <label>
              Start
              <input
                type="time"
                value={String(policy.access_start)}
                onChange={(e) =>
                  setPolicy({ ...policy, access_start: e.target.value })
                }
              />
            </label>
            <label>
              End
              <input
                type="time"
                value={String(policy.access_end)}
                onChange={(e) =>
                  setPolicy({ ...policy, access_end: e.target.value })
                }
              />
            </label>
            <label>
              Timezone
              <input
                value={String(policy.timezone)}
                onChange={(e) =>
                  setPolicy({ ...policy, timezone: e.target.value })
                }
              />
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={Boolean(policy.require_trusted_device)}
                onChange={(e) =>
                  setPolicy({
                    ...policy,
                    require_trusted_device: e.target.checked,
                  })
                }
              />
              Require an approved device
            </label>
            <p className="notice">
              Pre-create an override before excluding the current time. Keep an
              administrator able to enter.
            </p>
            <button className="primary">Save policy</button>
          </form>
        )}
        <form
          className="panel"
          onSubmit={(e) => {
            e.preventDefault();
            void act("/overrides", "POST", { userId: uid });
          }}
        >
          <h3>One-time access override</h3>
          <p className="muted">
            Redeem once for access outside hours until its 30-minute expiry.
            Device and role checks still apply.
          </p>
          <label>
            Member user ID
            <input
              value={uid}
              onChange={(e) => setUid(e.target.value)}
              required
              placeholder="User UUID from Members"
            />
          </label>
          <button>Create override</button>
        </form>
      </div>
      <div className="panel table-wrap">
        <h3>Trusted devices</h3>
        <table>
          <thead>
            <tr>
              <th>Device / User</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {devices.rows.map((d) => (
              <tr key={String(d.id)}>
                <td>
                  {String(d.label)}
                  <small>{String(d.user_id)}</small>
                </td>
                <td>
                  <span className="badge">{String(d.status)}</span>
                </td>
                <td>
                  <button
                    disabled={d.status === "approved"}
                    onClick={() =>
                      void act("/devices/" + d.id + "/approve", "POST", {})
                    }
                  >
                    Approve
                  </button>
                  <button
                    className="danger"
                    disabled={d.status === "revoked"}
                    onClick={() =>
                      void act("/devices/" + d.id + "/revoke", "POST", {})
                    }
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pager page={page} setPage={setPage} count={devices.rows.length} />
      </div>
    </>
  );
}
function Inspector() {
  const [family, setFamily] = useState(""),
    [classification, setClassification] = useState("");
  const [page, setPage] = useState(1),
    [outcome, setOutcome] = useState(""),
    [action, setAction] = useState(""),
    [from, setFrom] = useState(""),
    [to, setTo] = useState("");
  const params = new URLSearchParams({ page: String(page) });
  if (family) params.set("family", family);
  if (classification) params.set("classification", classification);
  if (outcome) params.set("outcome", outcome);
  if (action) params.set("action", action);
  if (from) params.set("from", new Date(from).toISOString());
  if (to) params.set("to", new Date(to).toISOString());
  const data = useRows("/audit?" + params.toString());
  const alerts = data.rows.filter(
    (e) => e.outcome !== "allowed" || e.action === "device.pending",
  );
  return (
    <>
      <Title
        title="Tenant Security Inspector"
        sub="A clear record of access and activity, scoped to this workspace."
      />
      <SecurityAlerts api={api} />
      <div
        className="security-actions"
        role="group"
        aria-label="Activity category"
      >
        {[
          ["", "All activity"],
          ["content", "Content Activity"],
          ["api_key", "API Keys"],
        ].map(([value, label]) => (
          <button
            key={value}
            aria-pressed={family === value}
            onClick={() => {
              setFamily(value);
              setPage(1);
            }}
          >
            {label}
          </button>
        ))}
        <select
          aria-label="Filter classification"
          value={classification}
          onChange={(e) => {
            setClassification(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All classifications</option>
          {["internal", "confidential", "restricted"].map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
      </div>
      <div className="alert-strip">
        ◎ {alerts.length} security events on this page{" "}
        <span>Review lockouts, denied requests and device activity below.</span>
      </div>
      <div className="filters">
        <select
          aria-label="Filter outcome"
          value={outcome}
          onChange={(e) => {
            setOutcome(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All outcomes</option>
          <option value="denied">Denied only</option>
          <option value="failed">Failed</option>
          <option value="allowed">Allowed</option>
        </select>
        <input
          aria-label="Filter action"
          placeholder="Action, e.g. auth.lockout"
          value={action}
          onChange={(e) => {
            setAction(e.target.value);
            setPage(1);
          }}
        />
        <label>
          From
          <input
            type="datetime-local"
            value={from}
            onChange={(e) => {
              setFrom(e.target.value);
              setPage(1);
            }}
          />
        </label>
        <label>
          To
          <input
            type="datetime-local"
            value={to}
            onChange={(e) => {
              setTo(e.target.value);
              setPage(1);
            }}
          />
        </label>
        <button onClick={() => void data.refresh()}>↻ Refresh</button>
      </div>
      <ErrorBox error={data.error} />
      <div className="panel table-wrap">
        {data.loading ? (
          <p>Loading security events…</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Action / Request</th>
                <th>Outcome</th>
                <th>Actor / Resource</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {data.rows.map((e) => (
                <tr key={String(e.id)}>
                  <td>{new Date(String(e.created_at)).toLocaleString()}</td>
                  <td>
                    <b>{String(e.action)}</b>
                    <small>{String(e.request_id)}</small>
                  </td>
                  <td>
                    <span className={"badge " + e.outcome}>
                      {String(e.outcome)}
                    </span>
                  </td>
                  <td>
                    <small>{String(e.actor_user_id || "—")}</small>
                    <small>{String(e.resource_id || "—")}</small>
                  </td>
                  <td>{String(e.reason || "—")}</td>
                </tr>
              ))}
              {!data.rows.length && (
                <tr>
                  <td colSpan={5}>No events match these filters.</td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        <Pager page={page} setPage={setPage} count={data.rows.length} />
      </div>
    </>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);
