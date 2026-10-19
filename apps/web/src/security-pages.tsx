import React, { useCallback, useEffect, useState, useRef } from "react";
type RecordRow = Record<string, unknown>;
type Api = <T = RecordRow[]>(
  path: string,
  method?: string,
  body?: unknown,
) => Promise<T>;
type Props = {
  api: Api;
  company: string;
  editable: boolean;
  verification: React.ReactNode;
};
const classifications = ["internal", "confidential", "restricted"];
async function download(path: string, name: string) {
  const r = await fetch("/api" + path, { credentials: "include" });
  if (!r.ok) throw new Error((await r.json()).error || "Download failed");
  const url = URL.createObjectURL(await r.blob()),
    a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function useData<T>(api: Api, path: string, initial: T) {
  const [data, setData] = useState(initial),
    [error, setError] = useState("");
  const refresh = useCallback(async () => {
    try {
      setData(await api<T>(path));
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }, [api, path]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  return { data, error, refresh };
}
function Status({ message }: { message: string }) {
  return message ? (
    <p
      role="status"
      className={
        /^(Saved|Policy saved|Rotation queued)/.test(message)
          ? "notice"
          : "error"
      }
    >
      {message}
    </p>
  ) : null;
}
function Heading({ title, company }: { title: string; company: string }) {
  return (
    <div className="page-title">
      <span className="eyebrow">WORKSPACE SECURITY</span>
      <h1>{title}</h1>
      <p className="tenant-banner">Showing data for {company} only</p>
    </div>
  );
}
export function ContentLibrary({
  api,
  company,
  editable,
  verification,
}: Props) {
  const [search, setSearch] = useState(""),
    [filter, setFilter] = useState(""),
    [page, setPage] = useState(1),
    [selected, setSelected] = useState(""),
    [message, setMessage] = useState(""),
    [busy, setBusy] = useState(false);
  const list = useData<RecordRow[]>(
    api,
    `/content?page=${page}&search=${encodeURIComponent(search)}${filter ? "&classification=" + filter : ""}`,
    [],
  );
  const [file, setFile] = useState<File | null>(null),
    [title, setTitle] = useState(""),
    [classification, setClassification] = useState(""),
    [kind, setKind] = useState("file");
  const fileInput = useRef<HTMLInputElement>(null);
  const act = async (fn: () => Promise<unknown>) => {
    try {
      setBusy(true);
      await fn();
      setMessage("");
      await list.refresh();
    } catch (e) {
      setMessage((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  async function upload(e: React.FormEvent) {
    e.preventDefault();
    if (!file) {
      setMessage("Choose a file first.");
      return;
    }
    const form = new FormData();
    form.set("title", title);
    if (classification) form.set("classification", classification);
    form.set("kind", kind);
    form.set("file", file);
    await act(async () => {
      await api("/content", "POST", form);
      setFile(null);
      setTitle("");
      if (fileInput.current) fileInput.current.value = "";
    });
  }
  return (
    <>
      <Heading title="Content library" company={company} />
      <Status message={message || list.error} />
      <div className="filters">
        <label>
          Search
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search title"
          />
        </label>
        <label>
          Classification
          <select
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All classifications</option>
            {classifications.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="security-grid">
        <section className="panel">
          <h2>Files and documents</h2>
          {list.data.length === 0 ? (
            <p>No accessible content on this page.</p>
          ) : (
            list.data.map((row) => (
              <button
                className="content-row"
                key={String(row.id)}
                onClick={() => setSelected(String(row.id))}
              >
                <strong>▣ {String(row.title)}</strong>
                <span className={"classification " + row.classification}>
                  🔒 {String(row.classification)}
                </span>
                <small>
                  {String(row.mime_type)} ·{" "}
                  {Math.ceil(Number(row.size_bytes) / 1024)} KB · v
                  {String(row.version)}
                </small>
              </button>
            ))
          )}
          <div className="pager">
            <button disabled={page === 1} onClick={() => setPage(page - 1)}>
              Previous
            </button>
            <span>Page {page}</span>
            <button
              disabled={list.data.length < 30}
              onClick={() => setPage(page + 1)}
            >
              Next
            </button>
          </div>
        </section>
        {editable && (
          <form
            className="panel upload-drop"
            onSubmit={(e) => void upload(e)}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              setFile(e.dataTransfer.files[0] || null);
            }}
          >
            <h2>Upload content</h2>
            <p>
              Drop one file here or choose a file. Maximum 10 MB. Type
              validation is enabled; antivirus scanning is not enabled.
            </p>
            <label>
              Title
              <input
                required
                maxLength={150}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </label>
            <label>
              Classification
              <select
                aria-label="Upload classification"
                value={classification}
                onChange={(e) => setClassification(e.target.value)}
              >
                <option value="">Use workspace default</option>
                {classifications.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </label>
            <label>
              Content kind
              <select value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="file">File</option>
                <option value="document">Document</option>
              </select>
            </label>
            <label>
              File
              <input
                aria-label="Upload file"
                ref={fileInput}
                type="file"
                accept=".pdf,.png,.jpg,.jpeg,.txt,.md,.csv,.docx,.xlsx"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
            </label>
            {file && <p>{file.name}</p>}
            <button className="primary" disabled={busy || !file}>
              {busy ? "Uploading…" : "Upload securely"}
            </button>
          </form>
        )}
      </div>
      {selected && (
        <ContentDetail
          key={selected}
          api={api}
          id={selected}
          close={() => setSelected("")}
          verification={verification}
          onChange={list.refresh}
        />
      )}
    </>
  );
}
function ContentDetail({
  api,
  id,
  close,
  verification,
  onChange,
}: {
  api: Api;
  id: string;
  close: () => void;
  verification: React.ReactNode;
  onChange: () => Promise<void>;
}) {
  const detail = useData<RecordRow | null>(api, "/content/" + id, null),
    versions = useData<RecordRow[]>(api, `/content/${id}/versions`, []);
  const [acl, setAcl] = useState<RecordRow[]>([]),
    [message, setMessage] = useState(""),
    [principal, setPrincipal] = useState(""),
    [type, setType] = useState("user"),
    [permission, setPermission] = useState("view"),
    [expiry, setExpiry] = useState("");
  const [preview, setPreview] = useState("");
  useEffect(
    () => () => {
      if (preview) URL.revokeObjectURL(preview);
    },
    [preview],
  );
  const row = detail.data,
    permissions = (row?.permissions || []) as string[];
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setMessage("Saved.");
      await detail.refresh();
      await onChange();
    } catch (e) {
      setMessage((e as Error).message);
    }
  };
  const loadAcl = async () =>
    setAcl(await api<RecordRow[]>(`/content/${id}/acl`));
  return (
    <section className="panel content-detail">
      <div className="section-heading">
        <h2>{String(row?.title || "Content details")}</h2>
        <button onClick={close}>Close</button>
      </div>
      <Status message={message || detail.error} />
      {row && (
        <>
          <p>
            <span className={"classification " + row.classification}>
              {String(row.classification)}
            </span>{" "}
            · {String(row.scan_status)} · Version {String(row.version)}
          </p>
          <p>Owner: {String(row.owner_id)}</p>
          <p className="hash">SHA-256: {String(row.sha256)}</p>
          {row.classification === "restricted" && verification}
          {preview && (
            <div>
              <button onClick={() => setPreview("")}>Close preview</button>
              <iframe
                title="Sandboxed content preview"
                sandbox=""
                src={preview}
                className="content-preview"
              />
            </div>
          )}
          <div className="security-actions">
            {permissions.includes("download") && (
              <button
                onClick={() =>
                  void act(() =>
                    download(`/content/${id}/download`, String(row.title)),
                  )
                }
              >
                Download
              </button>
            )}
            {permissions.includes("edit") && (
              <button
                onClick={() => {
                  const title = window.prompt("New title", String(row.title));
                  if (title)
                    void act(() => api(`/content/${id}`, "PATCH", { title }));
                }}
              >
                Rename
              </button>
            )}
            {permissions.includes("download") &&
              ["application/pdf", "image/png", "image/jpeg"].includes(
                String(row.mime_type),
              ) && (
                <button
                  onClick={() =>
                    void act(async () => {
                      const response = await fetch(
                        `/api/content/${id}/preview`,
                        { credentials: "include" },
                      );
                      if (!response.ok)
                        throw new Error((await response.json()).error);
                      setPreview(URL.createObjectURL(await response.blob()));
                    })
                  }
                >
                  Preview
                </button>
              )}
            {permissions.includes("manage") && (
              <>
                <button
                  onClick={() => {
                    const value = window.prompt(
                      "Classification: internal, confidential or restricted",
                      String(row.classification),
                    );
                    if (value && classifications.includes(value))
                      void act(() =>
                        api(`/content/${id}`, "PATCH", {
                          classification: value,
                        }),
                      );
                  }}
                >
                  Change classification
                </button>
                <button
                  className="danger"
                  onClick={() => {
                    if (window.confirm("Soft-delete this item?"))
                      void act(async () => {
                        await api(`/content/${id}`, "DELETE");
                        close();
                      });
                  }}
                >
                  Delete
                </button>
              </>
            )}
          </div>
          <h3>Versions</h3>
          <ul>
            {versions.data.map((v) => (
              <li key={String(v.id)}>
                Version {String(v.version)} · {String(v.size_bytes)} bytes ·{" "}
                {new Date(String(v.created_at)).toLocaleString()}
              </li>
            ))}
          </ul>
          {permissions.includes("edit") && (
            <label>
              Upload a new version
              <input
                type="file"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  const form = new FormData();
                  form.set("title", String(row.title));
                  form.set("classification", String(row.classification));
                  form.set("file", file);
                  void act(async () => {
                    await api(`/content/${id}/versions`, "POST", form);
                    await versions.refresh();
                  });
                }}
              />
            </label>
          )}
          {permissions.includes("share") && (
            <>
              <h3>Who has access</h3>
              <p>
                The owner has rights within their role. Internal items also
                allow Admin management. Other access comes from these grants;
                restricted items always require an explicit grant.
              </p>
              <button onClick={() => void act(loadAcl)}>
                Show access list
              </button>
              {acl.map((a) => (
                <div className="acl-row" key={String(a.id)}>
                  <span>
                    {String(a.principal_type)}: {String(a.principal_id)} ·{" "}
                    {String(a.permission)} ·{" "}
                    {a.expires_at ? String(a.expires_at) : "No expiry"}
                  </span>
                  <button
                    onClick={() =>
                      void act(async () => {
                        await api(`/content/${id}/acl/${a.id}`, "DELETE");
                        await loadAcl();
                      })
                    }
                  >
                    Remove grant
                  </button>
                </div>
              ))}
              <form
                className="share-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  void act(async () => {
                    await api(`/content/${id}/acl`, "PUT", {
                      principal_type: type,
                      principal_id: principal,
                      permission,
                      ...(expiry
                        ? { expires_at: new Date(expiry).toISOString() }
                        : {}),
                    });
                    await loadAcl();
                  });
                }}
              >
                <h3>Share within this company</h3>
                <label>
                  Principal type
                  <select
                    value={type}
                    onChange={(e) => setType(e.target.value)}
                  >
                    <option value="user">User</option>
                    <option value="role">Role</option>
                    <option value="api_key">API key</option>
                  </select>
                </label>
                <label>
                  {type === "role"
                    ? "Role: admin, member or viewer"
                    : "Principal UUID"}
                  <input
                    required
                    value={principal}
                    onChange={(e) => setPrincipal(e.target.value)}
                  />
                </label>
                <label>
                  Permission
                  <select
                    value={permission}
                    onChange={(e) => setPermission(e.target.value)}
                  >
                    {[
                      "view",
                      "download",
                      "edit",
                      "share",
                      ...(permissions.includes("manage") ? ["manage"] : []),
                    ].map((p) => (
                      <option key={p}>{p}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Expires at (optional)
                  <input
                    type="datetime-local"
                    value={expiry}
                    onChange={(e) => setExpiry(e.target.value)}
                  />
                </label>
                <button className="primary">Save grant</button>
              </form>
            </>
          )}
        </>
      )}
    </section>
  );
}
export function ApiKeys({ api, company, verification }: Props) {
  const keys = useData<RecordRow[]>(api, "/api-keys", []),
    [message, setMessage] = useState(""),
    [secret, setSecret] = useState(""),
    [name, setName] = useState(""),
    [days, setDays] = useState(90),
    [scopes, setScopes] = useState<string[]>(["projects:read"]);
  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      await keys.refresh();
      setMessage("");
    } catch (e) {
      setMessage((e as Error).message);
    }
  };
  return (
    <>
      <Heading title="API keys" company={company} />
      {verification}
      <Status message={message || keys.error} />
      {secret && (
        <section className="panel copy-once">
          <h2>Save this key now</h2>
          <p>The full key is shown once. It cannot be retrieved later.</p>
          <code>{secret}</code>
          <button
            onClick={() =>
              void navigator.clipboard
                .writeText(secret)
                .catch(() => setMessage("Select and copy the key manually."))
            }
          >
            Copy key
          </button>
          <button onClick={() => setSecret("")}>I saved it — dismiss</button>
        </section>
      )}
      <form
        className="panel"
        onSubmit={(e) => {
          e.preventDefault();
          void act(async () => {
            const r = await api<{ key: string }>("/api-keys", "POST", {
              name,
              scopes,
              expires_in_days: days,
            });
            setSecret(r.key);
            setName("");
          });
        }}
      >
        <h2>Create integration key</h2>
        <label>
          Name
          <input
            required
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          Expires in days
          <input
            type="number"
            min={1}
            max={365}
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
          />
        </label>
        <fieldset>
          <legend>Scopes</legend>
          {[
            "content:read",
            "content:write",
            "projects:read",
            "projects:write",
            "tasks:read",
            "tasks:write",
          ].map((scope) => (
            <label className="scope-check" key={scope}>
              <input
                type="checkbox"
                checked={scopes.includes(scope)}
                onChange={(e) =>
                  setScopes(
                    e.target.checked
                      ? [...scopes, scope]
                      : scopes.filter((s) => s !== scope),
                  )
                }
              />
              {scope}
            </label>
          ))}
        </fieldset>
        <button className="primary" disabled={!scopes.length}>
          Create key
        </button>
      </form>
      <section className="panel">
        <h2>Existing keys</h2>
        {keys.data.map((k) => (
          <div className="key-row" key={String(k.id)}>
            <div>
              <strong>{String(k.name)}</strong>
              <p>
                Prefix: {String(k.key_prefix)} · {String(k.status)} · expires{" "}
                {new Date(String(k.expires_at)).toLocaleDateString()}
              </p>
              <p>
                {(k.scopes as string[]).join(", ")} · last used{" "}
                {k.last_used_at
                  ? new Date(String(k.last_used_at)).toLocaleString()
                  : "Never"}
              </p>
              <small>Key ID: {String(k.id)}</small>
            </div>
            {k.status === "active" && (
              <div className="security-actions">
                <button
                  onClick={() =>
                    void act(async () => {
                      const r = await api<{ key: string }>(
                        `/api-keys/${k.id}/rotate`,
                        "POST",
                        {},
                      );
                      setSecret(r.key);
                    })
                  }
                >
                  Rotate
                </button>
                <button
                  onClick={() => {
                    if (window.confirm("Revoke this key immediately?"))
                      void act(() =>
                        api(`/api-keys/${k.id}/revoke`, "POST", {}),
                      );
                  }}
                >
                  Revoke
                </button>
              </div>
            )}
          </div>
        ))}
      </section>
    </>
  );
}
export function DataExplorer({ api, company, verification }: Props) {
  const [sort, setSort] = useState("created_at"),
    [direction, setDirection] = useState("desc");
  const sets = useData<{ name: string; columns: string[]; count: number }[]>(
      api,
      "/explorer",
      [],
    ),
    [dataset, setDataset] = useState("projects"),
    [filter, setFilter] = useState(""),
    [page, setPage] = useState(1),
    [hidden, setHidden] = useState<string[]>([]),
    [message, setMessage] = useState("");
  const table = useData<{ columns: string[]; rows: RecordRow[] }>(
    api,
    `/explorer/${dataset}?page=${page}&filter=${encodeURIComponent(filter)}&sort=${sort}&direction=${direction}`,
    { columns: [], rows: [] },
  );
  return (
    <>
      <Heading title="Data Explorer" company={company} />
      <div className="filters">
        <label>
          Sort by
          <select
            value={sort}
            onChange={(e) => {
              setSort(e.target.value);
              setPage(1);
            }}
          >
            <option value="created_at">Created date</option>
            <option value="id">ID</option>
          </select>
        </label>
        <label>
          Direction
          <select
            value={direction}
            onChange={(e) => {
              setDirection(e.target.value);
              setPage(1);
            }}
          >
            <option value="desc">Descending</option>
            <option value="asc">Ascending</option>
          </select>
        </label>
      </div>
      <p>
        Read-only datasets. Exports require fresh verification and include at
        most 1,000 rows. Restricted content is excluded from CSV exports.
      </p>
      {verification}
      <Status message={message || sets.error || table.error} />
      <div className="explorer-layout">
        <section className="panel dataset-list">
          {sets.data.map((d) => (
            <button
              key={d.name}
              className={d.name === dataset ? "selected" : ""}
              onClick={() => {
                setDataset(d.name);
                setPage(1);
                setHidden([]);
              }}
            >
              {d.name.replaceAll("_", " ")} <small>{d.count} rows</small>
            </button>
          ))}
        </section>
        <section className="panel">
          <div className="filters">
            <label>
              Filter
              <input
                value={filter}
                onChange={(e) => {
                  setFilter(e.target.value);
                  setPage(1);
                }}
              />
            </label>
            <button
              onClick={() =>
                void download(
                  `/explorer/${dataset}/export.csv?filter=${encodeURIComponent(filter)}`,
                  dataset + ".csv",
                ).catch((e) => setMessage(e.message))
              }
            >
              Export CSV
            </button>
          </div>
          <details>
            <summary>Visible columns</summary>
            {table.data.columns.map((c) => (
              <label className="scope-check" key={c}>
                <input
                  type="checkbox"
                  checked={!hidden.includes(c)}
                  onChange={(e) =>
                    setHidden(
                      e.target.checked
                        ? hidden.filter((h) => h !== c)
                        : [...hidden, c],
                    )
                  }
                />
                {c}
              </label>
            ))}
          </details>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {table.data.columns
                    .filter((c) => !hidden.includes(c))
                    .map((c) => (
                      <th key={c}>{c}</th>
                    ))}
                </tr>
              </thead>
              <tbody>
                {table.data.rows.map((r, i) => (
                  <tr key={String(r.id || i)}>
                    {table.data.columns
                      .filter((c) => !hidden.includes(c))
                      .map((c) => (
                        <td key={c}>
                          {typeof r[c] === "object"
                            ? JSON.stringify(r[c])
                            : String(r[c] ?? "—")}
                        </td>
                      ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <button disabled={page === 1} onClick={() => setPage(page - 1)}>
              Previous
            </button>
            <span>Page {page}</span>
            <button
              disabled={table.data.rows.length < 30}
              onClick={() => setPage(page + 1)}
            >
              Next
            </button>
          </div>
        </section>
      </div>
      <DataPolicy api={api} />
    </>
  );
}
export function SecurityAlerts({ api }: { api: Api }) {
  const alerts = useData<{
    events: RecordRow[];
    recent: RecordRow[];
    quota_near_limit: boolean;
  } | null>(api, "/security-alerts", null);
  const data = alerts.data;
  return (
    <section className="panel">
      <div className="section-heading">
        <h3>Recent security alerts</h3>
        <button onClick={() => void alerts.refresh()}>Refresh alerts</button>
      </div>
      <Status message={alerts.error} />
      {data && (
        <>
          <p>
            Rules inspect the last five minutes. Download and denial thresholds
            are 10 requests per actor; storage warning starts at 80%.
          </p>
          {data.quota_near_limit && (
            <p className="error">Storage quota is near its limit.</p>
          )}
          {data.events.map((event, i) => (
            <p className="error" key={i}>
              Actor {String(event.actor_user_id)}: {String(event.downloads)}{" "}
              downloads, {String(event.denied)} denied content requests.
            </p>
          ))}
          {data.recent.map((event, i) => (
            <p key={i}>
              <strong>{String(event.action)}</strong> · {String(event.reason)}
            </p>
          ))}
          {!data.quota_near_limit &&
            !data.events.length &&
            !data.recent.length && <p>No threshold alerts in this window.</p>}
        </>
      )}
    </section>
  );
}
export function DataPolicy({ api }: { api: Api }) {
  const policy = useData<{
      policy: RecordRow;
      usage: { storage_bytes: string };
    } | null>(api, "/data-policy", null),
    [message, setMessage] = useState("");
  const [quota, setQuota] = useState(""),
    [rows, setRows] = useState(""),
    [types, setTypes] = useState(""),
    [defaultClass, setDefaultClass] = useState(""),
    [kinds, setKinds] = useState<string[] | null>(null);
  const p = policy.data?.policy;
  return (
    <section className="panel">
      <h2>Storage and data policy</h2>
      <Status message={message || policy.error} />
      {p && (
        <>
          <p>
            {Math.round(Number(policy.data?.usage.storage_bytes) / 1024)} KB
            used / {Math.round(Number(p.max_storage_bytes) / 1048576)} MB
            allowed. Versions and deleted files count toward storage.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void api("/data-policy", "PUT", {
                allow_content_kinds: kinds ?? p.allow_content_kinds,
                allowed_mime_types: (
                  types || (p.allowed_mime_types as string[]).join(",")
                )
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
                max_storage_bytes: quota
                  ? Number(quota) * 1048576
                  : Number(p.max_storage_bytes),
                max_rows_per_table: rows
                  ? Number(rows)
                  : Number(p.max_rows_per_table),
                max_custom_fields: Number(p.max_custom_fields),
                default_classification:
                  defaultClass || String(p.default_classification),
              })
                .then(() => {
                  setMessage("Policy saved.");
                  void policy.refresh();
                })
                .catch((e) => setMessage(e.message));
            }}
          >
            <label>
              Default classification
              <select
                value={defaultClass || String(p.default_classification)}
                onChange={(e) => setDefaultClass(e.target.value)}
              >
                {classifications.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </label>
            <fieldset>
              <legend>Allowed content kinds</legend>
              {["file", "document"].map((k) => (
                <label className="scope-check" key={k}>
                  <input
                    type="checkbox"
                    checked={(
                      kinds ?? (p.allow_content_kinds as string[])
                    ).includes(k)}
                    onChange={(e) => {
                      const current =
                        kinds ?? (p.allow_content_kinds as string[]);
                      setKinds(
                        e.target.checked
                          ? [...current, k]
                          : current.filter((value) => value !== k),
                      );
                    }}
                  />
                  {k}
                </label>
              ))}
            </fieldset>
            <label>
              Storage quota (MB)
              <input
                type="number"
                min={1}
                placeholder={String(Number(p.max_storage_bytes) / 1048576)}
                value={quota}
                onChange={(e) => setQuota(e.target.value)}
              />
            </label>
            <label>
              Rows per table
              <input
                type="number"
                min={1}
                max={1000000}
                placeholder={String(p.max_rows_per_table)}
                value={rows}
                onChange={(e) => setRows(e.target.value)}
              />
            </label>
            <label>
              Allowed MIME types (comma separated)
              <textarea
                value={types}
                placeholder={(p.allowed_mime_types as string[]).join(",")}
                onChange={(e) => setTypes(e.target.value)}
              />
            </label>
            <button>Save data policy</button>
          </form>
          <div className="security-actions">
            <button
              onClick={() =>
                void api("/admin/keys/rotate", "POST", {})
                  .then(() =>
                    setMessage(
                      "Rotation queued. Check progress in Security Inspector.",
                    ),
                  )
                  .catch((e) => setMessage(e.message))
              }
            >
              Rotate tenant encryption key
            </button>
            <button
              onClick={() =>
                void api<RecordRow[]>("/admin/keys/rotation")
                  .then((jobs) =>
                    setMessage(
                      jobs.length
                        ? "Rotation: " +
                            jobs[0].status +
                            "; " +
                            jobs[0].completed_versions +
                            " versions"
                        : "No rotation jobs yet.",
                    ),
                  )
                  .catch((e) => setMessage(e.message))
              }
            >
              Check rotation status
            </button>
          </div>
        </>
      )}
    </section>
  );
}
