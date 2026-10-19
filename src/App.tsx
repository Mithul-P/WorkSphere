import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { Layers3, LayoutDashboard, FolderKanban, CheckCheck, ShieldCheck, Users, Plus, ArrowUpRight, ArrowRight, ChevronRight, Search, LogOut, X, MoreHorizontal, CalendarDays, LockKeyhole, Activity, Check, AlertTriangle, Copy, Building2, Mail, ExternalLink } from 'lucide-react';
type User = {
    id: string;
    name: string;
    email: string;
};
type Workspace = {
    id: string;
    name: string;
    role: 'admin' | 'member' | 'viewer';
};
type Project = {
    id: string;
    name: string;
    description: string;
    color: string;
    task_count: number;
    done_count: number;
};
type Task = {
    id: string;
    title: string;
    description: string;
    status: string;
    priority: string;
    project_id: string;
    project_name: string;
    project_color: string;
    assignee_id: string | null;
    assignee_name: string | null;
    due_date: string | null;
};
type Member = User & {
    role: string;
};
type Audit = {
    id: string;
    action: string;
    outcome: string;
    created_at: string;
    resource_id: string;
    request_id: string;
    actor_id: string;
};
type Modal = 'project' | 'task' | 'workspace' | 'invite' | 'accept' | null;
let csrf = '';
class ApiError extends Error {
    constructor(public status: number, message: string) { super(message); }
}
async function api<T = any>(url: string, method = 'GET', body?: unknown): Promise<T> { const r = await fetch(url, { method, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }); if (r.status === 204)
    return undefined as T; const data = await r.json(); if (!r.ok)
    throw new ApiError(r.status, data.error || 'Request failed'); return data; }
const initials = (name: string) => name.split(' ').map(s => s[0]).slice(0, 2).join('').toUpperCase();
const date = (value: string) => new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
const statusName: Record<string, string> = { todo: 'To do', in_progress: 'In progress', done: 'Done' };
function Brand() { return <div className="brand"><span className="brand-icon"><Layers3 size={22}/></span>WorkSphere<span className="brand-dot">.</span></div>; }
function App() {
    const [user, setUser] = useState<User | null>(null), [ready, setReady] = useState(false), [workspaces, setWorkspaces] = useState<Workspace[]>([]), [tenantId, setTenantId] = useState(''), [page, setPage] = useState('overview'), [projects, setProjects] = useState<Project[]>([]), [tasks, setTasks] = useState<Task[]>([]), [members, setMembers] = useState<Member[]>([]), [events, setEvents] = useState<Audit[]>([]), [selectedProject, setSelectedProject] = useState(''), [search, setSearch] = useState(''), [modal, setModal] = useState<Modal>(null), [toast, setToast] = useState(''), [error, setError] = useState(''), [loading, setLoading] = useState(false), [demo, setDemo] = useState(false), [pending, setPending] = useState(false), [invite, setInvite] = useState(''), [auditFilter, setAuditFilter] = useState('all'), [probe, setProbe] = useState(''), [probeResult, setProbeResult] = useState('');
    const workspace = workspaces.find(w => w.id === tenantId), canEdit = workspace?.role !== 'viewer', isAdmin = workspace?.role === 'admin';
    const base = `/api/workspaces/${tenantId}`;
    const activeScope=useRef('');
    activeScope.current=`${user?.id||''}:${tenantId}`;
    const notify = (message: string) => { setToast(message); setTimeout(() => setToast(''), 4500); };
    useEffect(() => { Promise.all([api('/api/auth/session').then(s => { setUser(s.user); csrf = s.csrf; }).catch(() => { }), api('/api/health').then(h => setDemo(h.demo)).catch(() => { })]).finally(() => setReady(true)); }, []);
    async function loadWorkspaces() { const currentUser=user?.id;const list = await api<Workspace[]>('/api/workspaces');if(!activeScope.current.startsWith(`${currentUser}:`))return; setWorkspaces(list); setTenantId(old => list.some(w => w.id === old) ? old : list[0]?.id || ''); }
    useEffect(() => { if (user)
        loadWorkspaces().catch(e => setError(e.message)); }, [user?.id]);
    async function refresh() { if (!tenantId)
        return; const requestedScope=activeScope.current;setLoading(true); try {
        const [p, t, m] = await Promise.all([api<Project[]>(base + '/projects'), api<Task[]>(base + '/tasks'), api<Member[]>(base + '/members')]);
        const log=isAdmin?await api<Audit[]>(base+'/audit'):[];
        if(activeScope.current!==requestedScope)return;
        setProjects(p);
        setTasks(t);
        setMembers(m);
        setEvents(log);
        setError('');
    }
    catch (e) {
        if(activeScope.current!==requestedScope)return;
        setError((e as Error).message);
        if (e instanceof ApiError && e.status === 401)
            setUser(null);
    }
    finally {
        if(activeScope.current===requestedScope)setLoading(false);
    } }
    useEffect(() => { setSelectedProject(''); setProbeResult('');setProjects([]);setTasks([]);setMembers([]);setEvents([]); refresh(); }, [tenantId, workspace?.role,user?.id]);
    useEffect(() => { if (demo && user)
        api('/api/demo/target').then(r => setProbe(r.projectId || '')).catch(() => { }); }, [demo, user?.id]);
    useEffect(() => { if (!modal)
        return; function escape(e: KeyboardEvent) { if (e.key === 'Escape')
        setModal(null); } document.addEventListener('keydown', escape); return () => document.removeEventListener('keydown', escape); }, [modal]);
    const filteredTasks = tasks.filter(t => (!selectedProject || t.project_id === selectedProject) && (!search || t.title.toLowerCase().includes(search.toLowerCase())) && (page !== 'mytasks' || t.assignee_id === user?.id));
    const currentProject = projects.find(p => p.id === selectedProject);
    async function mutate(fn: () => Promise<unknown>, message: string) { setPending(true); try {
        await fn();
        await refresh();
        notify(message);
        setModal(null);
    }
    catch (e) {
        setError((e as Error).message);
    }
    finally {
        setPending(false);
    } }
    async function submitModal(e: FormEvent<HTMLFormElement>) { e.preventDefault(); const data = new FormData(e.currentTarget); if (modal === 'project')
        return mutate(() => api(base + '/projects', 'POST', { name: data.get('name'), description: data.get('description'), color: data.get('color') }), 'Project created'); if (modal === 'task')
        return mutate(() => api(`${base}/projects/${data.get('project')}/tasks`, 'POST', { title: data.get('title'), description: data.get('description'), priority: data.get('priority'), assigneeId: data.get('assignee') || null, dueDate: data.get('due') || null }), 'Task added'); if (modal === 'workspace') {
        setPending(true);
        try {
            const w = await api('/api/workspaces', 'POST', { name: data.get('name') });
            await loadWorkspaces();
            setTenantId(w.id);
            setModal(null);
            notify('Your workspace is ready');
        }
        catch (e) {
            setError((e as Error).message);
        }
        finally {
            setPending(false);
        }
        return;
    } if (modal === 'invite') {
        setPending(true);
        try {
            const r = await api(base + '/invitations', 'POST', { email: data.get('email'), role: data.get('role') });
            setInvite(r.token);
            notify('Invitation created. Share the token with your teammate.');
        }
        catch (e) {
            setError((e as Error).message);
        }
        finally {
            setPending(false);
        }
        return;
    } if (modal === 'accept') {
        return mutate(async () => { await api('/api/invitations/accept', 'POST', { token: data.get('token') }); await loadWorkspaces(); }, 'Invitation accepted');
    } }
    async function runProbe() { setPending(true); setProbeResult(''); try {
        await api(`${base}/projects/${encodeURIComponent(probe)}`);
        setProbeResult('200 · This project belongs to your workspace and is accessible.');
    }
    catch (e) {
        if (e instanceof ApiError)
            setProbeResult(`${e.status} · ${e.status === 404 ? 'Access blocked. No project data returned. Audit event recorded.' : e.message}`);
        else
            setProbeResult((e as Error).message);
    }
    finally {
        await refresh();
        setPending(false);
    } }
    if (!ready)
        return <div className="splash"><Brand /><p>Opening your workspace…</p></div>;
    if (!user)
        return <Login demo={demo} onLogin={s => { csrf = s.csrf; setUser(s.user); setError(''); }}/>;
    const nav = [['overview', LayoutDashboard, 'Overview'], ['projects', FolderKanban, 'Projects'], ['mytasks', CheckCheck, 'My tasks'], ['team', Users, 'Team'], ...(isAdmin ? [['security', ShieldCheck, 'Security Inspector']] : [])] as [
        string,
        typeof Users,
        string
    ][];
    return <div className="app-shell">
  <aside className="sidebar"><Brand /><div className="workspace-picker"><span className="workspace-avatar">{workspace?.name?.[0] || 'W'}</span><div><label htmlFor="workspace-select">Workspace</label><select id="workspace-select" value={tenantId} onChange={e => { setPage('overview'); setTenantId(e.target.value); }}>{workspaces.map(w => <option key={w.id} value={w.id}>{w.name}</option>)}</select></div></div><div className="nav-label">WORKSPACE</div><nav>{nav.map(([key, Icon, label]) => <button className={'nav-item ' + (page === key ? 'active' : '')} onClick={() => { setPage(key); setSearch(''); setSelectedProject(''); }} key={key}><Icon size={19}/><span>{label}</span>{key === 'projects' && <small>{projects.length}</small>}{key === 'security' && <i className="live-dot"/>}</button>)}</nav><div className="sidebar-projects"><div className="nav-label">YOUR PROJECTS {canEdit && <button className="icon-button" title="New project" onClick={() => { setError(''); setModal('project'); }}><Plus size={16}/></button>}</div>{projects.slice(0, 5).map(p => <button key={p.id} className="project-link" onClick={() => { setPage('projects'); setSelectedProject(p.id); }}><i className={'project-dot ' + p.color}/>{p.name}</button>)}</div><div className="sidebar-bottom"><div className="boundary-note"><ShieldCheck size={21}/><div><b>Your space. Your data.</b><span>Tenant isolation is active</span></div></div><button className="secondary sidebar-action" onClick={() => { setError(''); setModal('workspace'); }}><Plus size={16}/>Create workspace</button><button className="plain sidebar-action" onClick={() => { setError(''); setModal('accept'); }}>Have an invite? Join a workspace</button><div className="profile"><span className="avatar dark">{initials(user.name)}</span><div><b>{user.name}</b><small>{workspace?.role || 'New member'}</small></div><button className="icon-button" aria-label="Sign out" onClick={async () => { try {
        await api('/api/auth/logout', 'POST');
        csrf = '';
        setUser(null);
        setTenantId('');
        setProjects([]);
        setTasks([]);
        setEvents([]);
    }
    catch (e) {
        setError((e as Error).message);
    } }}><LogOut size={17}/></button></div></div></aside>
  <div className="main-shell"><header className="topbar"><div className="breadcrumb">{workspace?.name || 'WorkSphere'}<ChevronRight size={14}/><span>{page === 'security' ? 'Security Inspector' : page === 'mytasks' ? 'My tasks' : page[0].toUpperCase() + page.slice(1)}</span></div><div className="topbar-right"><span className="secure-label"><LockKeyhole size={13}/>Secure workspace</span><span className="avatar small">{initials(user.name)}</span></div></header>
  <main><div className="page-heading"><div><div className="eyebrow">{page === 'overview' ? 'YOUR WORK, IN FOCUS' : page === 'security' ? 'TRUST THROUGH VISIBILITY' : 'A SHARED SPACE, A CLEAR NEXT STEP'}</div><h1>{page === 'overview' ? `Good to see you, ${user.name.split(' ')[0]}.` : page === 'security' ? 'Tenant Security Inspector' : page === 'team' ? 'Better, together.' : page === 'mytasks' ? 'Your next great work.' : currentProject?.name || 'A space for every idea.'}</h1><p>{page === 'overview' ? 'A little clarity. A lot of possibility. Here’s where your team stands.' : page === 'security' ? 'A clear record of access decisions inside your workspace.' : page === 'team' ? 'The people making things happen in your workspace.' : page === 'mytasks' ? 'Everything assigned to you, all in one place.' : currentProject?.description || 'Bring your projects, people, and progress together.'}</p></div>{page === 'team' && isAdmin ? <button className="primary" onClick={() => { setInvite(''); setError(''); setModal('invite'); }}><Plus size={17}/>Invite teammate</button> : canEdit && page !== 'security' && page !== 'team' ? <button className="primary" onClick={() => { setError(''); setModal(page === 'overview' || !projects.length ? 'project' : 'task'); }}><Plus size={18}/>{page === 'overview' || !projects.length ? 'New project' : 'Add task'}</button> : <span className="role-tag">{workspace?.role || 'Member'}</span>}</div>
  {error && <div className="error-banner" role="alert"><AlertTriangle size={18}/>{error}<button aria-label="Dismiss error" onClick={() => setError('')}><X size={16}/></button></div>}
  {!workspace ? <div className="empty-state"><Building2 size={36}/><h2>Your next chapter starts here.</h2><p>Create your own workspace or join one with an invitation.</p><button className="primary" onClick={() => setModal('workspace')}>Create workspace</button></div> : <>
  {page === 'overview' && <><section className="hero"><div className="hero-content"><span className="hero-kicker"><i />ALL TOGETHER, MOVING FORWARD</span><h2>Good work happens<br />in a shared space.</h2><p>Make room for what matters. Turn your team’s<br className="desktop"/> ideas into a little more progress, every day.</p><button onClick={() => { setPage('projects'); setSelectedProject(''); }}>Explore your projects<ArrowUpRight size={18}/></button></div><div className="hero-art" aria-hidden="true"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="art-card card-back"><span /><span /><span /></div><div className="art-card card-front"><div className="card-mini-title"><span className="tiny-icon"><Check size={13}/></span>A little more progress</div><div className="art-line"/><div className="art-line short"/><div className="art-check"><Check size={13}/><span>Better, together</span></div><div className="art-progress"><span /></div><div className="mini-avatars"><i>MC</i><i>AM</i><i>SR</i><em>+ your team</em></div></div><div className="art-float"><ShieldCheck size={22}/></div><div className="spark spark-one">✦</div><div className="spark spark-two">✧</div></div></section><section className="stats-grid">{[[FolderKanban, projects.length, 'Active projects', 'Ideas taking shape'], [CheckCheck, tasks.filter(t => t.status === 'done').length, 'Tasks completed', 'Small wins, big momentum'], [Users, members.length, 'Team members', 'Different minds. Shared goals.'], [ShieldCheck, events.filter(e => e.outcome === 'denied').length, 'Blocked requests', isAdmin ? 'Visible in your Inspector' : 'Admin visibility only']].map(([Icon, n, label, caption], i) => { const I = Icon as typeof Users; return <article className="stat" key={String(label)}><div className={'stat-icon s' + i}><I size={19}/></div><div className="stat-value">{n as ReactNode}</div><b>{label as string}</b><p>{caption as string}</p></article>; })}</section></>}
  {(page === 'overview' || page === 'projects') && !selectedProject && <section><div className="section-heading"><div><h2>{page === 'overview' ? 'Your projects' : 'All projects'}<span className="count">{projects.length}</span></h2><p>A shared goal, a clear next step.</p></div>{page === 'overview' ? <button className="plain" onClick={() => setPage('projects')}>View all projects<ArrowRight size={16}/></button> : <label className="search-box"><Search size={16}/><input aria-label="Search projects" placeholder="Find a project…" value={search} onChange={e => setSearch(e.target.value)}/></label>}</div><div className="project-grid">{projects.filter(p => p.name.toLowerCase().includes(search.toLowerCase())).map(p => <button key={p.id} className="project-card" onClick={() => { setPage('projects'); setSelectedProject(p.id); setSearch(''); }}><div className="project-card-top"><span className={'project-symbol ' + p.color}><FolderKanban size={23}/></span><ArrowUpRight size={19}/></div><h3>{p.name}</h3><p>{p.description || 'A new idea, ready to take shape.'}</p><div className="project-progress-label"><span>{p.done_count} of {p.task_count} tasks</span><b>{p.task_count ? Math.round(p.done_count / p.task_count * 100) : 0}%</b></div><div className={'progress-bar ' + p.color}><span style={{ width: `${p.task_count ? p.done_count / p.task_count * 100 : 0}%` }}/></div><div className="project-card-footer"><span className="stacked-avatars">{members.slice(0, 3).map(m => <i key={m.id}>{initials(m.name)}</i>)}</span><span>{p.task_count ? 'In motion' : 'Just getting started'}</span></div></button>)}{canEdit && <button className="new-project-card" onClick={() => setModal('project')}><span><Plus size={23}/></span><b>Make space for something new</b><small>Create a project</small></button>}</div></section>}
  {page === 'overview' && <section className="bottom-grid"><div className="focus-list"><div className="section-heading"><div><h2>A few things in motion</h2><p>Your team’s next steps.</p></div><button className="plain" onClick={() => setPage('mytasks')}>My tasks<ArrowUpRight size={15}/></button></div>{tasks.filter(t => t.status !== 'done').slice(0, 4).map(t => <div className="focus-task" key={t.id}><button className="task-check" disabled={!canEdit} aria-label={`Complete ${t.title}`} onClick={() => mutate(() => api(base + '/tasks/' + t.id, 'PATCH', { status: 'done' }), 'One more win for the team')}><Check size={13}/></button><div><b>{t.title}</b><small>{t.project_name}</small></div><span className={'priority ' + t.priority}>{t.priority}</span></div>)}</div><div className="security-summary"><div className="summary-icon"><ShieldCheck size={25}/></div><h3>A boundary you can trust.</h3><p>Workspace membership, role checks and database row policies keep each company’s data within its own space.</p>{isAdmin ? <button className="plain" onClick={() => setPage('security')}>Open Security Inspector<ArrowUpRight size={17}/></button> : <small>Your admin can review access events.</small>}</div></section>}
  {(page === 'mytasks' || page === 'projects' && !!selectedProject) && <section className="board-section"><div className="board-toolbar"><button className="plain" onClick={() => { setSelectedProject(''); setPage('projects'); }}>← All projects</button><label className="search-box"><Search size={16}/><input aria-label="Search tasks" placeholder="Find a task…" value={search} onChange={e => setSearch(e.target.value)}/></label><span className="subtle">{filteredTasks.length} tasks</span>{isAdmin && selectedProject && <button className="danger plain" onClick={() => { if (confirm('Delete this project and all its tasks?'))
            mutate(async () => { await api(base + '/projects/' + selectedProject, 'DELETE'); setSelectedProject(''); }, 'Project deleted'); }}>Delete project</button>}</div><div className="task-board">{Object.entries(statusName).map(([status, label]) => <div className={'board-column ' + status} key={status} onDragOver={e => { if (canEdit)
            e.preventDefault(); }} onDrop={e => { e.preventDefault(); const taskId = e.dataTransfer.getData('text/plain'); if (canEdit && filteredTasks.some(t => t.id === taskId))
            mutate(() => api(base + '/tasks/' + taskId, 'PATCH', { status }), 'Task moved'); }}><div className="column-heading"><h3><i />{label}<span>{filteredTasks.filter(t => t.status === status).length}</span></h3>{canEdit && <button className="icon-button" aria-label={`Add task to ${label}`} onClick={() => setModal('task')}><Plus size={16}/></button>}</div>{filteredTasks.filter(t => t.status === status).map(t => <article key={t.id} className="task-card" draggable={canEdit} onDragStart={e => e.dataTransfer.setData('text/plain', t.id)}><div className="task-card-top"><span className={'priority ' + t.priority}>{t.priority}</span><button className="icon-button" aria-label={`Delete ${t.title}`} disabled={!canEdit} onClick={() => { if (confirm('Delete this task?'))
            mutate(() => api(base + '/tasks/' + t.id, 'DELETE'), 'Task deleted'); }}><X size={14}/></button></div><h4>{t.title}</h4>{t.description && <p>{t.description}</p>}<div className="task-meta"><span>{t.assignee_name ? <><i className="avatar tiny">{initials(t.assignee_name)}</i>{t.assignee_name.split(' ')[0]}</> : 'Unassigned'}</span>{t.due_date && <span><CalendarDays size={12}/>{date(t.due_date)}</span>}</div><label className="status-control">Status<select aria-label={`Status of ${t.title}`} disabled={!canEdit || pending} value={t.status} onChange={e => mutate(() => api(base + '/tasks/' + t.id, 'PATCH', { status: e.target.value }), 'Task status updated')}>{Object.entries(statusName).map(([v, n]) => <option key={v} value={v}>{n}</option>)}</select></label></article>)}{canEdit && <button className="add-card" onClick={() => setModal('task')}><Plus size={15}/>Add task</button>}</div>)}</div></section>}
  {page === 'team' && <section className="panel"><div className="panel-heading"><h2>Workspace members <span className="count">{members.length}</span></h2><span>Roles apply within {workspace.name}</span></div><div className="table-scroll"><table><thead><tr><th>Teammate</th><th>Email</th><th>Workspace role</th><th>Permissions</th></tr></thead><tbody>{members.map(m => <tr key={m.id}><td><div className="person"><span className="avatar">{initials(m.name)}</span><b>{m.name}{m.id === user.id && <small> (you)</small>}</b></div></td><td>{m.email}</td><td>{isAdmin ? <select aria-label={`Role for ${m.name}`} value={m.role} onChange={e => mutate(async () => { await api(base + '/members/' + m.id, 'PATCH', { role: e.target.value }); await loadWorkspaces(); }, 'Member role updated')}><option value="admin">Admin</option><option value="member">Member</option><option value="viewer">Viewer</option></select> : <span className="role-tag">{m.role}</span>}</td><td>{m.role === 'admin' ? 'Work + members + Inspector' : m.role === 'member' ? 'Read and edit work' : 'Read work'}</td></tr>)}</tbody></table></div></section>}
  {page === 'security' && isAdmin && <><div className="inspector-intro"><ShieldCheck size={26}/><div><b>Tenant isolation is enforced on the server and in PostgreSQL.</b><p>Each request checks current membership, role and resource ownership. Events below belong to {workspace.name}.</p></div><span className="active-label"><i />Active</span></div><section className="probe-panel"><div><span className="eyebrow">TENANT BOUNDARY CHECK</span><h2>Try a request across the boundary.</h2><p>{demo ? 'The demo preloads a project ID from Beta Labs. An Alpha Studio session should receive a 404.' : 'Enter a project ID to verify access from this workspace.'}</p></div><div className="probe-form"><label htmlFor="probe">Project ID</label><div><input id="probe" value={probe} onChange={e => setProbe(e.target.value)} placeholder="Project UUID"/><button className="primary" disabled={pending || !probe} onClick={runProbe}>Run check<ArrowRight size={16}/></button></div>{probeResult && <output className={probeResult.startsWith('404') ? 'probe-denied' : 'probe-output'}>{probeResult}</output>}</div></section><section className="panel"><div className="panel-heading"><h2>Access and activity log <span className="count">{events.length}</span></h2><div className="filter-group">{['all', 'allowed', 'denied'].map(v => <button key={v} className={auditFilter === v ? 'chosen' : ''} onClick={() => setAuditFilter(v)}>{v[0].toUpperCase() + v.slice(1)}</button>)}</div><button className="plain" onClick={refresh}>Refresh</button></div><div className="table-scroll"><table><thead><tr><th>Event</th><th>Outcome</th><th>Actor</th><th>Time</th><th>Request ID</th></tr></thead><tbody>{events.filter(e => auditFilter === 'all' || e.outcome === auditFilter).map(e => <tr key={e.id}><td>{e.action.replaceAll('.', ' / ').replaceAll('_', ' ')}</td><td><span className={'outcome ' + e.outcome}>{e.outcome === 'allowed' ? <Check size={12}/> : <LockKeyhole size={12}/>} {e.outcome}</span></td><td>{members.find(m => m.id === e.actor_id)?.name || 'Workspace user'}</td><td>{new Date(e.created_at).toLocaleString()}</td><td><code title={e.request_id}>{e.request_id.slice(0, 8)}</code></td></tr>)}</tbody></table>{!events.length && <div className="empty-inline">No events yet. Create a project or run a boundary check.</div>}</div></section></>}
  </>}{loading && <span className="loading-indicator" role="status">Updating workspace…</span>}<footer className="main-footer"><span><Layers3 size={13}/>A little more connected. A little more in sync.</span><span>WorkSphere · Syntax Syndicate</span></footer></main></div>
  {toast && <div className="toast" role="status"><Check size={17}/>{toast}</div>}
  {modal && <div className="modal-overlay" onMouseDown={e => { if (e.target === e.currentTarget)
        setModal(null); }}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><button className="modal-close icon-button" aria-label="Close dialog" onClick={() => setModal(null)}><X size={20}/></button><div className="modal-icon"><Layers3 size={22}/></div><h2 id="modal-title">{modal === 'project' ? 'Make space for a new idea.' : modal === 'task' ? 'One clear next step.' : modal === 'workspace' ? 'Create your team’s space.' : modal === 'accept' ? 'Join your teammates.' : 'Invite a new perspective.'}</h2><p>{modal === 'invite' ? 'Create a one-time invitation valid for 24 hours. The recipient must sign in with the matching email.' : 'Your workspace keeps everything in the right place.'}</p>{error && <p className="form-error" role="alert">{error}</p>}<form onSubmit={submitModal}>{(modal === 'project' || modal === 'workspace') && <label>Name<input name="name" required autoFocus maxLength={80} placeholder={modal === 'project' ? 'e.g. Website redesign' : 'e.g. Acme Studio'}/></label>}{modal === 'project' && <><label>Description<textarea name="description" rows={3} maxLength={1000} placeholder="What are we making happen?"/></label><label>Project color<select name="color"><option value="green">Forest green</option><option value="purple">Soft violet</option><option value="orange">Warm orange</option><option value="blue">Ocean blue</option></select></label></>}{modal === 'task' && <><label>Task title<input name="title" required autoFocus maxLength={180} placeholder="What’s the next step?"/></label><label>Project<select name="project" defaultValue={selectedProject || projects[0]?.id}>{projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label><label>Description<textarea name="description" rows={2} maxLength={2000}/></label><div className="form-row"><label>Priority<select name="priority" defaultValue="medium"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></label><label>Due date<input type="date" name="due"/></label></div><label>Assignee<select name="assignee"><option value="">Unassigned</option>{members.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}</select></label></>}{modal === 'invite' && <><label>Email<input name="email" type="email" required autoFocus placeholder="teammate@company.com"/></label><label>Workspace role<select name="role" defaultValue="member"><option value="member">Member — read and edit work</option><option value="viewer">Viewer — read only</option><option value="admin">Admin — manage workspace</option></select></label>{invite && <div className="invite-result"><b>Invitation token</b><code>{invite}</code><button type="button" className="secondary" onClick={async () => { try {
        await navigator.clipboard.writeText(invite);
        notify('Invitation copied');
    }
    catch {
        notify('Select and copy the invitation token above');
    } }}><Copy size={15}/>Copy token</button><small>Share privately with the recipient. This app does not send email.</small></div>}</>}{modal === 'accept' && <label>Invitation token<input name="token" required autoFocus minLength={64} maxLength={64} placeholder="Paste the invitation token"/></label>}<div className="modal-actions"><button type="button" className="secondary" onClick={() => setModal(null)}>Cancel</button><button className="primary" disabled={pending || modal === 'task' && !projects.length}>{pending ? 'Saving…' : modal === 'invite' ? 'Create invitation' : modal === 'accept' ? 'Join workspace' : modal === 'task' ? 'Create task' : modal === 'project' ? 'Create project' : 'Create workspace'}<ArrowRight size={16}/></button></div></form></section></div>}
 </div>;
}
function Login({ onLogin, demo }: {
    onLogin: (s: any) => void;
    demo: boolean;
}) { const [register, setRegister] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState(''), [email, setEmail] = useState(''), [password, setPassword] = useState(''); async function submit(e: FormEvent<HTMLFormElement>) { e.preventDefault(); setBusy(true); setError(''); const f = new FormData(e.currentTarget); try {
    onLogin(await api(register ? '/api/auth/register' : '/api/auth/login', 'POST', { email, password, ...(register ? { name: f.get('name') } : {}) }));
}
catch (e) {
    setError((e as Error).message);
}
finally {
    setBusy(false);
} } return <div className="login-page"><div className="login-story"><Brand /><div><span className="hero-kicker">A SPACE FOR YOUR TEAM’S NEXT CHAPTER</span><h1>Great work.<br />Shared space.<br /><em>Endless possibility.</em></h1><p>Your projects, your people, and your progress.<br />Together in a workspace that’s truly yours.</p><div className="login-features"><span><CheckCheck size={18}/>Projects with purpose</span><span><ShieldCheck size={18}/>Clear company boundaries</span><span><Users size={18}/>Better together</span></div></div><small>BUILT BY SYNTAX SYNDICATE · ADVANTIX HACKATHON</small></div><div className="login-form"><div className="login-form-inner"><span className="login-mark"><Layers3 size={28}/></span><h2>{register ? 'Your next chapter starts here.' : 'Welcome back.'}</h2><p>{register ? 'Create an account and find your team’s space.' : 'A good day to make something happen.'}</p>{error && <div className="form-error" role="alert">{error}</div>}<form onSubmit={submit}>{register && <label>Your name<input name="name" required minLength={2} maxLength={80} autoComplete="name"/></label>}<label>Email address<input type="email" required value={email} onChange={e => setEmail(e.target.value)} autoComplete="email" placeholder="you@company.com"/></label><label>Password<input type="password" required minLength={12} maxLength={128} value={password} onChange={e => setPassword(e.target.value)} autoComplete={register ? 'new-password' : 'current-password'} placeholder="At least 12 characters"/></label><button className="primary full" disabled={busy}>{busy ? 'Opening your workspace…' : register ? 'Create account' : 'Enter your workspace'}<ArrowRight size={18}/></button></form><p className="login-toggle">{register ? 'Already have a space?' : 'New around here?'} <button onClick={() => { setRegister(!register); setError(''); }}>{register ? 'Sign in' : 'Create an account'}</button></p>{demo && <div className="demo-logins"><b>Explore the live demo</b><p>Choose a role. Then select “Enter your workspace.”</p><div>{[['Alpha admin', 'admin@alpha.demo'], ['Member', 'member@alpha.demo'], ['Viewer', 'viewer@alpha.demo'], ['Beta admin', 'admin@beta.demo']].map(([n, e]) => <button key={e} onClick={() => { setRegister(false); setEmail(e); setPassword('WorkSphereDemo2026!'); }}>{n}</button>)}</div><small>Demo accounts are enabled only in local demo mode.</small></div>}<div className="login-security"><LockKeyhole size={14}/>Your company’s work stays in your company’s space.</div></div></div></div>; }
export default App;
