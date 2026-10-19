import { type Database, id } from './database.js';
import { hashPassword } from './auth.js';
export const DEMO_PASSWORD = 'WorkSphereDemo2026!';
export async function seedDemo(db: Database) {
    if ((await db.query('SELECT id FROM users LIMIT 1')).length)
        return;
    const password = await hashPassword(DEMO_PASSWORD);
    const people = [['Maya Chen', 'admin@alpha.demo'], ['Alex Morgan', 'member@alpha.demo'], ['Sam Rivera', 'viewer@alpha.demo'], ['Jordan Lee', 'admin@beta.demo']];
    const ids = people.map(() => id());
    for (let i = 0; i < people.length; i++)
        await db.query('INSERT INTO users(id,name,email,password_hash) VALUES($1,$2,$3,$4)', [ids[i], ...people[i], password]);
    const alpha = id(), beta = id();
    await db.query('INSERT INTO tenants(id,name) VALUES($1,$2),($3,$4)', [alpha, 'Alpha Studio', beta, 'Beta Labs']);
    for (let i = 0; i < 3; i++)
        await db.query('INSERT INTO memberships VALUES($1,$2,$3)', [alpha, ids[i], ['admin', 'member', 'viewer'][i]]);
    await db.query('INSERT INTO memberships VALUES($1,$2,$3)', [beta, ids[3], 'admin']);
    const projects = [['Website redesign', 'A thoughtful new home for our next chapter.', 'green'], ['Product launch', 'Bring the next release to life, together.', 'purple'], ['Customer research', 'Learn what matters to the people we build for.', 'orange']];
    const projectIds = projects.map(() => id());
    for (let i = 0; i < projects.length; i++)
        await db.query('INSERT INTO projects(id,tenant_id,name,description,color,created_by) VALUES($1,$2,$3,$4,$5,$6)', [projectIds[i], alpha, ...projects[i], ids[0]]);
    const taskData = [['Map the new user journey', 'in_progress', 'high', 0, 1], ['Explore visual directions', 'in_progress', 'medium', 0, 0], ['Review accessibility checklist', 'todo', 'high', 0, 1], ['Build the design system', 'todo', 'medium', 0, 0], ['Collect team feedback', 'done', 'low', 0, 1], ['Set up project workspace', 'done', 'low', 0, 0], ['Draft the launch story', 'in_progress', 'medium', 1, 0], ['Create release checklist', 'todo', 'high', 1, 1], ['Schedule customer interviews', 'todo', 'medium', 2, 0]];
    for (const [title, status, priority, projectIndex, assignee] of taskData)
        await db.query("INSERT INTO tasks(id,tenant_id,project_id,title,status,priority,assignee_id,due_date) VALUES($1,$2,$3,$4,$5,$6,$7,CURRENT_DATE+5)", [id(), alpha, projectIds[Number(projectIndex)], title, status, priority, ids[Number(assignee)]]);
    const secretProject = id();
    await db.query('INSERT INTO projects(id,tenant_id,name,description,color,created_by) VALUES($1,$2,$3,$4,$5,$6)', [secretProject, beta, 'Beta private roadmap', 'Only Beta Labs members may access this.', 'purple', ids[3]]);
    await db.query('INSERT INTO tasks(id,tenant_id,project_id,title,created_at) VALUES($1,$2,$3,$4,now())', [id(), beta, secretProject, 'Beta confidential task']);
    // A fixed demo target is stored separately from API data and exposed only in demo mode.
    await db.query('CREATE TABLE IF NOT EXISTS demo_targets(project_id uuid NOT NULL)');
    await db.query('INSERT INTO demo_targets VALUES($1)', [secretProject]);
}
