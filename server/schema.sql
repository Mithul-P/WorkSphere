CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY, name text NOT NULL, email text NOT NULL UNIQUE,
 password_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf text NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
 id uuid PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS memberships (
 tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 role text NOT NULL CHECK(role IN ('admin','member','viewer')),
 PRIMARY KEY(tenant_id,user_id)
);
CREATE TABLE IF NOT EXISTS projects (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
 name text NOT NULL, description text NOT NULL DEFAULT '', color text NOT NULL DEFAULT 'green',
 created_by uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS tasks (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), project_id uuid NOT NULL,
 title text NOT NULL, description text NOT NULL DEFAULT '',
 status text NOT NULL DEFAULT 'todo' CHECK(status IN ('todo','in_progress','done')),
 priority text NOT NULL DEFAULT 'medium' CHECK(priority IN ('low','medium','high')),
 assignee_id uuid, due_date date,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id) ON DELETE CASCADE,
 FOREIGN KEY(tenant_id,assignee_id) REFERENCES memberships(tenant_id,user_id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS audit_events (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), actor_id uuid NOT NULL REFERENCES users(id),
 action text NOT NULL, resource_id text, outcome text NOT NULL CHECK(outcome IN ('allowed','denied')),
 request_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS invitations (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), email text NOT NULL,
 role text NOT NULL CHECK(role IN ('admin','member','viewer')), token_hash text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL, accepted_at timestamptz, created_by uuid NOT NULL REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS task_tenant_project ON tasks(tenant_id,project_id);
CREATE INDEX IF NOT EXISTS audit_tenant_time ON audit_events(tenant_id,created_at DESC);
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='worksphere_app') THEN
  CREATE ROLE worksphere_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
 END IF;
END $$;
GRANT USAGE ON SCHEMA public TO worksphere_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON projects,tasks,invitations TO worksphere_app;
GRANT SELECT, INSERT ON audit_events TO worksphere_app;
-- Membership and identity resolution remain in narrow, server-controlled queries.
-- The application role cannot query users, sessions or memberships directly.
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['projects','tasks','audit_events','invitations'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT FROM pg_policies WHERE tablename=t AND policyname='tenant_boundary') THEN
   EXECUTE format('CREATE POLICY tenant_boundary ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',t);
  END IF;
 END LOOP;
END $$;
