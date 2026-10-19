CREATE TABLE IF NOT EXISTS users(id uuid PRIMARY KEY, email text UNIQUE NOT NULL, password_hash text NOT NULL, totp_secret_encrypted text NOT NULL, totp_enabled boolean NOT NULL DEFAULT true, last_used_counter bigint NOT NULL DEFAULT -1, failed_attempts int NOT NULL DEFAULT 0, locked_until timestamptz, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS tenants(id uuid PRIMARY KEY,name text NOT NULL,slug text UNIQUE NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS memberships(id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES tenants,user_id uuid NOT NULL REFERENCES users,role text NOT NULL CHECK(role IN ('admin','member','viewer')),status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(tenant_id,user_id));
CREATE TABLE IF NOT EXISTS tenant_policies(tenant_id uuid PRIMARY KEY REFERENCES tenants,access_days int[] NOT NULL DEFAULT ARRAY[0,1,2,3,4,5,6],access_start time NOT NULL DEFAULT '00:00',access_end time NOT NULL DEFAULT '23:59:59',timezone text NOT NULL DEFAULT 'Asia/Kolkata',require_trusted_device boolean NOT NULL DEFAULT false);
CREATE TABLE IF NOT EXISTS trusted_devices(id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES tenants,user_id uuid NOT NULL REFERENCES users,device_token_hash text NOT NULL,label text NOT NULL,status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','revoked')),created_at timestamptz NOT NULL DEFAULT now(),approved_by uuid REFERENCES users,UNIQUE(tenant_id,user_id,device_token_hash));
CREATE TABLE IF NOT EXISTS projects(id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES tenants,name text NOT NULL,description text NOT NULL DEFAULT '',created_by uuid NOT NULL REFERENCES users,created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(tenant_id,id));
CREATE TABLE IF NOT EXISTS tasks(id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES tenants,project_id uuid NOT NULL,title text NOT NULL,status text NOT NULL DEFAULT 'todo' CHECK(status IN ('todo','in_progress','done')),assignee_id uuid,created_at timestamptz NOT NULL DEFAULT now(),FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id) ON DELETE CASCADE,FOREIGN KEY(tenant_id,assignee_id) REFERENCES memberships(tenant_id,user_id));
CREATE TABLE IF NOT EXISTS audit_events(id uuid PRIMARY KEY,tenant_id uuid REFERENCES tenants,actor_user_id uuid REFERENCES users,action text NOT NULL,resource_type text,resource_id text,outcome text NOT NULL CHECK(outcome IN ('allowed','denied','failed')),reason text,request_id text,ip text,user_agent text,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS access_overrides(id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES tenants,user_id uuid NOT NULL REFERENCES users,expires_at timestamptz NOT NULL,used_at timestamptz,created_by uuid NOT NULL REFERENCES users);
CREATE TABLE IF NOT EXISTS session(sid varchar PRIMARY KEY,sess json NOT NULL,expire timestamp(6) NOT NULL);
CREATE INDEX IF NOT EXISTS session_expire ON session(expire);
CREATE INDEX IF NOT EXISTS audit_tenant_time ON audit_events(tenant_id,created_at DESC);
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['memberships','tenant_policies','trusted_devices','projects','tasks','audit_events','access_overrides'] LOOP
EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I',t);
EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',t);
END LOOP; END $$;
-- SECURITY DEFINER exposes only the caller-selected user membership discovery needed before selection.
-- Database credentials are trusted server credentials; never expose them to a browser.
CREATE OR REPLACE FUNCTION discover_workspaces(uid uuid) RETURNS TABLE(tenant_id uuid,name text,slug text,role text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE t record; prior text;
BEGIN
 prior:=current_setting('app.tenant_id',true);
 FOR t IN SELECT id FROM tenants LOOP
  PERFORM set_config('app.tenant_id',t.id::text,true);
  RETURN QUERY SELECT m.tenant_id,tn.name,tn.slug,m.role FROM memberships m JOIN tenants tn ON tn.id=m.tenant_id WHERE m.user_id=uid AND m.status='active';
 END LOOP;
 PERFORM set_config('app.tenant_id',coalesce(prior,''),true);
END $$;
REVOKE ALL ON FUNCTION discover_workspaces(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION discover_workspaces(uuid) TO worksphere_app;
GRANT USAGE ON SCHEMA public TO worksphere_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON users,session,projects,tasks,memberships,tenant_policies,trusted_devices,access_overrides TO worksphere_app;
GRANT SELECT ON tenants TO worksphere_app;
GRANT SELECT,INSERT ON audit_events TO worksphere_app;
