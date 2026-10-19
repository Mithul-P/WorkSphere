ALTER TABLE tenant_data_policy ADD COLUMN IF NOT EXISTS default_classification text NOT NULL DEFAULT 'internal' CHECK(default_classification IN ('internal','confidential','restricted'));
CREATE TABLE IF NOT EXISTS key_rotation_jobs (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES tenants(id),created_by uuid NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed')),
 completed_versions int NOT NULL DEFAULT 0 CHECK(completed_versions>=0),created_at timestamptz NOT NULL DEFAULT now(),finished_at timestamptz,
 FOREIGN KEY(tenant_id,created_by) REFERENCES memberships(tenant_id,user_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_tenant_rotation ON key_rotation_jobs(tenant_id) WHERE status IN ('queued','running');
ALTER TABLE key_rotation_jobs ENABLE ROW LEVEL SECURITY;ALTER TABLE key_rotation_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON key_rotation_jobs;
CREATE POLICY tenant_isolation ON key_rotation_jobs USING(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
DROP TRIGGER IF EXISTS immutable_tenant ON key_rotation_jobs;
CREATE TRIGGER immutable_tenant BEFORE UPDATE ON key_rotation_jobs FOR EACH ROW EXECUTE FUNCTION immutable_tenant_id();
REVOKE ALL ON key_rotation_jobs FROM PUBLIC;GRANT SELECT,INSERT,UPDATE,DELETE ON key_rotation_jobs TO worksphere_app;
