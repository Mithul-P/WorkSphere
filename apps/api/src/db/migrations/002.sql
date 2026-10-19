-- Phase 7: all tenant content references use composite foreign keys.
CREATE TABLE IF NOT EXISTS tenant_data_policy (
 tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
 allow_content_kinds text[] NOT NULL DEFAULT ARRAY['document','file'],
 allowed_mime_types text[] NOT NULL DEFAULT ARRAY['application/pdf','image/png','image/jpeg','text/plain','text/markdown','text/csv','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
 max_storage_bytes bigint NOT NULL DEFAULT 209715200 CHECK(max_storage_bytes BETWEEN 1 AND 1099511627776),
 max_rows_per_table int NOT NULL DEFAULT 10000 CHECK(max_rows_per_table BETWEEN 1 AND 1000000),
 max_custom_fields int NOT NULL DEFAULT 20 CHECK(max_custom_fields BETWEEN 0 AND 100),
 CHECK(allow_content_kinds <@ ARRAY['document','file']), CHECK(cardinality(allowed_mime_types) BETWEEN 1 AND 20)
);
CREATE TABLE IF NOT EXISTS content_items (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), project_id uuid,
 owner_id uuid NOT NULL, title text NOT NULL CHECK(length(title) BETWEEN 1 AND 150),
 kind text NOT NULL CHECK(kind IN ('document','file')),
 classification text NOT NULL DEFAULT 'internal' CHECK(classification IN ('internal','confidential','restricted')),
 mime_type text NOT NULL CHECK(length(mime_type) BETWEEN 1 AND 150),
 size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 10485760),
 sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'), storage_key text NOT NULL CHECK(length(storage_key) BETWEEN 1 AND 200),
 scan_status text NOT NULL CHECK(scan_status IN ('pending','clean','quarantined')),
 version int NOT NULL DEFAULT 1 CHECK(version > 0), deleted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,id), FOREIGN KEY(tenant_id,project_id) REFERENCES projects(tenant_id,id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES memberships(tenant_id,user_id)
);
CREATE TABLE IF NOT EXISTS content_acl (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), item_id uuid NOT NULL,
 principal_type text NOT NULL CHECK(principal_type IN ('user','role','project','api_key')),
 principal_id text NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 50),
 permission text NOT NULL CHECK(permission IN ('view','download','edit','share','manage')),
 granted_by uuid NOT NULL, expires_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,item_id) REFERENCES content_items(tenant_id,id),
 FOREIGN KEY(tenant_id,granted_by) REFERENCES memberships(tenant_id,user_id),
 UNIQUE(tenant_id,item_id,principal_type,principal_id,permission)
);
CREATE TABLE IF NOT EXISTS content_versions (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), item_id uuid NOT NULL,
 version int NOT NULL CHECK(version > 0), storage_key text NOT NULL CHECK(length(storage_key) BETWEEN 1 AND 200),
 sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'), size_bytes bigint NOT NULL CHECK(size_bytes BETWEEN 1 AND 10485760),
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,item_id) REFERENCES content_items(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES memberships(tenant_id,user_id), UNIQUE(tenant_id,item_id,version)
);
CREATE INDEX IF NOT EXISTS content_tenant_created ON content_items(tenant_id,created_at DESC,id);
CREATE INDEX IF NOT EXISTS acl_item ON content_acl(tenant_id,item_id);
CREATE OR REPLACE FUNCTION immutable_tenant_id() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN RAISE EXCEPTION 'tenant_id is immutable'; END IF; RETURN NEW; END $$;
REVOKE ALL ON FUNCTION immutable_tenant_id() FROM PUBLIC;
DO $$ DECLARE t record; BEGIN
 FOR t IN SELECT c.table_name FROM information_schema.columns c JOIN information_schema.tables b USING(table_schema,table_name)
 WHERE c.table_schema='public' AND c.column_name='tenant_id' AND b.table_type='BASE TABLE' LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t.table_name);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t.table_name);
 EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I',t.table_name);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid) WITH CHECK(tenant_id=nullif(current_setting(''app.tenant_id'',true),'''')::uuid)',t.table_name);
 EXECUTE format('DROP TRIGGER IF EXISTS immutable_tenant ON %I',t.table_name);
 EXECUTE format('CREATE TRIGGER immutable_tenant BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION immutable_tenant_id()',t.table_name);
 END LOOP;
END $$;
-- No project membership model exists yet: deny project and service-principal ACLs
-- until those principals can be checked, rather than treating a project as membership.
CREATE OR REPLACE FUNCTION validate_content_principal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.principal_type='user' THEN
  IF NOT EXISTS(SELECT 1 FROM memberships WHERE tenant_id=NEW.tenant_id AND user_id::text=NEW.principal_id AND status='active') THEN RAISE EXCEPTION 'Invalid content principal'; END IF;
 ELSIF NEW.principal_type='role' THEN
  IF NEW.principal_id NOT IN ('admin','member','viewer') THEN RAISE EXCEPTION 'Invalid content principal'; END IF;
 ELSE RAISE EXCEPTION 'Unsupported content principal';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION validate_content_principal() FROM PUBLIC;
DROP TRIGGER IF EXISTS content_principal ON content_acl;
CREATE TRIGGER content_principal BEFORE INSERT OR UPDATE ON content_acl FOR EACH ROW EXECUTE FUNCTION validate_content_principal();
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO worksphere_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON content_items,content_acl,content_versions,tenant_data_policy TO worksphere_app;
REVOKE UPDATE,DELETE ON audit_events FROM worksphere_app;
-- Bootstrap administrators create this NOLOGIN group; migrations never need CREATEROLE.
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='worksphere_readonly') THEN
 REVOKE ALL ON ALL TABLES IN SCHEMA public FROM worksphere_readonly;
 GRANT USAGE ON SCHEMA public TO worksphere_readonly;
 END IF; END $$;
