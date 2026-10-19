CREATE TABLE IF NOT EXISTS tenant_keys (
 tenant_id uuid PRIMARY KEY REFERENCES tenants(id), encrypted_dek text NOT NULL CHECK(length(encrypted_dek) BETWEEN 1 AND 500),
 key_version int NOT NULL DEFAULT 1 CHECK(key_version>0), created_at timestamptz NOT NULL DEFAULT now(), rotated_at timestamptz
);
ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON tenant_keys;
CREATE POLICY tenant_isolation ON tenant_keys USING(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
DROP TRIGGER IF EXISTS immutable_tenant ON tenant_keys;
CREATE TRIGGER immutable_tenant BEFORE UPDATE ON tenant_keys FOR EACH ROW EXECUTE FUNCTION immutable_tenant_id();
REVOKE ALL ON tenant_keys FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON tenant_keys TO worksphere_app;
