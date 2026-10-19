CREATE TABLE IF NOT EXISTS api_keys (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL REFERENCES tenants(id),created_by uuid NOT NULL,
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 100), key_prefix text NOT NULL UNIQUE CHECK(key_prefix ~ '^[a-zA-Z0-9_-]{8}$'),
 key_hash text NOT NULL CHECK(key_hash ~ '^[a-f0-9]{64}$'), scopes text[] NOT NULL CHECK(cardinality(scopes) BETWEEN 1 AND 6 AND scopes <@ ARRAY['content:read','content:write','projects:read','projects:write','tasks:read','tasks:write']),
 status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')), expires_at timestamptz NOT NULL,
 last_used_at timestamptz,last_used_ip inet, rate_limit_per_min int NOT NULL DEFAULT 60 CHECK(rate_limit_per_min BETWEEN 1 AND 300),
 ip_allowlist cidr[],created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES memberships(tenant_id,user_id)
);
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY; ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON api_keys;
CREATE POLICY tenant_isolation ON api_keys USING(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
DROP TRIGGER IF EXISTS immutable_tenant ON api_keys;
CREATE TRIGGER immutable_tenant BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION immutable_tenant_id();
REVOKE ALL ON api_keys FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON api_keys TO worksphere_app;
-- Narrow lookup needed before the bearer tenant is known, following the existing
-- workspace discovery pattern. The runtime credential is a trusted server boundary.
CREATE OR REPLACE FUNCTION discover_api_key(prefix text) RETURNS SETOF api_keys LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE t record; prior text;
BEGIN prior:=current_setting('app.tenant_id',true);
 FOR t IN SELECT id FROM tenants LOOP
  PERFORM set_config('app.tenant_id',t.id::text,true);
  RETURN QUERY SELECT * FROM api_keys WHERE key_prefix=prefix;
 END LOOP;
 PERFORM set_config('app.tenant_id',coalesce(prior,''),true);
END $$;
REVOKE ALL ON FUNCTION discover_api_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION discover_api_key(text) TO worksphere_app;
CREATE OR REPLACE FUNCTION validate_content_principal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.principal_type='user' THEN
  IF NOT EXISTS(SELECT 1 FROM memberships WHERE tenant_id=NEW.tenant_id AND user_id::text=NEW.principal_id AND status='active') THEN RAISE EXCEPTION 'Invalid content principal'; END IF;
 ELSIF NEW.principal_type='role' THEN
  IF NEW.principal_id NOT IN ('admin','member','viewer') THEN RAISE EXCEPTION 'Invalid content principal'; END IF;
 ELSIF NEW.principal_type='api_key' THEN
  IF NOT EXISTS(SELECT 1 FROM api_keys WHERE tenant_id=NEW.tenant_id AND id::text=NEW.principal_id AND status='active' AND expires_at>now()) THEN RAISE EXCEPTION 'Invalid content principal'; END IF;
 ELSE RAISE EXCEPTION 'Unsupported content principal'; END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION content_can_access(uid uuid, actor_role text, iid uuid, requested text, service_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=public,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM content_items i
 JOIN memberships m ON m.tenant_id=i.tenant_id AND m.user_id=uid AND m.status='active'
 WHERE i.id=iid AND i.deleted_at IS NULL AND (service_id IS NOT NULL OR m.role=actor_role)
 AND requested IN ('view','download','edit','share','manage')
 AND (service_id IS NULL OR (i.classification<>'restricted' AND requested NOT IN ('share','manage') AND EXISTS(SELECT 1 FROM api_keys k WHERE k.id=service_id AND k.tenant_id=i.tenant_id AND k.status='active' AND k.expires_at>now())))
 AND (requested NOT IN ('edit','share','manage') OR actor_role='admin' OR (actor_role='member' AND (i.owner_id=uid OR service_id IS NOT NULL) AND requested<>'manage'))
 AND (requested<>'download' OR i.scan_status='clean')
 AND (
  (service_id IS NULL AND i.owner_id=uid AND i.classification<>'restricted')
  OR (service_id IS NULL AND actor_role='admin' AND i.classification='internal')
  OR EXISTS(SELECT 1 FROM content_acl a WHERE a.tenant_id=i.tenant_id AND a.item_id=i.id AND (a.expires_at IS NULL OR a.expires_at>now())
   AND ((service_id IS NULL AND ((a.principal_type='user' AND a.principal_id=uid::text) OR (a.principal_type='role' AND a.principal_id=actor_role))) OR (service_id IS NOT NULL AND a.principal_type='api_key' AND a.principal_id=service_id::text))
   AND (a.permission=requested OR a.permission='manage' OR (requested='view' AND a.permission IN ('download','edit','share'))))
 ));
$$;
REVOKE ALL ON FUNCTION content_can_access(uuid,text,uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION content_can_access(uuid,text,uuid,text,uuid) TO worksphere_app;
