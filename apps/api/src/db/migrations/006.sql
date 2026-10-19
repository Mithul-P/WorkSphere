CREATE OR REPLACE VIEW explorer_projects WITH(security_invoker=true) AS SELECT id,tenant_id,name,description,created_by,created_at FROM projects;
CREATE OR REPLACE VIEW explorer_tasks WITH(security_invoker=true) AS SELECT id,tenant_id,project_id,title,status,assignee_id,created_at FROM tasks;
CREATE OR REPLACE VIEW explorer_content_items WITH(security_invoker=true) AS SELECT id,tenant_id,project_id,owner_id,title,kind,classification,mime_type,size_bytes,scan_status,version,created_at FROM content_items WHERE deleted_at IS NULL;
CREATE OR REPLACE VIEW explorer_members WITH(security_invoker=true) AS SELECT id,tenant_id,user_id,role,status,created_at FROM memberships;
CREATE OR REPLACE VIEW explorer_api_keys WITH(security_invoker=true) AS SELECT id,tenant_id,name,key_prefix,scopes,status,expires_at,last_used_at,created_at FROM api_keys;
CREATE OR REPLACE VIEW explorer_audit WITH(security_invoker=true) AS SELECT id,tenant_id,actor_user_id,action,outcome,resource_type,resource_id,reason,request_id,created_at FROM audit_events;
GRANT SELECT ON explorer_projects,explorer_tasks,explorer_content_items,explorer_members,explorer_api_keys,explorer_audit TO worksphere_app;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='worksphere_readonly') THEN
 GRANT SELECT ON explorer_projects,explorer_tasks,explorer_content_items,explorer_members,explorer_api_keys,explorer_audit TO worksphere_readonly;
 -- security_invoker views require column grants to the invoker; secret columns remain inaccessible.
 GRANT SELECT(id,tenant_id,name,description,created_by,created_at) ON projects TO worksphere_readonly;
 GRANT SELECT(id,tenant_id,project_id,title,status,assignee_id,created_at) ON tasks TO worksphere_readonly;
 GRANT SELECT(id,tenant_id,project_id,owner_id,title,kind,classification,mime_type,size_bytes,scan_status,version,created_at,deleted_at) ON content_items TO worksphere_readonly;
 GRANT SELECT(id,tenant_id,user_id,role,status,created_at) ON memberships TO worksphere_readonly;
 GRANT SELECT(id,tenant_id,name,key_prefix,scopes,status,expires_at,last_used_at,created_at) ON api_keys TO worksphere_readonly;
 GRANT SELECT(id,tenant_id,actor_user_id,action,outcome,resource_type,resource_id,reason,request_id,created_at) ON audit_events TO worksphere_readonly;
 END IF; END $$;
-- A serialized database guard enforces row quotas even for existing write paths.
CREATE OR REPLACE FUNCTION enforce_tenant_row_quota() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE cap int; used bigint;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text,0));
 SELECT max_rows_per_table INTO cap FROM tenant_data_policy WHERE tenant_id=NEW.tenant_id;
 cap:=coalesce(cap,10000);
 EXECUTE format('SELECT count(*) FROM %I WHERE tenant_id=$1',TG_TABLE_NAME) INTO used USING NEW.tenant_id;
 IF used>=cap THEN RAISE EXCEPTION 'Tenant row quota exceeded' USING ERRCODE='P0422'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION enforce_tenant_row_quota() FROM PUBLIC;
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['projects','tasks','content_items','content_acl','content_versions','api_keys','memberships','trusted_devices','access_overrides'] LOOP
 EXECUTE format('DROP TRIGGER IF EXISTS tenant_row_quota ON %I',t);
 EXECUTE format('CREATE TRIGGER tenant_row_quota BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION enforce_tenant_row_quota()',t);
 END LOOP;END $$;
