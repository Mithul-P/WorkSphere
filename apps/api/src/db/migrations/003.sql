CREATE OR REPLACE FUNCTION content_can_access(uid uuid, actor_role text, iid uuid, requested text) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=public,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM content_items i
 JOIN memberships m ON m.tenant_id=i.tenant_id AND m.user_id=uid AND m.status='active' AND m.role=actor_role
 WHERE i.id=iid AND i.deleted_at IS NULL
 AND requested IN ('view','download','edit','share','manage')
 AND (requested NOT IN ('edit','share','manage') OR actor_role='admin' OR (actor_role='member' AND i.owner_id=uid AND requested<>'manage'))
 AND (requested<>'download' OR i.scan_status='clean')
 AND (
   (i.owner_id=uid AND i.classification<>'restricted')
   OR (actor_role='admin' AND i.classification='internal')
   OR EXISTS(SELECT 1 FROM content_acl a WHERE a.tenant_id=i.tenant_id AND a.item_id=i.id
    AND (a.expires_at IS NULL OR a.expires_at>now())
    AND ((a.principal_type='user' AND a.principal_id=uid::text) OR (a.principal_type='role' AND a.principal_id=actor_role))
    AND (a.permission=requested OR a.permission='manage' OR (requested='view' AND a.permission IN ('download','edit','share'))))
 ));
$$;
REVOKE ALL ON FUNCTION content_can_access(uuid,text,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION content_can_access(uuid,text,uuid,text) TO worksphere_app;
