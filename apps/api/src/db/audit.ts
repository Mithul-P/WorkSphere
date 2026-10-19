import type pg from "pg";
export async function auditDatabase(
  db: Pick<pg.Pool, "query">,
): Promise<string[]> {
  const issues: string[] = [];
  const tables =
    await db.query(`SELECT c.oid,c.relname,c.relrowsecurity,c.relforcerowsecurity,
    EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND t.tgname='immutable_tenant' AND NOT t.tgisinternal AND t.tgenabled='O') AS immutable
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relkind IN ('r','p') AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' AND NOT a.attisdropped)`);
  for (const t of tables.rows) {
    if (!t.relrowsecurity || !t.relforcerowsecurity)
      issues.push(`${t.relname}: RLS must be enabled and forced`);
    if (!t.immutable)
      issues.push(`${t.relname}: tenant immutability trigger missing`);
  }
  const role = await db.query(
    "SELECT rolsuper,rolbypassrls,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname='worksphere_app'",
  );
  if (!role.rows.length || Object.values(role.rows[0]).some(Boolean))
    issues.push("Application role has unsafe privileges");
  const owned = await db.query(
    "SELECT c.relname FROM pg_class c JOIN pg_roles r ON c.relowner=r.oid JOIN pg_namespace n ON c.relnamespace=n.oid WHERE r.rolname='worksphere_app' AND n.nspname='public'",
  );
  if (owned.rows.length) issues.push("Application role owns database objects");
  const grants = await db.query(
    "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE n.nspname='public' AND c.relkind IN ('r','p','v') AND a.grantee=0",
  );
  if (grants.rows.length) issues.push("PUBLIC has table grants");
  const unsafe = await db.query(
    "SELECT has_table_privilege('worksphere_app','audit_events','UPDATE') OR has_table_privilege('worksphere_app','audit_events','DELETE') AS unsafe, has_schema_privilege('worksphere_app','public','CREATE') AS ddl",
  );
  if (unsafe.rows[0].unsafe)
    issues.push("Audit events are mutable by application role");
  if (unsafe.rows[0].ddl)
    issues.push("Application role can create schema objects");
  const readonly = await db.query(
    "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname='worksphere_readonly'",
  );
  if (!readonly.rows.length || Object.values(readonly.rows[0]).some(Boolean))
    issues.push("Readonly role missing or privileged");
  else {
    const secrets = await db.query(
      "SELECT has_column_privilege('worksphere_readonly','users','password_hash','SELECT') OR has_column_privilege('worksphere_readonly','users','totp_secret_encrypted','SELECT') OR has_column_privilege('worksphere_readonly','api_keys','key_hash','SELECT') OR has_column_privilege('worksphere_readonly','tenant_keys','encrypted_dek','SELECT') OR has_column_privilege('worksphere_readonly','content_items','storage_key','SELECT') AS exposed",
    );
    if (secrets.rows[0].exposed)
      issues.push("Readonly role can select secrets");
  }
  const memberships = await db.query(
    "SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='worksphere_app'",
  );
  if (memberships.rows.length)
    issues.push("Application role inherits another role");
  return issues;
}
