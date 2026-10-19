import type pg from "pg";
import type { Role } from "./permissions.js";
export type ContentAction = "view" | "download" | "edit" | "share" | "manage";
export type ContentActor = {
  id: string;
  role: Role;
  tenantId: string;
  apiKey?: string;
};
// One database predicate powers both individual checks and SQL-filtered pagination.
export const contentPredicate =
  "content_can_access($1::uuid,$2::text,i.id,$3::text,$8::uuid)";
export async function canAccessContent(
  db: pg.PoolClient,
  actor: ContentActor,
  itemId: string,
  action: ContentAction,
) {
  const { rows } = await db.query(
    "SELECT content_can_access($1,$2,$3,$4,$5) AS allowed",
    [actor.id, actor.role, itemId, action, actor.apiKey ?? null],
  );
  return rows[0]?.allowed === true;
}
