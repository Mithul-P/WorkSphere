import pg from "pg";
import { config } from "../config.js";
// Raw pool is restricted to authentication, sessions and the narrow membership discovery function.
// All tenant table access MUST use withTenant; never export tenant repositories accepting Pool.
export const pool = new pg.Pool({ connectionString: config.DATABASE_URL });
export async function withTenant<T>(
  tenantId: string,
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.tenant_id',$1,true)", [
      tenantId,
    ]);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
