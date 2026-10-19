import {PGlite, type Transaction} from '@electric-sql/pglite';
import {randomUUID} from 'node:crypto';
import {readFile, mkdir} from 'node:fs/promises';
import path from 'node:path';

export type Row = Record<string, any>;
export class Database {
  constructor(public readonly pg: PGlite) {}
  async query<T extends Row = Row>(sql:string, args:unknown[]=[]){return (await this.pg.query<T>(sql,args)).rows;}
  async scope<T>(tenantId:string, action:(tx:Transaction)=>Promise<T>, beforeRole?:(tx:Transaction)=>Promise<void>){
    return this.pg.transaction(async tx=>{
      if(beforeRole)await beforeRole(tx);
      await tx.query("SELECT set_config('app.tenant_id', $1, true)",[tenantId]);
      await tx.exec('SET LOCAL ROLE worksphere_app');
      return action(tx);
    });
  }
  async close(){await this.pg.close();}
}
export async function openDatabase(directory?:string){
  if(directory)await mkdir(directory,{recursive:true});
  const db=new Database(new PGlite(directory));
  await db.pg.waitReady;
  await db.pg.exec(await readFile(new URL('./schema.sql',import.meta.url),'utf8'));
  return db;
}
export const id=()=>randomUUID();
export const first=async<T extends Row=Row>(tx:Transaction,sql:string,args:unknown[]=[]) => (await tx.query<T>(sql,args)).rows[0];
