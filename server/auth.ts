import {randomBytes, createHash, scrypt, timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
const scryptAsync=promisify(scrypt);
export const randomToken=()=>randomBytes(32).toString('hex');
export const digest=(value:string)=>createHash('sha256').update(value).digest('hex');
export async function hashPassword(password:string){const salt=randomBytes(16).toString('hex');const hash=await scryptAsync(password,salt,64) as Buffer;return `${salt}:${hash.toString('hex')}`;}
export async function checkPassword(password:string,stored:string){const [salt,value]=stored.split(':');const expected=Buffer.from(value,'hex');const actual=await scryptAsync(password,salt,64) as Buffer;return actual.length===expected.length&&timingSafeEqual(actual,expected);}
