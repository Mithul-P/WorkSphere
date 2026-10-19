import path from 'node:path';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { openDatabase } from './database.js';
import { createApp } from './app.js';
import { seedDemo } from './seed.js';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const production = process.env.NODE_ENV === 'production';
const demo = process.env.DEMO_MODE === 'true' || (!production && process.env.DEMO_MODE !== 'false');
const port = Number(process.env.PORT || 3000);
const origin = process.env.APP_ORIGIN || `http://localhost:${port}`;
const db = await openDatabase(process.env.DATA_DIR || path.join(root, '.data'));
if (demo)
    await seedDemo(db);
const app = createApp(db, { origin, production, demo });
if (production) {
    app.use((_req, res, next) => { res.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"); next(); });
    app.use(express.static(path.join(root, 'dist')));
    app.get('/{*path}', (_req, res) => res.sendFile(path.join(root, 'dist/index.html')));
}
else {
    const { createServer } = await import('vite');
    const vite = await createServer({ root, server: { middlewareMode: true }, appType: 'spa' });
    app.use(vite.middlewares);
}
const server = app.listen(port, '127.0.0.1', () => { console.log(`WorkSphere ready: ${origin}`); console.log(`Demo mode: ${demo ? 'enabled (local demonstration accounts)' : 'disabled'}`); });
async function stop() { server.close(); await db.close(); process.exit(0); }
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
