import 'dotenv/config';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from './app.js';
import { attachProductionFrontend } from './production.js';

const app = createApp();
const httpServer = http.createServer(app);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.env.PORT) || 3000;

if (process.env.NODE_ENV === 'production') {
  attachProductionFrontend(app, path.join(root, 'dist'));
} else {
  const { createServer } = await import('vite');
  const vite = await createServer({ root, server: { middlewareMode: true, allowedHosts: true, hmr: { server: httpServer } }, appType: 'spa' });
  app.use(vite.middlewares);
}

httpServer.listen(port, '0.0.0.0', () => {
  console.log(`Linkscope is listening on port ${port}`);
});
