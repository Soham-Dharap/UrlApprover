import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';
import { createApp } from '../server/app.js';
import { attachProductionFrontend } from '../server/production.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('Render Blueprint uses one web service with a real health check and no required secret', async () => {
  const blueprint = YAML.parse(await readFile(path.join(root, 'render.yaml'), 'utf8'));
  assert.equal(blueprint.services.length, 1);
  const service = blueprint.services[0];
  assert.equal(service.name, 'cyberace');
  assert.equal(service.type, 'web');
  assert.equal(service.runtime, 'node');
  assert.equal(service.plan, 'free');
  assert.equal(service.healthCheckPath, '/api/health');
  assert.equal(service.buildCommand, 'npm ci --include=dev && npm run build');
  assert.equal(service.startCommand, 'npm start');
  assert.equal(service.envVars.find((entry) => entry.key === 'NODE_VERSION').value, '22.23.4');
  assert.equal(service.envVars.find((entry) => entry.key === 'TRUST_PROXY_HOPS').value, '1');
  assert.equal(service.envVars.some((entry) => entry.key === 'VIRUSTOTAL_API_KEY'), false);
});

test('production frontend serves the SPA and static assets without swallowing API routes', async () => {
  const dist = await mkdtemp(path.join(os.tmpdir(), 'linkscope-dist-'));
  const app = createApp({ apiKey: '', trustProxyHops: 0 });
  let server;
  try {
    await mkdir(path.join(dist, 'assets'));
    await writeFile(path.join(dist, 'index.html'), '<!doctype html><title>Linkscope test</title>');
    await writeFile(path.join(dist, 'assets', 'app.js'), 'console.log("asset");');
    attachProductionFrontend(app, dist);
    server = app.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const index = await fetch(`${base}/`);
    assert.equal(index.status, 200);
    assert.match(await index.text(), /Linkscope test/);
    const head = await fetch(`${base}/`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
    const asset = await fetch(`${base}/assets/app.js`);
    assert.equal(asset.status, 200);
    assert.match(asset.headers.get('content-type'), /javascript/);
    assert.equal((await fetch(`${base}/api/health`)).status, 200);
    assert.equal((await fetch(`${base}/api/not-found`)).status, 404);
    assert.equal((await fetch(`${base}/`, { method: 'POST' })).status, 404);
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    await rm(dist, { recursive: true, force: true });
  }
});
