import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.js';
import { InputError } from '../server/scanner.js';

async function withServer(app, run) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  try { await run(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

const jsonPost = (base, body) => fetch(`${base}/api/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('configuration reports availability without exposing the API key', async () => {
  await withServer(createApp({ apiKey: 'test-secret' }), async (base) => {
    const response = await fetch(`${base}/api/config`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const body = await response.text();
    assert(!body.includes('test-secret'));
    assert.equal(JSON.parse(body).reputation.configured, true);
  });
});

test('validates JSON, forwards opt-in, and handles input errors', async () => {
  let options;
  const app = createApp({ apiKey: 'key', scanner: async (url, opts) => {
    options = opts;
    if (url === 'bad') throw new InputError('Invalid URL.');
    return { hostname: 'example.com' };
  } });
  await withServer(app, async (base) => {
    let response = await jsonPost(base, { url: 'https://example.com', includeReputation: true });
    assert.equal(response.status, 200);
    assert.deepEqual(options, { includeReputation: true, apiKey: 'key' });
    response = await jsonPost(base, { url: 'bad' });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, 'Invalid URL.');
    response = await jsonPost(base, { url: 'https://example.com', includeReputation: 'true' });
    assert.equal(response.status, 400);
    response = await fetch(`${base}/api/scan`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'https://example.com' });
    assert.equal(response.status, 415);
  });
});

test('applies a basic per-client rate limit', async () => {
  await withServer(createApp({ scanner: async () => ({ ok: true }) }), async (base) => {
    for (let i = 0; i < 15; i++) assert.equal((await jsonPost(base, { url: 'https://example.com' })).status, 200);
    const limited = await jsonPost(base, { url: 'https://example.com' });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '60');
  });
});

test('health checks do not reveal secrets or consume scan rate limits', async () => {
  await withServer(createApp({ apiKey: 'test-secret', scanner: async () => ({ ok: true }), trustProxyHops: 0 }), async (base) => {
    for (let i = 0; i < 20; i++) {
      const health = await fetch(`${base}/api/health`);
      assert.equal(health.status, 200);
      assert.deepEqual(await health.json(), { status: 'ok' });
      assert.equal(health.headers.get('cache-control'), 'no-store');
    }
    assert.equal((await jsonPost(base, { url: 'https://example.com' })).status, 200);
  });
});

test('one trusted proxy hop ignores forged left-most forwarded addresses', async () => {
  const app = createApp({ scanner: async () => ({ ok: true }), trustProxyHops: 1 });
  await withServer(app, async (base) => {
    const postFrom = (forwarded) => fetch(`${base}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': forwarded },
      body: JSON.stringify({ url: 'https://example.com' }),
    });
    // A caller changes an earlier address while the trusted proxy appends the
    // same address on the right. Every request must hit the same rate bucket.
    for (let i = 0; i < 15; i++) {
      assert.equal((await postFrom(`198.51.100.${i + 1}, 203.0.113.10`)).status, 200);
    }
    assert.equal((await postFrom('198.51.100.99, 203.0.113.10')).status, 429);
    assert.equal((await postFrom('198.51.100.99, 203.0.113.11')).status, 200);
  });
});

test('rejects invalid proxy-hop configuration instead of trusting all proxies', () => {
  for (const trustProxyHops of [-1, 4, NaN, 1.5]) {
    assert.throws(() => createApp({ trustProxyHops }), /TRUST_PROXY_HOPS/);
  }
});
