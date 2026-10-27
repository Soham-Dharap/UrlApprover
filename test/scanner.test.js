import test from 'node:test';
import assert from 'node:assert/strict';
import { InputError, displayUrl, isPublicAddress, lookupVirusTotal, parseInput, scanUrl } from '../server/scanner.js';

const publicLookup = async () => [{ address: '8.8.8.8', family: 4 }];
const goodTls = async () => ({ ok: true, protocol: 'TLSv1.3', validTo: 'Jan 01 00:00:00 2030 GMT' });
const freshCleanReport = async () => ({ stats: { malicious: 0, suspicious: 0, harmless: 20, undetected: 50 }, lastAnalysisDate: Math.floor(Date.now() / 1000) });
const freshMaliciousReport = async () => ({ stats: { malicious: 2, suspicious: 1, harmless: 20, undetected: 50 }, lastAnalysisDate: Math.floor(Date.now() / 1000) });
const check = (report, id) => report.checks.find((item) => item.id === id);

const baseOptions = { lookup: publicLookup, inspectTls: goodTls };

test('normalizes ordinary domains and rejects unsafe schemes and malformed input', () => {
  assert.equal(parseInput(' github.com/path ').href, 'https://github.com/path');
  assert.equal(parseInput('http://example.com').protocol, 'http:');
  for (const input of ['', 'javascript:alert(1)', 'file:///etc/passwd', 'ftp://example.com', 'https://bad host', `https://${'x'.repeat(2049)}`, 'https://example.com/\u0000']) {
    assert.throws(() => parseInput(input), InputError, input);
  }
});

test('normalization exposes unusual IP encodings before policy checks', async () => {
  assert.equal(parseInput('http://2130706433').hostname, '127.0.0.1');
  assert.equal(parseInput('http://0177.0.0.1').hostname, '127.0.0.1');
  for (const address of ['127.0.0.1', '10.1.2.3', '169.254.169.254', '100.64.0.1', '192.0.2.1', '::1', 'fc00::1', '::ffff:127.0.0.1', '::7f00:1', '4000::1', '2002:7f00:1::', '64:ff9b::7f00:1']) {
    assert.equal(isPublicAddress(address), false, `${address} should be blocked`);
  }
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2001:4860:4860::8888'), true);
});

test('never connects to local names or non-public IPs', async () => {
  let lookupCount = 0;
  let tlsCount = 0;
  let reputationCount = 0;
  const options = {
    apiKey: 'key', includeReputation: true,
    lookup: async () => { lookupCount += 1; return [{ address: '127.0.0.1', family: 4 }]; },
    inspectTls: async () => { tlsCount += 1; return { ok: true }; },
    lookupReputation: async () => { reputationCount += 1; return freshCleanReport(); },
  };
  for (const url of ['http://127.0.0.1', 'https://[::1]', 'https://localhost', 'https://printer.local', 'https://example.com']) {
    const report = await scanUrl(url, options);
    assert.equal(check(report, 'dns').status, 'unavailable', url);
    assert.equal(check(report, 'tls').status, url.startsWith('http:') ? 'warning' : 'unavailable', url);
  }
  assert.equal(lookupCount, 1, 'local names and IPs should not use DNS');
  assert.equal(tlsCount, 0);
  assert.equal(reputationCount, 0);
});

test('blocks a mixed DNS answer and pins a validated address for TLS', async () => {
  let contacted;
  const mixed = await scanUrl('https://example.com', {
    lookup: async () => [{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.2', family: 4 }],
    inspectTls: async (...args) => { contacted = args; return { ok: true }; },
  });
  assert.equal(check(mixed, 'dns').title, 'Protected address blocked');
  assert.equal(contacted, undefined);
  const valid = await scanUrl('https://example.com', {
    lookup: publicLookup,
    inspectTls: async (...args) => { contacted = args; return goodTls(); },
  });
  assert.deepEqual(contacted, ['example.com', '8.8.8.8']);
  assert.equal(check(valid, 'tls').status, 'pass');
});

test('reports limited coverage when reputation is not configured', async () => {
  const report = await scanUrl('https://example.com/path', baseOptions);
  assert.equal(report.verdict.level, 'limited');
  assert.equal(report.coverage.completed, 3);
  assert.equal(check(report, 'reputation').status, 'unavailable');
  assert.match(report.verdict.description, /does not mean the link is safe/i);
});

test('does not perform optional reputation lookup without explicit opt-in', async () => {
  let called = false;
  const report = await scanUrl('https://example.com/private?token=123', {
    ...baseOptions, apiKey: 'key', includeReputation: false,
    lookupReputation: async () => { called = true; return freshCleanReport(); },
  });
  assert.equal(called, false);
  assert.equal(check(report, 'reputation').title, 'Not requested');
  assert.equal(report.displayUrl, 'https://example.com/private?…');
});

test('redacts credentials and never shares credential-bearing URLs with VirusTotal', async () => {
  const parsed = parseInput('https://user:secret@example.com/path?token=private#fragment');
  assert.equal(displayUrl(parsed), 'https://redacted@example.com/path?…#…');
  let called = false;
  const report = await scanUrl(parsed.href, {
    ...baseOptions, apiKey: 'key', includeReputation: true,
    lookupReputation: async () => { called = true; return freshCleanReport(); },
  });
  assert.equal(called, false);
  assert.equal(check(report, 'reputation').title, 'Lookup skipped for privacy');
  assert.equal(check(report, 'structure').status, 'warning');
  assert(!JSON.stringify(report).includes('secret'));
  assert(!JSON.stringify(report).includes('private'));
});

test('only a fresh clean reputation report with all other checks can be clear', async () => {
  const report = await scanUrl('https://example.com', { ...baseOptions, apiKey: 'key', includeReputation: true, lookupReputation: freshCleanReport });
  assert.equal(report.verdict.level, 'clear');
  assert.equal(report.coverage.completed, 4);
  assert.match(report.verdict.description, /no scanner can guarantee/i);
  const old = await scanUrl('https://example.com', { ...baseOptions, apiKey: 'key', includeReputation: true, lookupReputation: async () => ({ stats: { harmless: 5 }, lastAnalysisDate: Math.floor(Date.now() / 1000) - 31 * 86400 }) });
  assert.equal(check(old, 'reputation').status, 'info');
  assert.equal(old.verdict.level, 'limited');
});

test('flags reported malicious engines, HTTP and invalid certificates without overstating certainty', async () => {
  const bad = await scanUrl('https://example.com', { ...baseOptions, apiKey: 'key', includeReputation: true, lookupReputation: freshMaliciousReport });
  assert.equal(bad.verdict.level, 'danger');
  assert.equal(check(bad, 'reputation').status, 'danger');
  const http = await scanUrl('http://example.com', baseOptions);
  assert.equal(check(http, 'tls').status, 'warning');
  assert.equal(http.verdict.level, 'warning');
  const invalidCert = await scanUrl('https://example.com', { lookup: publicLookup, inspectTls: async () => ({ ok: false, unavailable: false }) });
  assert.equal(check(invalidCert, 'tls').status, 'warning');
});

test('does not connect to non-standard ports', async () => {
  let called = false;
  const report = await scanUrl('https://example.com:8443', { lookup: publicLookup, inspectTls: async () => { called = true; } });
  assert.equal(called, false);
  assert.equal(check(report, 'tls').status, 'unavailable');
  assert.equal(check(report, 'structure').status, 'warning');
});

test('VirusTotal integration requests an existing report only and handles missing reports', async () => {
  const url = parseInput('https://example.com/a?x=1');
  let received;
  const result = await lookupVirusTotal(url, 'secret-key', async (address, options) => {
    received = { address, options };
    return { ok: true, json: async () => ({ data: { attributes: { last_analysis_stats: { malicious: 1 }, last_analysis_date: 100 } } }) };
  });
  assert.equal(received.address, `https://www.virustotal.com/api/v3/urls/${Buffer.from(url.href).toString('base64url')}`);
  assert.equal(received.options.method, 'GET');
  assert.equal(received.options.redirect, 'error');
  assert.equal(received.options.headers['x-apikey'], 'secret-key');
  assert.equal(result.stats.malicious, 1);
  const missing = await lookupVirusTotal(url, 'key', async () => ({ status: 404, ok: false }));
  assert.match(missing.unavailable, /No existing/);
});
