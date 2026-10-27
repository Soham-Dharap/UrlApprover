import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { auditDomain, parseDomain } from '../server/domain-audit.js';
import {
  analyzeSecurityHeaders,
  auditSecurityHeaders,
} from '../server/header-audit.js';
import { lookupFileReputation } from '../server/file-reputation.js';
import {
  analyzeFile,
  calculateEntropy,
  identifySignature,
  MAX_FILE_SIZE,
} from '../src/lib/fileAnalysis.js';
import {
  analyzeEmailHeaders,
  SAMPLE_HEADERS,
} from '../src/lib/emailAnalysis.js';
import { InputError } from '../server/scanner.js';

const missing = () => {
  throw Object.assign(new Error('no data'), { code: 'ENODATA' });
};
const publicLookup = async () => [{ address: '8.8.8.8', family: 4 }];

test('file analysis hashes selected bytes locally and identifies mismatched signatures', async () => {
  const file = new File(
    [new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
    'document.pdf',
  );
  const result = await analyzeFile(file);
  assert.equal(
    result.sha256,
    createHash('sha256')
      .update(Buffer.from(await file.arrayBuffer()))
      .digest('hex'),
  );
  assert.equal(result.signature.name, 'PNG image');
  assert.equal(
    result.checks.find((check) => check.id === 'extension').status,
    'warning',
  );
  assert(!JSON.stringify(result).includes('File is safe'));
  assert.equal(identifySignature(new Uint8Array([0x4d, 0x5a])).key, 'pe');
  assert.equal(calculateEntropy(new Uint8Array([0, 0, 0, 0])), 0);
});

test('file checks flag deceptive filenames and enforce their size limit', async () => {
  const result = await analyzeFile(
    new File([new Uint8Array([0x4d, 0x5a, 0, 1])], 'invoice.pdf.exe'),
  );
  assert.equal(
    result.checks.find((check) => check.id === 'extension').status,
    'warning',
  );
  assert.equal(
    result.checks.find((check) => check.id === 'active').status,
    'warning',
  );
  await assert.rejects(() => analyzeFile({ size: MAX_FILE_SIZE + 1 }), /10 MB/);
});

test('email headers are parsed as unverified claims and body content is ignored', () => {
  const report = analyzeEmailHeaders(
    `${SAMPLE_HEADERS}\n\nAuthentication-Results: spoofed; dmarc=pass`,
  );
  assert.deepEqual(
    report.claims.map((claim) => claim.value),
    ['pass', 'fail', 'fail'],
  );
  assert.equal(
    report.checks.find((check) => check.id === 'reply').status,
    'warning',
  );
  assert.equal(
    report.checks.find((check) => check.id === 'received').title,
    '1 hop header found',
  );
  assert.throws(
    () => analyzeEmailHeaders('This is not a header'),
    /No email header/,
  );
});

test('domain parser rejects private names, addresses, paths, and credentials', () => {
  assert.equal(parseDomain('https://github.com'), 'github.com');
  for (const value of [
    'localhost',
    'printer.local',
    '127.0.0.1',
    'github.com/private',
    'https://user:pass@github.com',
    'github.com:8443',
  ]) {
    assert.throws(() => parseDomain(value), InputError, value);
  }
});

test('domain audit parses DNS records without overstating SPF and DMARC', async () => {
  const resolver = {
    resolve4: async () => ['8.8.8.8'],
    resolve6: missing,
    resolveMx: async () => [{ priority: 10, exchange: 'mail.example.com' }],
    resolveNs: async () => ['ns1.example.com'],
    resolveTxt: async (name) =>
      name.startsWith('_dmarc.')
        ? [['v=DMARC1; p=none']]
        : [['v=spf1 ', '-all']],
  };
  const report = await auditDomain('example.com', { resolver });
  assert.equal(
    report.checks.find((check) => check.id === 'addresses').status,
    'present',
  );
  assert.equal(
    report.checks.find((check) => check.id === 'spf').status,
    'present',
  );
  assert.equal(
    report.checks.find((check) => check.id === 'dmarc').status,
    'warning',
  );
  assert.match(
    report.checks.find((check) => check.id === 'dmarc').description,
    /monitoring/,
  );
});

test('DNS outages are unavailable, not reported as missing records', async () => {
  const unavailable = () => {
    throw Object.assign(new Error('failed'), { code: 'ESERVFAIL' });
  };
  const resolver = {
    resolve4: unavailable,
    resolve6: missing,
    resolveMx: unavailable,
    resolveNs: missing,
    resolveTxt: unavailable,
  };
  const report = await auditDomain('example.com', { resolver });
  assert.equal(
    report.checks.find((check) => check.id === 'addresses').status,
    'unavailable',
  );
  assert.equal(
    report.checks.find((check) => check.id === 'spf').status,
    'unavailable',
  );
  assert.equal(
    report.checks.find((check) => check.id === 'dmarc').status,
    'unavailable',
  );
});

test('security-header checker blocks private and mixed DNS answers before connecting', async () => {
  let contacted = false;
  const requestHeaders = async () => {
    contacted = true;
    return { statusCode: 200, headers: {} };
  };
  const privateResult = await auditSecurityHeaders('http://127.0.0.1', {
    requestHeaders,
  });
  assert.equal(privateResult.available, false);
  const mixedResult = await auditSecurityHeaders('https://example.com', {
    lookup: async () => [{ address: '8.8.8.8' }, { address: '127.0.0.1' }],
    requestHeaders,
  });
  assert.equal(mixedResult.available, false);
  assert.equal(contacted, false);
  await assert.rejects(
    () =>
      auditSecurityHeaders('https://example.com:8443', {
        lookup: publicLookup,
        requestHeaders,
      }),
    InputError,
  );
  await assert.rejects(
    () =>
      auditSecurityHeaders('https://user:pass@example.com', {
        lookup: publicLookup,
        requestHeaders,
      }),
    InputError,
  );
});

test('security-header checker pins the resolved address, strips paths, and does not follow redirects', async () => {
  let received;
  const report = await auditSecurityHeaders(
    'https://example.com/private?token=secret#fragment',
    {
      lookup: publicLookup,
      requestHeaders: async (url, ip) => {
        received = { url: url.href, ip };
        return {
          statusCode: 302,
          headers: {
            'content-security-policy':
              "default-src 'self'; frame-ancestors 'none'",
            'x-content-type-options': 'nosniff',
          },
        };
      },
    },
  );
  assert.deepEqual(received, { url: 'https://example.com/', ip: '8.8.8.8' });
  assert.equal(report.redirect, true);
  assert.equal(
    report.checks.find((check) => check.id === 'frame').status,
    'present',
  );
  assert.equal(
    report.checks.find((check) => check.id === 'content-type').status,
    'present',
  );
  assert(!JSON.stringify(report).includes('secret'));
  assert.equal(
    analyzeSecurityHeaders(
      { 'strict-transport-security': 'max-age=31536000' },
      false,
    ).find((check) => check.id === 'hsts').status,
    'info',
  );
});

test('file reputation sends only a validated SHA-256 to the configured provider', async () => {
  const hash = createHash('sha256').update('sample').digest('hex');
  let requested;
  const result = await lookupFileReputation(hash, {
    apiKey: 'key',
    fetcher: async (url, options) => {
      requested = { url, options };
      return {
        ok: true,
        json: async () => ({
          data: {
            attributes: {
              last_analysis_stats: { malicious: 1, undetected: 12 },
              last_analysis_date: Math.floor(Date.now() / 1000),
            },
          },
        }),
      };
    },
  });
  assert.equal(
    requested.url,
    `https://www.virustotal.com/api/v3/files/${hash}`,
  );
  assert.equal(requested.options.method, 'GET');
  assert.equal(requested.options.body, undefined);
  assert.equal(result.status, 'danger');
  await assert.rejects(
    () => lookupFileReputation('bad', { apiKey: 'key' }),
    InputError,
  );
  assert.equal((await lookupFileReputation(hash, {})).status, 'unavailable');
});

test('file reputation handles missing, stale and unreachable reports honestly', async () => {
  const hash = createHash('sha256').update('sample').digest('hex');
  const missingReport = await lookupFileReputation(hash, {
    apiKey: 'key',
    fetcher: async () => ({ status: 404, ok: false }),
  });
  assert.equal(missingReport.status, 'unavailable');
  assert.match(missingReport.title, /No existing/);
  const staleReport = await lookupFileReputation(hash, {
    apiKey: 'key',
    fetcher: async () => ({
      ok: true,
      json: async () => ({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 0, undetected: 12 },
            last_analysis_date: 1,
          },
        },
      }),
    }),
  });
  assert.equal(staleReport.status, 'info');
  assert.match(staleReport.title, /older/);
  const unavailable = await lookupFileReputation(hash, {
    apiKey: 'key',
    fetcher: async () => {
      throw new Error('offline');
    },
  });
  assert.equal(unavailable.status, 'unavailable');
});
