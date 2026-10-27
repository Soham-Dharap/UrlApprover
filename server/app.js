import express from 'express';
import { InputError, scanUrl } from './scanner.js';
import { auditDomain } from './domain-audit.js';
import { auditSecurityHeaders } from './header-audit.js';
import { lookupFileReputation } from './file-reputation.js';

const RATE_WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 15;
const MAX_ACTIVE_SCANS = 8;

/** Scanner dependencies can be substituted in tests without making network calls. */
export function createApp({
  scanner = scanUrl,
  domainScanner = auditDomain,
  headerScanner = auditSecurityHeaders,
  fileReputationScanner = lookupFileReputation,
  apiKey = process.env.VIRUSTOTAL_API_KEY?.trim() || '',
  trustProxyHops = Number(process.env.TRUST_PROXY_HOPS || 0),
} = {}) {
  if (
    !Number.isInteger(trustProxyHops) ||
    trustProxyHops < 0 ||
    trustProxyHops > 3
  ) {
    throw new Error('TRUST_PROXY_HOPS must be an integer from 0 to 3.');
  }
  const app = express();
  app.set('trust proxy', trustProxyHops);
  const requestsByClient = new Map();
  let activeScans = 0;

  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });
  app.use('/api', (_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(express.json({ limit: '8kb', strict: true }));

  app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/api/config', (_req, res) =>
    res.json({
      reputation: { provider: 'VirusTotal', configured: Boolean(apiKey) },
    }),
  );

  function requireJson(req, res, next) {
    if (!req.is('application/json'))
      return res
        .status(415)
        .json({ error: 'Use an application/json request.' });
    return next();
  }
  function rateLimit(req, res, next) {
    const client = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const recent = (requestsByClient.get(client) || []).filter(
      (timestamp) => now - timestamp < RATE_WINDOW_MS,
    );
    if (recent.length >= MAX_PER_WINDOW) {
      res.setHeader('Retry-After', '60');
      return res
        .status(429)
        .json({ error: 'Too many scans. Please wait a minute and try again.' });
    }
    recent.push(now);
    requestsByClient.delete(client);
    requestsByClient.set(client, recent);
    if (requestsByClient.size > 10_000)
      requestsByClient.delete(requestsByClient.keys().next().value);
    return next();
  }
  const runSafely = (handler) => async (req, res) => {
    if (activeScans >= MAX_ACTIVE_SCANS)
      return res
        .status(503)
        .json({ error: 'The scanner is busy. Please try again in a moment.' });
    activeScans += 1;
    try {
      return res.json(await handler(req));
    } catch (error) {
      if (error instanceof InputError)
        return res.status(400).json({ error: error.message });
      return res
        .status(500)
        .json({ error: 'The scan could not be completed. Please try again.' });
    } finally {
      activeScans -= 1;
    }
  };

  app.post(
    '/api/scan',
    requireJson,
    rateLimit,
    runSafely(async (req) => {
      if (
        !req.body ||
        typeof req.body.url !== 'string' ||
        (req.body.includeReputation !== undefined &&
          typeof req.body.includeReputation !== 'boolean')
      ) {
        throw new InputError(
          'Provide a URL and an optional reputation setting.',
        );
      }
      return scanner(req.body.url, {
        includeReputation: req.body.includeReputation === true,
        apiKey,
      });
    }),
  );
  app.post(
    '/api/dns-audit',
    requireJson,
    rateLimit,
    runSafely(async (req) => domainScanner(req.body?.domain)),
  );
  app.post(
    '/api/security-headers',
    requireJson,
    rateLimit,
    runSafely(async (req) => headerScanner(req.body?.url)),
  );
  app.post(
    '/api/file-reputation',
    requireJson,
    rateLimit,
    runSafely(async (req) =>
      fileReputationScanner(req.body?.sha256, { apiKey }),
    ),
  );

  app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found.' }));
  app.use((error, _req, res, next) => {
    if (error.type === 'entity.too.large')
      return res.status(413).json({ error: 'Request is too large.' });
    if (error instanceof SyntaxError && error.status === 400)
      return res.status(400).json({ error: 'Invalid JSON request.' });
    return next(error);
  });
  return app;
}
