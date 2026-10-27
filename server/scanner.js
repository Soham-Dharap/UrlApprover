import dns from 'node:dns/promises';
import net from 'node:net';
import tls from 'node:tls';
import ipaddr from 'ipaddr.js';

const DNS_TIMEOUT_MS = 6000;
const TLS_TIMEOUT_MS = 7000;
const REPUTATION_TIMEOUT_MS = 7000;
const MAX_URL_LENGTH = 2048;

export class InputError extends Error {}

/** Parse without navigating to the URL. The URL object also normalizes unusual IP forms. */
export function parseInput(input) {
  if (typeof input !== 'string' || !input.trim()) {
    throw new InputError('Enter a URL to start a scan.');
  }
  const trimmed = input.trim();
  if (trimmed.length > MAX_URL_LENGTH) {
    throw new InputError(`Please use a URL shorter than ${MAX_URL_LENGTH + 1} characters.`);
  }
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new InputError('The URL contains unsupported control characters.');
  }
  if (/^(?:javascript|data|file|ftp|mailto|ws|wss):/i.test(trimmed)) {
    throw new InputError('Only HTTP and HTTPS links can be analyzed.');
  }
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new InputError('That doesn’t look like a valid URL. Try something like https://example.com.');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
    throw new InputError('Only HTTP and HTTPS links can be analyzed.');
  }
  return parsed;
}

export function hostnameOf(url) {
  return url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
}

/** Refuse local, special-use and transition addresses, including mapped IPv4. */
export function isPublicAddress(address) {
  try {
    const parsed = ipaddr.parse(address);
    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
      return parsed.toIPv4Address().range() === 'unicast';
    }
    // Most IPv6 space is not globally routable. Limit it to global unicast
    // 2000::/3 as well as excluding every special range known to ipaddr.js.
    if (parsed.kind() === 'ipv6') {
      return parsed.range() === 'unicast' && parsed.match(ipaddr.IPv6.parse('2000::'), 3);
    }
    return parsed.range() === 'unicast';
  } catch {
    return false;
  }
}

function isLocalHostname(hostname) {
  if (net.isIP(hostname)) return false;
  return !hostname.includes('.') || ['localhost', 'local', 'internal', 'lan', 'home.arpa', 'onion', 'test', 'invalid'].some(
    (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`),
  );
}

function timeout(promise, milliseconds, message) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), milliseconds);
    }),
  ]).finally(() => clearTimeout(timer));
}

export function structureCheck(url) {
  const hostname = hostnameOf(url);
  const concerns = [];
  if (url.username || url.password) {
    concerns.push('The link contains a username or password before the @ sign. Check the actual domain carefully.');
  }
  if (net.isIP(hostname)) {
    concerns.push('The link uses a numeric IP address instead of a domain name.');
  }
  if (hostname.split('.').some((part) => part.startsWith('xn--'))) {
    concerns.push('This is an internationalized domain. Look closely for look-alike characters.');
  }
  if (!net.isIP(hostname) && hostname.split('.').length > 5) {
    concerns.push('The domain has an unusually high number of subdomains.');
  }
  if (url.href.length > 180) {
    concerns.push('This is an unusually long link, which can make the destination harder to review.');
  }
  if (url.port && !((url.protocol === 'https:' && url.port === '443') || (url.protocol === 'http:' && url.port === '80'))) {
    concerns.push('The link uses a non-standard port. Connection checks are limited to standard ports.');
  }
  if (concerns.length) {
    return {
      id: 'structure', label: 'URL patterns', status: 'warning',
      title: `${concerns.length} pattern${concerns.length === 1 ? '' : 's'} to review`,
      description: 'These characteristics can be legitimate, but deserve a closer look.',
      details: concerns,
    };
  }
  return {
    id: 'structure', label: 'URL patterns', status: 'pass',
    title: 'No obvious tricks found',
    description: 'No common suspicious formatting patterns were found. This is not a phishing test.',
    details: [],
  };
}

/** Resolve once and inspect every answer before any connection. */
export async function resolvePublic(hostname, lookup = dns.lookup) {
  if (isLocalHostname(hostname)) {
    return { ok: false, blocked: true, reason: 'Local and internal hostnames are not scanned.' };
  }
  try {
    const addresses = net.isIP(hostname)
      ? [{ address: hostname, family: net.isIP(hostname) }]
      : await timeout(lookup(hostname, { all: true, verbatim: true }), DNS_TIMEOUT_MS, 'DNS timed out');
    if (!Array.isArray(addresses) || addresses.length === 0) {
      return { ok: false, reason: 'No DNS addresses were returned for this domain.' };
    }
    if (addresses.some((entry) => !isPublicAddress(entry.address))) {
      return { ok: false, blocked: true, reason: 'The domain resolves to a private, reserved, or special-use address. Connections to those addresses are blocked.' };
    }
    return { ok: true, addresses };
  } catch {
    return { ok: false, reason: 'The domain could not be resolved within the time limit. This can also be caused by network restrictions.' };
  }
}

function dnsCheck(resolution) {
  if (!resolution.ok) {
    return {
      id: 'dns', label: 'DNS resolution', status: 'unavailable',
      title: resolution.blocked ? 'Protected address blocked' : 'Could not resolve domain',
      description: resolution.reason, details: [],
    };
  }
  const count = resolution.addresses.length;
  return {
    id: 'dns', label: 'DNS resolution', status: 'pass',
    title: 'Domain resolved',
    description: `${count} public address${count === 1 ? '' : 'es'} returned. A DNS response does not establish trust.`,
    details: resolution.addresses.slice(0, 3).map((entry) => entry.address),
  };
}

/** Connect directly to a previously validated IP; never resolve again or follow redirects. */
export function inspectTls(hostname, address) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const options = {
      host: address,
      port: 443,
      rejectUnauthorized: false,
      // Passing the pinned IP as host prevents DNS rebinding after validation.
      ...(net.isIP(hostname) ? {} : { servername: hostname }),
    };
    const socket = tls.connect(options);
    socket.setTimeout(TLS_TIMEOUT_MS, () => finish({ ok: false, unavailable: true }));
    socket.once('error', () => finish({ ok: false, unavailable: true }));
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      const identityError = cert && Object.keys(cert).length ? tls.checkServerIdentity(hostname, cert) : new Error('No certificate');
      const authorized = socket.authorized && !identityError;
      finish({
        ok: authorized,
        unavailable: false,
        protocol: socket.getProtocol(),
        validTo: cert?.valid_to || null,
      });
    });
  });
}

async function tlsCheck(url, resolution, inspect = inspectTls) {
  if (url.protocol === 'http:') {
    return {
      id: 'tls', label: 'Connection security', status: 'warning', title: 'HTTP is not encrypted',
      description: 'Information sent over HTTP can be read or changed in transit. Avoid entering sensitive information.', details: [],
    };
  }
  if (url.port && url.port !== '443') {
    return {
      id: 'tls', label: 'Connection security', status: 'unavailable', title: 'Non-standard port not checked',
      description: 'For safety, connection checks only use the standard HTTPS port 443.', details: [],
    };
  }
  if (!resolution.ok) {
    return {
      id: 'tls', label: 'Connection security', status: 'unavailable', title: 'Certificate not checked',
      description: 'A public domain address is needed before a TLS connection can be checked.', details: [],
    };
  }
  try {
    const result = await timeout(inspect(hostnameOf(url), resolution.addresses[0].address), TLS_TIMEOUT_MS + 500, 'TLS timed out');
    if (result.unavailable) {
      return {
        id: 'tls', label: 'Connection security', status: 'unavailable', title: 'Connection could not be checked',
        description: 'The TLS handshake did not complete. The site or this scanner’s network may be unavailable.', details: [],
      };
    }
    if (!result.ok) {
      return {
        id: 'tls', label: 'Connection security', status: 'warning', title: 'Certificate could not be verified',
        description: 'The certificate presented to this scanner did not pass hostname or trust-chain verification. Network interception can also cause this.', details: [],
      };
    }
    return {
      id: 'tls', label: 'Connection security', status: 'pass', title: 'Valid TLS certificate',
      description: 'The certificate presented by the checked address matches the domain and has a trusted chain. Encryption alone does not mean a site is safe.',
      details: [result.protocol, result.validTo ? `Expires ${new Date(result.validTo).toISOString().slice(0, 10)}` : null].filter(Boolean),
    };
  } catch {
    return {
      id: 'tls', label: 'Connection security', status: 'unavailable', title: 'Connection could not be checked',
      description: 'The TLS handshake did not complete within the time limit.', details: [],
    };
  }
}

/** Only retrieves an existing report. It never submits a URL for analysis. */
export async function lookupVirusTotal(url, apiKey, fetcher = fetch) {
  const identifier = Buffer.from(url.href).toString('base64url');
  try {
    const response = await fetcher(`https://www.virustotal.com/api/v3/urls/${identifier}`, {
      method: 'GET',
      headers: { 'x-apikey': apiKey, accept: 'application/json' },
      signal: AbortSignal.timeout(REPUTATION_TIMEOUT_MS),
      redirect: 'error',
    });
    if (response.status === 404) return { unavailable: 'No existing VirusTotal report was found for this exact URL.' };
    if (response.status === 429) return { unavailable: 'The VirusTotal rate limit was reached. Try again later.' };
    if (response.status === 401 || response.status === 403) return { unavailable: 'VirusTotal rejected the configured API key.' };
    if (!response.ok) return { unavailable: 'VirusTotal could not provide a report right now.' };
    const json = await response.json();
    const stats = json?.data?.attributes?.last_analysis_stats;
    if (!stats) return { unavailable: 'The existing VirusTotal report has no analysis statistics.' };
    return { stats, lastAnalysisDate: json?.data?.attributes?.last_analysis_date || null };
  } catch {
    return { unavailable: 'The VirusTotal lookup could not be completed within the time limit.' };
  }
}

async function reputationCheck(url, resolution, { includeReputation, apiKey, lookup = lookupVirusTotal }) {
  const unavailable = (title, description) => ({ id: 'reputation', label: 'Threat intelligence', status: 'unavailable', title, description, details: [] });
  if (!apiKey) return unavailable('Not connected', 'Add a VirusTotal API key on the server to enable optional reputation checks.');
  if (!includeReputation) return unavailable('Not requested', 'The optional VirusTotal lookup was not selected for this scan.');
  if (url.username || url.password) return unavailable('Lookup skipped for privacy', 'Links containing credentials are never sent to VirusTotal.');
  if (!resolution.ok) return unavailable('Lookup skipped', 'Reputation lookups are skipped when a public address cannot be verified.');
  let result;
  try {
    result = await timeout(lookup(url, apiKey), REPUTATION_TIMEOUT_MS + 500, 'Reputation timed out');
  } catch {
    return unavailable('Lookup unavailable', 'The VirusTotal lookup did not complete within the time limit.');
  }
  if (result.unavailable) return unavailable('Report unavailable', result.unavailable);
  const malicious = Math.max(0, Number(result.stats?.malicious) || 0);
  const suspicious = Math.max(0, Number(result.stats?.suspicious) || 0);
  const harmless = Math.max(0, Number(result.stats?.harmless) || 0);
  const undetected = Math.max(0, Number(result.stats?.undetected) || 0);
  const total = malicious + suspicious + harmless + undetected;
  if (!total) return unavailable('Report unavailable', 'The existing report has no completed engine results.');
  const lastDate = Number(result.lastAnalysisDate) || null;
  const ageDays = lastDate ? Math.max(0, Math.floor((Date.now() / 1000 - lastDate) / 86400)) : null;
  const old = ageDays === null || ageDays > 30;
  const details = [`${malicious} malicious`, `${suspicious} suspicious`, `${total} engines`, ageDays === null ? 'Report date unavailable' : `Report age: ${ageDays} day${ageDays === 1 ? '' : 's'}`];
  if (malicious > 0) {
    return { id: 'reputation', label: 'Threat intelligence', status: 'danger', title: `${malicious} engine${malicious === 1 ? '' : 's'} flagged this URL`, description: 'An existing VirusTotal report contains malicious detections. Do not open the link until investigated.', details };
  }
  if (suspicious > 0) {
    return { id: 'reputation', label: 'Threat intelligence', status: 'warning', title: `${suspicious} engine${suspicious === 1 ? '' : 's'} marked it suspicious`, description: 'An existing VirusTotal report contains suspicious detections. Treat this link with caution.', details };
  }
  return {
    id: 'reputation', label: 'Threat intelligence', status: old ? 'info' : 'pass',
    title: old ? 'No detections in an older report' : 'No detections in existing report',
    description: old ? 'The existing VirusTotal report is over 30 days old or undated, so it may not reflect the link now.' : 'No engines marked this URL as malicious or suspicious in the existing report. This is not a guarantee of safety.',
    details,
  };
}

function verdictFor(checks) {
  if (checks.some((check) => check.status === 'danger')) {
    return { level: 'danger', title: 'Threats reported', description: 'A threat-intelligence engine flagged this link. Avoid opening it while you investigate.' };
  }
  if (checks.some((check) => check.status === 'warning')) {
    return { level: 'warning', title: 'A closer look is needed', description: 'We found one or more things worth reviewing. A warning does not necessarily mean the link is malicious.' };
  }
  if (checks.some((check) => check.status === 'unavailable' || check.status === 'info')) {
    return { level: 'limited', title: 'Analysis is limited', description: 'No obvious concerns were found in the checks completed, but some checks were unavailable. This does not mean the link is safe.' };
  }
  return { level: 'clear', title: 'No threats detected', description: 'The available checks found no obvious issues. No scanner can guarantee that a link is safe.' };
}

/** Redact credentials, query and fragment from the report; never save the input. */
export function displayUrl(url) {
  const safe = new URL(url.href);
  if (safe.username || safe.password) {
    safe.username = 'redacted';
    safe.password = '';
  }
  const hadSearch = Boolean(safe.search);
  const hadHash = Boolean(safe.hash);
  safe.search = '';
  safe.hash = '';
  return `${safe.href}${hadSearch ? '?…' : ''}${hadHash ? '#…' : ''}`;
}

export async function scanUrl(input, options = {}) {
  const started = Date.now();
  const url = parseInput(input);
  const hostname = hostnameOf(url);
  const structure = structureCheck(url);
  const resolution = await resolvePublic(hostname, options.lookup);
  const [connection, reputation] = await Promise.all([
    tlsCheck(url, resolution, options.inspectTls),
    reputationCheck(url, resolution, {
      includeReputation: options.includeReputation === true,
      apiKey: options.apiKey,
      lookup: options.lookupReputation,
    }),
  ]);
  const checks = [structure, dnsCheck(resolution), connection, reputation];
  return {
    displayUrl: displayUrl(url),
    hostname,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    verdict: verdictFor(checks),
    checks,
    coverage: { completed: checks.filter((check) => check.status !== 'unavailable').length, total: checks.length },
  };
}
