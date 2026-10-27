import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import {
  InputError,
  hostnameOf,
  parseInput,
  resolvePublic,
} from './scanner.js';

const REQUEST_TIMEOUT_MS = 7000;

/** Fetch only response headers from the site root, pinned to the verified IP. */
export function requestRootHeaders(url, address) {
  return new Promise((resolve, reject) => {
    const host = hostnameOf(url);
    const transport = url.protocol === 'https:' ? https : http;
    let settled = false;
    let timer;
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(value);
    };
    const req = transport.request(
      {
        host: address,
        port: url.protocol === 'https:' ? 443 : 80,
        method: 'HEAD',
        path: '/',
        agent: false,
        maxHeaderSize: 16 * 1024,
        headers: {
          Host: url.host,
          'User-Agent': 'CyberAce-Security-Headers/1.0',
          Accept: '*/*',
        },
        // Preserve hostname validation and SNI while never re-resolving the host.
        ...(url.protocol === 'https:' && !net.isIP(host)
          ? { servername: host }
          : {}),
        rejectUnauthorized: true,
      },
      (response) => {
        response.resume();
        finish(null, {
          statusCode: response.statusCode,
          headers: response.headers,
        });
      },
    );
    timer = setTimeout(() => {
      req.destroy();
      finish(new Error('timeout'));
    }, REQUEST_TIMEOUT_MS);
    req.once('error', (error) => finish(error));
    req.end();
  });
}

const valueOf = (headers, key) => {
  const value = headers[key];
  return (Array.isArray(value) ? value.join(', ') : String(value || '')).slice(
    0,
    300,
  );
};

export function analyzeSecurityHeaders(headers, httpsConnection) {
  const csp = valueOf(headers, 'content-security-policy');
  const hsts = valueOf(headers, 'strict-transport-security');
  const frame = valueOf(headers, 'x-frame-options');
  const contentType = valueOf(headers, 'x-content-type-options');
  const referrer = valueOf(headers, 'referrer-policy');
  const permissions = valueOf(headers, 'permissions-policy');
  const hasFrameAncestors = /(?:^|;)\s*frame-ancestors\b/i.test(csp);
  const item = (id, label, status, value, description) => ({
    id,
    label,
    status,
    title:
      status === 'present'
        ? 'Header present'
        : status === 'missing'
          ? 'Header not found'
          : status === 'warning'
            ? 'Review header value'
            : 'Not evaluated',
    value: value || '',
    description,
  });
  return [
    item(
      'csp',
      'Content-Security-Policy',
      csp ? 'present' : 'missing',
      csp,
      'Controls which resources a browser may load. Presence alone does not mean the policy is effective.',
    ),
    item(
      'hsts',
      'Strict-Transport-Security',
      !httpsConnection ? 'info' : hsts ? 'present' : 'missing',
      hsts,
      httpsConnection
        ? 'Instructs browsers to use HTTPS for future visits. Review max-age and scope.'
        : 'HSTS is only evaluated on HTTPS responses.',
    ),
    item(
      'frame',
      'Clickjacking protection',
      frame || hasFrameAncestors ? 'present' : 'missing',
      frame || (hasFrameAncestors ? 'CSP frame-ancestors directive' : ''),
      'X-Frame-Options or CSP frame-ancestors can restrict framing.',
    ),
    item(
      'content-type',
      'X-Content-Type-Options',
      /^nosniff$/i.test(contentType.trim())
        ? 'present'
        : contentType
          ? 'warning'
          : 'missing',
      contentType,
      'The nosniff value helps prevent MIME-type sniffing.',
    ),
    item(
      'referrer',
      'Referrer-Policy',
      referrer ? 'present' : 'missing',
      referrer,
      'Controls how much referrer information the browser sends.',
    ),
    item(
      'permissions',
      'Permissions-Policy',
      permissions ? 'present' : 'missing',
      permissions,
      'Controls access to selected browser features.',
    ),
  ];
}

export async function auditSecurityHeaders(
  input,
  { lookup, requestHeaders = requestRootHeaders } = {},
) {
  const url = parseInput(input);
  if (url.username || url.password || url.port)
    throw new InputError(
      'Use an HTTP(S) site without credentials or a non-standard port.',
    );
  const hostname = hostnameOf(url);
  const target = `${url.origin}/`;
  const resolution = await resolvePublic(hostname, lookup);
  if (!resolution.ok)
    return { target, available: false, message: resolution.reason, checks: [] };
  try {
    // Discard path, query, and fragment before handing the target to networking.
    const rootUrl = new URL(target);
    const response = await requestHeaders(
      rootUrl,
      resolution.addresses[0].address,
    );
    return {
      target,
      available: true,
      statusCode: response.statusCode,
      redirect: response.statusCode >= 300 && response.statusCode < 400,
      checks: analyzeSecurityHeaders(
        response.headers || {},
        url.protocol === 'https:',
      ),
      checkedAt: new Date().toISOString(),
    };
  } catch {
    return {
      target,
      available: false,
      message:
        'The site could not be reached with a verified connection. The site or scanner network may be unavailable, or its certificate could not be verified.',
      checks: [],
    };
  }
}
