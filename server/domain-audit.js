import dns from 'node:dns/promises';
import net from 'node:net';
import {
  InputError,
  hostnameOf,
  isLocalHostname,
  parseInput,
} from './scanner.js';

const DNS_TIMEOUT_MS = 6000;

/** Only public-looking DNS names are queried; no arbitrary URL is fetched. */
export function parseDomain(input) {
  if (typeof input !== 'string' || !input.trim())
    throw new InputError('Enter a domain to inspect.');
  const url = parseInput(input.trim());
  const host = hostnameOf(url);
  if (
    url.username ||
    url.password ||
    url.port ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new InputError(
      'Enter a domain only, without a path, port, or credentials.',
    );
  }
  if (
    net.isIP(host) ||
    isLocalHostname(host) ||
    host.length > 253 ||
    !host
      .split('.')
      .every((label) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i.test(label))
  ) {
    throw new InputError(
      'Enter a public domain name such as example.com. Local and private names are not queried.',
    );
  }
  return host;
}

async function lookup(fn, name) {
  let timer;
  try {
    const records = await Promise.race([
      fn(name),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), DNS_TIMEOUT_MS);
      }),
    ]);
    return { status: records.length ? 'present' : 'missing', records };
  } catch (error) {
    const missing = ['ENODATA', 'ENOTFOUND', 'ENONAME', 'NXDOMAIN'].includes(
      error.code,
    );
    return { status: missing ? 'missing' : 'unavailable', records: [] };
  } finally {
    clearTimeout(timer);
  }
}

const textRecords = (result) =>
  result.records.map((parts) =>
    Array.isArray(parts) ? parts.join('') : String(parts),
  );
const shorten = (text) => String(text).slice(0, 350);

export async function auditDomain(input, { resolver = dns } = {}) {
  const domain = parseDomain(input);
  const [a, aaaa, mx, ns, txt, dmarcTxt] = await Promise.all([
    lookup((name) => resolver.resolve4(name), domain),
    lookup((name) => resolver.resolve6(name), domain),
    lookup((name) => resolver.resolveMx(name), domain),
    lookup((name) => resolver.resolveNs(name), domain),
    lookup((name) => resolver.resolveTxt(name), domain),
    lookup((name) => resolver.resolveTxt(name), `_dmarc.${domain}`),
  ]);
  const addresses = [...a.records, ...aaaa.records].slice(0, 8);
  const addressStatus = addresses.length
    ? 'present'
    : a.status === 'unavailable' || aaaa.status === 'unavailable'
      ? 'unavailable'
      : 'missing';
  const spf = textRecords(txt).filter((text) => /^v=spf1(?:\s|$)/i.test(text));
  const dmarc = textRecords(dmarcTxt).filter((text) =>
    /^v=DMARC1(?:\s*;|\s*$)/i.test(text),
  );
  const dmarcPolicy = dmarc[0]
    ?.match(/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b/i)?.[1]
    ?.toLowerCase();
  const dmarcPercent = Number(
    dmarc[0]?.match(/(?:^|;)\s*pct\s*=\s*(\d+)/i)?.[1] ?? 100,
  );
  let dmarcStatus = dmarcTxt.status;
  if (
    dmarc.length > 1 ||
    (dmarc.length &&
      (!dmarcPolicy || dmarcPolicy === 'none' || dmarcPercent < 100))
  )
    dmarcStatus = 'warning';
  else if (dmarc.length) dmarcStatus = 'present';
  else if (dmarcTxt.status === 'present') dmarcStatus = 'missing';
  let spfStatus = txt.status;
  if (spf.length > 1) spfStatus = 'warning';
  else if (spf.length) spfStatus = 'present';
  else if (txt.status === 'present') spfStatus = 'missing';
  const checks = [
    {
      id: 'addresses',
      label: 'Address records',
      status: addressStatus,
      title: addresses.length
        ? `${addresses.length} address record${addresses.length === 1 ? '' : 's'} found`
        : addressStatus === 'unavailable'
          ? 'Address lookup unavailable'
          : 'No address records found',
      description:
        'A and AAAA records point a name to IP addresses. They do not prove a domain is trustworthy.',
      details: addresses.map(shorten),
    },
    {
      id: 'mx',
      label: 'Mail servers',
      status: mx.status,
      title:
        mx.status === 'present'
          ? 'MX records found'
          : mx.status === 'missing'
            ? 'No MX records found'
            : 'MX lookup unavailable',
      description: 'MX records identify where incoming mail is delivered.',
      details: mx.records
        .slice(0, 8)
        .map((record) => `${record.priority}  ${shorten(record.exchange)}`),
    },
    {
      id: 'spf',
      label: 'SPF policy',
      status: spfStatus,
      title:
        spf.length > 1
          ? 'Multiple SPF records found'
          : spf.length
            ? 'SPF record found'
            : spfStatus === 'missing'
              ? 'No SPF record found'
              : 'SPF lookup unavailable',
      description:
        'SPF describes authorized mail senders; presence alone does not validate the policy.',
      details: spf.slice(0, 3).map(shorten),
    },
    {
      id: 'dmarc',
      label: 'DMARC policy',
      status: dmarcStatus,
      title:
        dmarc.length > 1
          ? 'Multiple DMARC records found'
          : dmarc.length
            ? `DMARC policy: ${dmarcPolicy || 'unrecognized'}`
            : dmarcStatus === 'missing'
              ? 'No DMARC record found'
              : 'DMARC lookup unavailable',
      description:
        dmarcPolicy === 'none'
          ? 'The domain is monitoring mail rather than requesting quarantine or rejection.'
          : dmarcPercent < 100
            ? `The policy applies to ${dmarcPercent}% of mail; review its scope.`
            : 'DMARC helps receivers handle messages that fail SPF or DKIM. This is not a full policy validation.',
      details: dmarc.slice(0, 3).map(shorten),
    },
    {
      id: 'ns',
      label: 'Name servers',
      status: ns.status,
      title:
        ns.status === 'present'
          ? 'Name servers found'
          : ns.status === 'missing'
            ? 'No NS records found'
            : 'NS lookup unavailable',
      description: 'Name servers publish DNS data for this domain.',
      details: ns.records.slice(0, 8).map(shorten),
    },
  ];
  return { domain, checkedAt: new Date().toISOString(), checks };
}
