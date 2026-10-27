const MAX_HEADER_LENGTH = 32_000;
const extractAddress = (value) =>
  value
    ?.match(/[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@([a-z0-9.-]+\.[a-z]{2,})/i)?.[0]
    ?.toLowerCase() || '';
const domain = (address) => address.split('@').pop() || '';

/** Best-effort parsing of supplied headers; authentication claims are untrusted. */
export function analyzeEmailHeaders(input) {
  if (typeof input !== 'string' || !input.trim())
    throw new Error('Paste email headers to start the analysis.');
  if (input.length > MAX_HEADER_LENGTH)
    throw new Error('Headers must be under 32,000 characters.');
  const headerBlock = input.trim().split(/\r?\n\s*\r?\n/, 1)[0];
  const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, ' ');
  const headers = [];
  for (const line of unfolded.split(/\r?\n/)) {
    const match = line.match(/^([!-9;-~]+):\s*(.*)$/);
    if (match)
      headers.push({ name: match[1].toLowerCase(), value: match[2].trim() });
  }
  if (!headers.length)
    throw new Error(
      'No email header fields found. Paste the raw message headers, not the email body.',
    );
  const values = (name) =>
    headers
      .filter((header) => header.name === name)
      .map((header) => header.value);
  const from = extractAddress(values('from')[0]);
  const replyTo = extractAddress(values('reply-to')[0]);
  const returnPath = extractAddress(values('return-path')[0]);
  const authentication = values('authentication-results').join('; ');
  const authClaim = (method) =>
    authentication
      .match(
        new RegExp(
          `(?:^|[;\\s])${method}\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)\\b`,
          'i',
        ),
      )?.[1]
      ?.toLowerCase() || 'not found';
  const fromMismatch = Boolean(
    from && replyTo && domain(from) !== domain(replyTo),
  );
  const claims = ['spf', 'dkim', 'dmarc'].map((method) => ({
    method: method.toUpperCase(),
    value: authClaim(method),
  }));
  const checks = [
    {
      id: 'sender',
      label: 'From address',
      status: from ? 'present' : 'info',
      title: from || 'No sender address found',
      description:
        'The From field can be forged. Verify the sender independently.',
    },
    {
      id: 'reply',
      label: 'Reply-to address',
      status: fromMismatch ? 'warning' : 'info',
      title: replyTo || 'No Reply-To address found',
      description: fromMismatch
        ? 'The Reply-To and From domains differ. This can be legitimate but is worth checking.'
        : 'Reply-To differences are only a heuristic and do not prove phishing.',
    },
    {
      id: 'return',
      label: 'Return path',
      status: 'info',
      title: returnPath || 'No return path found',
      description:
        'This field describes a bounce address and can differ legitimately from the From address.',
    },
    {
      id: 'received',
      label: 'Received headers',
      status: 'info',
      title: `${values('received').length} hop header${values('received').length === 1 ? '' : 's'} found`,
      description:
        'Received headers can be forged; trust only headers added by infrastructure you control.',
    },
  ];
  return { claims, checks, fieldCount: headers.length };
}

export const SAMPLE_HEADERS = `From: "Example Billing" <billing@example.com>\nReply-To: support@example.net\nReturn-Path: <bounce@example.com>\nAuthentication-Results: mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=fail header.d=example.com; dmarc=fail header.from=example.com\nReceived: from mail.example.com by mx.example.org; Tue, 12 Mar 2024 10:30:00 +0000\nSubject: Please review your account`;
