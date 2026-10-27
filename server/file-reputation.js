import { InputError } from './scanner.js';

/** Look up an existing file report by SHA-256. Never upload the file itself. */
export async function lookupFileReputation(
  input,
  { apiKey, fetcher = fetch } = {},
) {
  if (typeof input !== 'string' || !/^[a-f\d]{64}$/i.test(input))
    throw new InputError('Provide a valid SHA-256 fingerprint.');
  if (!apiKey)
    return {
      status: 'unavailable',
      title: 'Reputation not connected',
      description: 'A VirusTotal API key must be configured on the server.',
    };
  try {
    const response = await fetcher(
      `https://www.virustotal.com/api/v3/files/${input.toLowerCase()}`,
      {
        method: 'GET',
        headers: { 'x-apikey': apiKey, accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(7000),
      },
    );
    if (response.status === 404)
      return {
        status: 'unavailable',
        title: 'No existing report found',
        description:
          'VirusTotal has no existing report for this file fingerprint.',
      };
    if (response.status === 429)
      return {
        status: 'unavailable',
        title: 'Rate limit reached',
        description: 'VirusTotal is rate-limiting requests. Try again later.',
      };
    if (!response.ok)
      return {
        status: 'unavailable',
        title: 'Lookup unavailable',
        description:
          'VirusTotal could not provide a report. Check the configured key and try again later.',
      };
    const data = await response.json();
    const attributes = data?.data?.attributes;
    const stats = attributes?.last_analysis_stats;
    if (!stats)
      return {
        status: 'unavailable',
        title: 'No analysis available',
        description: 'The existing report has no engine statistics.',
      };
    const malicious = Math.max(0, Number(stats.malicious) || 0);
    const suspicious = Math.max(0, Number(stats.suspicious) || 0);
    const total =
      malicious +
      suspicious +
      Math.max(0, Number(stats.harmless) || 0) +
      Math.max(0, Number(stats.undetected) || 0);
    if (!total)
      return {
        status: 'unavailable',
        title: 'No completed engine results',
        description: 'The existing report has no completed engine results.',
      };
    const timestamp = Number(attributes.last_analysis_date) || null;
    const ageDays = timestamp
      ? Math.max(0, Math.floor((Date.now() / 1000 - timestamp) / 86400))
      : null;
    const old = ageDays === null || ageDays > 30;
    const status = malicious
      ? 'danger'
      : suspicious
        ? 'warning'
        : old
          ? 'info'
          : 'present';
    const title = malicious
      ? `${malicious} engine${malicious === 1 ? '' : 's'} flagged this file`
      : suspicious
        ? `${suspicious} engine${suspicious === 1 ? '' : 's'} marked it suspicious`
        : old
          ? 'No detections in an older report'
          : 'No detections in existing report';
    return {
      status,
      title,
      description:
        'An existing report is a signal, not proof that the file is safe. VirusTotal receives the SHA-256 fingerprint only.',
      malicious,
      suspicious,
      total,
      ageDays,
    };
  } catch {
    return {
      status: 'unavailable',
      title: 'Lookup unavailable',
      description:
        'The VirusTotal lookup could not be completed within the time limit.',
    };
  }
}
