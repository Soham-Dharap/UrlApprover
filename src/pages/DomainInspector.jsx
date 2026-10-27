import { useState } from 'react';
import { ArrowRight, Globe2, LoaderCircle, Search } from 'lucide-react';
import {
  ToolPage,
  PanelHeading,
  Notice,
  FindingList,
} from '../components/ToolPage.jsx';
import { postJson } from '../lib/api.js';

const steps = [
  {
    title: 'Enter a domain',
    copy: 'Use a public domain name without a path or private address.',
  },
  {
    title: 'Query public DNS',
    copy: 'We look for address, mail, nameserver, SPF, and DMARC records.',
  },
  {
    title: 'Review the details',
    copy: 'Missing or unavailable records need context; this is not a full audit.',
  },
];
export default function DomainInspector() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [working, setWorking] = useState(false);
  async function run(e, example) {
    e?.preventDefault();
    const domain = (example || input).trim();
    if (!domain) {
      setError('Enter a domain to inspect.');
      return;
    }
    setInput(domain);
    setError('');
    setResult(null);
    setWorking(true);
    try {
      setResult(await postJson('/api/dns-audit', { domain }));
    } catch (err) {
      setError(err.message);
    } finally {
      setWorking(false);
    }
  }
  return (
    <ToolPage
      id="dns"
      intro="Get to know the public DNS and email-security records behind a domain."
      visualTitle="Understand your domain."
      visualCopy="See the records that connect a domain to the world."
      steps={steps}
    >
      <div className="ca-panel">
        <PanelHeading
          eyebrow="DOMAIN INTELLIGENCE"
          title="Explore a domain."
          copy="We’ll query public DNS records for a little more context."
          right={
            <span className="ca-panel-badge">
              <span /> PUBLIC DNS ONLY
            </span>
          }
        />
        <form onSubmit={run}>
          <label className="ca-field-label" htmlFor="domain-input">
            DOMAIN NAME
          </label>
          <div className="ca-inline-form">
            <div className="ca-input-wrap">
              <Globe2 size={19} />
              <input
                id="domain-input"
                value={input}
                onChange={(e) => {
                  setInput(e.target.value);
                  setError('');
                }}
                placeholder="example.com"
                autoCapitalize="none"
                autoComplete="off"
                spellCheck="false"
                disabled={working}
              />
            </div>
            <button className="ca-action" type="submit" disabled={working}>
              {working ? (
                <>
                  <LoaderCircle size={16} className="spin" /> Checking
                </>
              ) : (
                <>
                  Inspect domain <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>
          <div className="ca-example-line">
            Need an example?{' '}
            <button
              type="button"
              disabled={working}
              onClick={() => run(null, 'github.com')}
            >
              Try github.com <ArrowRight size={13} />
            </button>
          </div>
          {error && (
            <div className="ca-error" role="alert">
              {error}
            </div>
          )}
        </form>
        <Notice>
          Public DNS records may change. Presence alone does not prove that a
          domain or its email is safe.
        </Notice>
      </div>
      {result && (
        <div className="ca-panel ca-result-panel" aria-live="polite">
          <PanelHeading
            eyebrow="DNS LOOKUP COMPLETE"
            title={result.domain}
            copy="Public DNS results and email-policy signals."
            right={
              <span className="ca-result-icon">
                <Search size={21} />
              </span>
            }
          />
          <FindingList checks={result.checks} />
          <div className="ca-report-foot">
            DKIM, DNSSEC, record correctness, and domain ownership are not
            verified by this tool.
          </div>
        </div>
      )}
    </ToolPage>
  );
}
