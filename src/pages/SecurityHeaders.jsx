import { useState } from 'react';
import { ArrowRight, Globe2, LoaderCircle, ShieldCheck } from 'lucide-react';
import {
  ToolPage,
  PanelHeading,
  Notice,
  FindingList,
} from '../components/ToolPage.jsx';
import { postJson } from '../lib/api.js';

const steps = [
  {
    title: 'Enter a website',
    copy: 'Choose a public HTTP or HTTPS site on a standard port.',
  },
  {
    title: 'Inspect the response',
    copy: 'We send a HEAD request to the site root without following redirects.',
  },
  {
    title: 'Review the headers',
    copy: 'We show presence, not a full security or configuration assessment.',
  },
];
export default function SecurityHeaders() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [working, setWorking] = useState(false);
  async function run(e, example) {
    e?.preventDefault();
    const url = (example || input).trim();
    if (!url) {
      setError('Enter a website to check.');
      return;
    }
    setInput(url);
    setError('');
    setResult(null);
    setWorking(true);
    try {
      setResult(await postJson('/api/security-headers', { url }));
    } catch (err) {
      setError(err.message);
    } finally {
      setWorking(false);
    }
  }
  return (
    <ToolPage
      id="headers"
      intro="See the browser-facing security headers a website sends back."
      visualTitle="Behind the response."
      visualCopy="A simple first look at a site’s defensive headers."
      steps={steps}
    >
      <div className="ca-panel">
        <PanelHeading
          eyebrow="WEBSITE HARDENING"
          title="Check a website."
          copy="We’ll inspect response headers from its root page only."
          right={
            <span className="ca-panel-badge">
              <span /> NO REDIRECTS FOLLOWED
            </span>
          }
        />
        <form onSubmit={run}>
          <label className="ca-field-label" htmlFor="headers-input">
            WEBSITE URL
          </label>
          <div className="ca-inline-form">
            <div className="ca-input-wrap">
              <Globe2 size={19} />
              <input
                id="headers-input"
                value={input}
                onChange={(e) => {
                  setInput(e.target.value);
                  setError('');
                }}
                placeholder="https://example.com"
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
                  Check headers <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>
          <div className="ca-example-line">
            Need an example?{' '}
            <button
              type="button"
              disabled={working}
              onClick={() => run(null, 'https://github.com')}
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
          Only the root response is checked. Paths, redirects, page content, and
          vulnerabilities are not inspected.
        </Notice>
      </div>
      {result && (
        <div className="ca-panel ca-result-panel" aria-live="polite">
          <PanelHeading
            eyebrow="RESPONSE INSPECTION"
            title={
              result.available
                ? 'Your header breakdown'
                : 'The check is unavailable'
            }
            copy={result.target}
            right={
              <span className="ca-result-icon">
                <ShieldCheck size={21} />
              </span>
            }
          />
          {result.available ? (
            <>
              <div className="ca-response-bar">
                <span>HTTP RESPONSE</span>
                <strong>{result.statusCode}</strong>
                <small>
                  {result.redirect
                    ? 'Redirects are not followed'
                    : 'Root HEAD response'}
                </small>
              </div>
              <Notice>
                Header presence is not proof of correct configuration or website
                safety.
              </Notice>
              <FindingList checks={result.checks} />
            </>
          ) : (
            <Notice tone="caution">{result.message}</Notice>
          )}
        </div>
      )}
    </ToolPage>
  );
}
