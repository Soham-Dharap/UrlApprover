import { useState } from 'react';
import { ArrowRight, Braces, MailSearch, Sparkles, Trash2 } from 'lucide-react';
import {
  ToolPage,
  PanelHeading,
  Notice,
  FindingList,
} from '../components/ToolPage.jsx';
import { analyzeEmailHeaders, SAMPLE_HEADERS } from '../lib/emailAnalysis.js';

const steps = [
  {
    title: 'Get the raw headers',
    copy: 'In your email client, find “show original” or “view message source”.',
  },
  {
    title: 'Paste the headers',
    copy: 'Only paste headers—not the message body or private content.',
  },
  {
    title: 'Review the clues',
    copy: 'Authentication fields are claims and are not independently verified.',
  },
];
export default function EmailHeaders() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  function run(e) {
    e.preventDefault();
    try {
      setResult(analyzeEmailHeaders(input));
      setError('');
    } catch (err) {
      setError(err.message);
      setResult(null);
    }
  }
  function clear() {
    setInput('');
    setResult(null);
    setError('');
  }
  return (
    <ToolPage
      id="email"
      intro="Turn a wall of email headers into clues you can actually understand."
      visualTitle="Find the story in the headers."
      visualCopy="Analyze the details without sending your email anywhere."
      steps={steps}
    >
      <div className="ca-panel">
        <PanelHeading
          eyebrow="MESSAGE INSPECTION"
          title="Let’s look at the headers."
          copy="Paste the raw headers from your email client below."
          right={
            <span className="ca-panel-badge">
              <span /> PROCESSED LOCALLY
            </span>
          }
        />
        <form onSubmit={run}>
          <div className="ca-textarea-label">
            <label className="ca-field-label" htmlFor="email-headers">
              RAW EMAIL HEADERS
            </label>
            <button
              type="button"
              onClick={() => {
                setInput(SAMPLE_HEADERS);
                setResult(null);
                setError('');
              }}
            >
              <Sparkles size={14} /> Use an example
            </button>
          </div>
          <textarea
            id="email-headers"
            className="ca-textarea"
            value={input}
            maxLength={32000}
            onChange={(e) => {
              setInput(e.target.value);
              setError('');
            }}
            placeholder={
              'From: sender@example.com\nAuthentication-Results: ...\nReceived: ...'
            }
            spellCheck="false"
          />
          <div className="ca-character-count">
            {input.length.toLocaleString()} / 32,000 CHARACTERS
          </div>
          {error && (
            <div className="ca-error" role="alert">
              {error}
            </div>
          )}
          <div className="ca-form-footer">
            <button
              type="button"
              className="ca-clear"
              onClick={clear}
              disabled={!input}
            >
              <Trash2 size={15} /> Clear
            </button>
            <button className="ca-action" type="submit">
              Analyze headers <ArrowRight size={16} />
            </button>
          </div>
        </form>
      </div>
      {result && (
        <div className="ca-panel ca-result-panel" aria-live="polite">
          <PanelHeading
            eyebrow="HEADER BREAKDOWN"
            title="A closer look."
            copy={`${result.fieldCount} header fields parsed locally.`}
            right={
              <span className="ca-result-icon">
                <MailSearch size={21} />
              </span>
            }
          />
          <Notice tone="caution">
            Authentication results below are unverified claims from the pasted
            text. Only trust results added by your receiving mail provider.
          </Notice>
          <div className="ca-auth-grid">
            {result.claims.map((claim) => (
              <div key={claim.method}>
                <span>{claim.method}</span>
                <strong
                  className={
                    claim.value === 'pass'
                      ? 'claim-pass'
                      : ['fail', 'softfail'].includes(claim.value)
                        ? 'claim-fail'
                        : ''
                  }
                >
                  {claim.value}
                </strong>
                <small>HEADER CLAIM</small>
              </div>
            ))}
          </div>
          <FindingList checks={result.checks} />
        </div>
      )}
    </ToolPage>
  );
}
