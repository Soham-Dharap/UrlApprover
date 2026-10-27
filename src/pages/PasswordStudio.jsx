import { useMemo, useState } from 'react';
import zxcvbn from 'zxcvbn';
import {
  ArrowRight,
  Check,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { ToolPage, PanelHeading, Notice } from '../components/ToolPage.jsx';

const steps = [
  {
    title: 'Enter or generate',
    copy: 'Try a password or create a random one directly in your browser.',
  },
  {
    title: 'Review the estimate',
    copy: 'Explore common patterns and length-related feedback.',
  },
  {
    title: 'Keep it unique',
    copy: 'Use a password manager and a different password for every account.',
  },
];
const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
function randomPassword(length) {
  const groups = [
    'abcdefghijkmnopqrstuvwxyz',
    'ABCDEFGHJKLMNPQRSTUVWXYZ',
    '23456789',
    '!@#$%*-_+=?',
  ];
  const charset = groups.join('');
  const max = Math.floor(256 / charset.length) * charset.length;
  let password = '';
  do {
    password = '';
    while (password.length < length) {
      const bytes = crypto.getRandomValues(new Uint8Array(length * 2));
      for (const value of bytes)
        if (value < max && password.length < length)
          password += charset[value % charset.length];
    }
  } while (
    !groups.every((group) =>
      [...password].some((character) => group.includes(character)),
    )
  );
  return password;
}

export default function PasswordStudio() {
  const [value, setValue] = useState('');
  const [visible, setVisible] = useState(false);
  const [length, setLength] = useState(20);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const assessment = useMemo(() => (value ? zxcvbn(value) : null), [value]);
  const score = assessment?.score ?? -1;
  function generate() {
    try {
      setValue(randomPassword(length));
      setVisible(true);
      setError('');
      setCopied(false);
    } catch {
      setError('Secure random generation is unavailable in this browser.');
    }
  }
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError('Could not copy. Please copy the password manually.');
    }
  }
  return (
    <ToolPage
      id="password"
      intro="A stronger password is one small step toward a safer digital life."
      visualTitle="Your secret stays yours."
      visualCopy="Password analysis and generation happen only in your browser."
      steps={steps}
    >
      <div className="ca-panel">
        <PanelHeading
          eyebrow="PASSWORD CHECKUP"
          title="Let’s make it stronger."
          copy="Check a password’s estimated strength or generate a new one."
          right={
            <span className="ca-panel-badge">
              <span /> 100% IN YOUR BROWSER
            </span>
          }
        />
        <label className="ca-field-label" htmlFor="password-value">
          YOUR PASSWORD <span>NEVER SENT TO OUR SERVER</span>
        </label>
        <div className="ca-input-wrap password-input">
          <KeyRound size={19} />
          <input
            id="password-value"
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              setError('');
              setCopied(false);
            }}
            type={visible ? 'text' : 'password'}
            autoComplete="new-password"
            spellCheck="false"
            maxLength={128}
            placeholder="Type a password to see its strength..."
          />
          <button
            type="button"
            className="ca-icon-button"
            onClick={() => setVisible(!visible)}
            aria-label={visible ? 'Hide password' : 'Show password'}
          >
            {visible ? <EyeOff size={17} /> : <Eye size={17} />}
          </button>
          {value && (
            <button
              type="button"
              className="ca-icon-button"
              onClick={copy}
              aria-label="Copy password"
            >
              {copied ? <Check size={17} /> : <Copy size={17} />}
            </button>
          )}
        </div>
        <div className="ca-strength-head">
          <span>ESTIMATED STRENGTH</span>
          <strong className={`strength-${score}`}>
            {assessment ? labels[score] : 'Waiting for a password'}
          </strong>
        </div>
        <div
          className={`ca-strength-bars strength-${score}`}
          aria-label={
            assessment
              ? `Estimated strength: ${labels[score]}`
              : 'No password entered'
          }
        >
          {[0, 1, 2, 3, 4].map((index) => (
            <span key={index} className={index <= score ? 'filled' : ''} />
          ))}
        </div>
        {assessment ? (
          <div className="ca-password-feedback">
            <div>
              <span className="ca-result-icon">
                <ShieldCheck size={19} />
              </span>
              <div>
                <strong>
                  {assessment.feedback.warning ||
                    (score >= 3
                      ? 'Looking better.'
                      : 'There’s room to improve.')}
                </strong>
                <p>
                  {assessment.feedback.suggestions[0] ||
                    'Long, unique passwords and a password manager are a good combination.'}
                </p>
              </div>
            </div>
            <span>{value.length} CHARACTERS</span>
          </div>
        ) : (
          <div className="ca-password-empty">
            Use a long, unique password for every account. We’ll show practical
            feedback here.
          </div>
        )}
        {error && (
          <div className="ca-error" role="alert">
            {error}
          </div>
        )}
        <div className="ca-generator">
          <div>
            <span className="ca-generator-icon">
              <RefreshCw size={17} />
            </span>
            <div>
              <strong>Need a fresh password?</strong>
              <p>Generate one using secure browser randomness.</p>
            </div>
          </div>
          <div className="ca-generator-actions">
            <label className="sr-only" htmlFor="password-length">
              Password length
            </label>
            <select
              id="password-length"
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
            >
              {[16, 20, 24, 32].map((n) => (
                <option key={n} value={n}>
                  {n} characters
                </option>
              ))}
            </select>
            <button type="button" className="ca-action" onClick={generate}>
              Generate <ArrowRight size={16} />
            </button>
          </div>
        </div>
      </div>
      <Notice>
        Strength estimates are not guarantees. This tool does not check whether
        a password appeared in a data breach.
      </Notice>
    </ToolPage>
  );
}
