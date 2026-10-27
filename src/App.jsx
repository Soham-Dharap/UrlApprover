import { useEffect, useRef, useState } from 'react';
import {
  Activity, ArrowRight, ArrowUpRight, BookOpen, Check, ChevronRight,
  CircleAlert, CircleHelp, Clock3, Copy, FileSearch, Fingerprint, Globe2, History, Info, Link2,
  LoaderCircle, LockKeyhole, Radar, ScanLine, Search, Shield, ShieldAlert,
  ShieldCheck, Sparkles, Trash2, X,
} from 'lucide-react';

const HISTORY_KEY = 'linkscope-history-v1';
const EXAMPLE_URL = 'https://github.com';

function readHistory() {
  try {
    const saved = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    return Array.isArray(saved) ? saved.slice(0, 6) : [];
  } catch {
    return [];
  }
}

function saveHistory(items) {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items)); } catch { /* Storage can be disabled. */ }
}

function Logo({ compact = false }) {
  return (
    <a className={`brand ${compact ? 'brand-compact' : ''}`} href="#scanner" aria-label="Linkscope home">
      <span className="brand-mark"><ShieldCheck size={21} strokeWidth={1.9} /></span>
      <span className="brand-word">linkscope<span className="brand-period">.</span><small>URL INTELLIGENCE</small></span>
    </a>
  );
}

function Sidebar({ historyCount }) {
  return (
    <aside className="sidebar">
      <Logo />
      <div className="side-label">YOUR WORKSPACE</div>
      <nav className="side-nav" aria-label="Main navigation">
        <a className="side-link active" href="#scanner"><ScanLine size={18} /><span>URL scanner</span><ChevronRight size={15} className="nav-arrow" /></a>
        <a className="side-link" href="#history"><History size={18} /><span>Recent scans</span>{historyCount > 0 && <span className="nav-count">{historyCount}</span>}</a>
      </nav>
      <div className="side-label second-label">THE DETAILS</div>
      <nav className="side-nav" aria-label="Information">
        <a className="side-link" href="#how-it-works"><BookOpen size={18} /><span>How it works</span></a>
        <a className="side-link" href="#safety-notes"><CircleHelp size={18} /><span>Safety notes</span></a>
      </nav>
      <div className="side-bottom">
        <div className="side-note">
          <div className="side-note-icon"><Shield size={17} /></div>
          <strong>A little caution<br />goes a long way.</strong>
          <p>More context for the moments you’re not quite sure.</p>
          <a href="#how-it-works">Get to know Linkscope <ArrowUpRight size={13} /></a>
        </div>
        <div className="side-footer"><span className="side-footer-dot" /> MADE FOR SAFER CLICKS <span>✳</span></div>
      </div>
    </aside>
  );
}

function Header({ serverState }) {
  return (
    <header className="topbar">
      <div className="topbar-left"><div className="mobile-brand"><Logo compact /></div><div className="breadcrumbs"><span>WORKSPACE</span><ChevronRight size={13} /><strong>URL SCANNER</strong></div></div>
      <div className="topbar-right">
        <span className="topbar-note"><LockKeyhole size={14} /> NO SIGN-IN REQUIRED</span>
        <span className="topbar-divider" />
        <span className={`server-status ${serverState}`}><span />{serverState === 'online' ? 'Scanner online' : serverState === 'offline' ? 'Scanner offline' : 'Connecting'}</span>
      </div>
    </header>
  );
}

const features = [
  { icon: Link2, title: 'URL patterns', copy: 'Spot unusual link formatting.', index: '01' },
  { icon: Globe2, title: 'Domain & DNS', copy: 'Check public domain resolution.', index: '02' },
  { icon: LockKeyhole, title: 'Connection', copy: 'Review HTTPS & certificate trust.', index: '03' },
  { icon: Fingerprint, title: 'Threat intelligence', copy: 'Optional reputation lookup.', index: '04' },
];

function FeatureStrip() {
  return (
    <section className="features-section" aria-labelledby="features-title">
      <div className="section-heading features-heading">
        <div><div className="eyebrow">A CLOSER LOOK</div><h2 id="features-title">A little more insight, all in one place.</h2></div>
        <a className="text-link" href="#how-it-works">How it works <ArrowUpRight size={15} /></a>
      </div>
      <div className="feature-grid">
        {features.map(({ icon: Icon, title, copy, index }) => (
          <div className="feature-card" key={title}>
            <div className="feature-card-top"><span className="feature-icon"><Icon size={19} strokeWidth={1.7} /></span><span className="feature-index">{index} / 04</span></div>
            <strong>{title}</strong><p>{copy}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function ScanHero({ input, setInput, inputRef, onSubmit, scanning, error, setError, config, includeReputation, setIncludeReputation, onExample }) {
  const configured = config?.reputation?.configured === true;
  return (
    <section className="hero" aria-labelledby="hero-title">
      <div className="hero-background" />
      <div className="hero-content">
        <div className="hero-kicker"><span className="hero-kicker-icon"><Sparkles size={12} /></span> YOUR FIRST STEP TO A SAFER CLICK</div>
        <h2 id="hero-title">Not sure about a link?<br /><span>Let’s take a look.</span></h2>
        <p className="hero-description">Get a clearer picture of suspicious links before you open them.</p>
        <form className="scan-form" onSubmit={onSubmit}>
          <label className="sr-only" htmlFor="url-input">URL to analyze</label>
          <div className={`url-field ${error ? 'has-error' : ''}`}>
            <Link2 className="input-icon" size={20} aria-hidden="true" />
            <input ref={inputRef} id="url-input" type="text" inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck="false" maxLength={2048} placeholder="Paste a URL or suspicious link here..." value={input} onChange={(event) => { setInput(event.target.value); if (error) setError(''); }} disabled={scanning} aria-describedby={error ? 'scan-error' : undefined} />
            {input && !scanning && <button className="input-clear" type="button" aria-label="Clear URL" onClick={() => { setInput(''); setError(''); inputRef.current?.focus(); }}><X size={15} /></button>}
            <button className="scan-button" type="submit" disabled={scanning}>
              {scanning ? <><LoaderCircle className="spin" size={17} /> Analyzing</> : <>Analyze URL <ArrowUpRight size={17} /></>}
            </button>
          </div>
          {error && <div className="form-error" id="scan-error" role="alert"><CircleAlert size={14} /> {error}</div>}
          <div className="hero-form-bottom">
            <span><Clock3 size={14} /> Designed for ~30 second scans</span><span className="hero-bullet">•</span><span><ShieldCheck size={14} /> No page opened in your browser</span>
          </div>
          <div className="reputation-option">
            <label className={configured ? '' : 'option-disabled'}>
              <input type="checkbox" checked={includeReputation} onChange={(event) => setIncludeReputation(event.target.checked)} disabled={!configured || scanning} />
              <span>Include VirusTotal reputation lookup</span>
            </label>
            <span className={`provider-state ${configured ? 'available' : ''}`}>{configured ? 'OPTIONAL' : 'NOT CONNECTED'}</span>
            {configured && includeReputation && <span className="provider-disclosure">The full URL will be shared with VirusTotal.</span>}
          </div>
        </form>
      </div>
      <div className="hero-art-label" aria-hidden="true"><span className="art-line" /><span>MORE CONTEXT.<br />MORE CONFIDENCE.</span></div>
      <div className="hero-example"><span>NEED A PLACE TO START?</span><button type="button" onClick={onExample} disabled={scanning}>Try an example <ArrowUpRight size={13} /></button></div>
    </section>
  );
}

function EmptyReport({ onExample, scanning }) {
  if (scanning) {
    return (
      <div className="empty-report loading-report" role="status">
        <div className="empty-illustration"><span className="empty-illustration-inner"><LoaderCircle size={24} className="spin" /></span></div>
        <h3>Taking a closer look...</h3>
        <p>Checking the available signals. This can take a few moments.</p>
        <span className="waiting-label"><span className="pulse-dot" /> ANALYSIS IN PROGRESS</span>
      </div>
    );
  }
  return (
    <div className="empty-report">
      <div className="empty-illustration"><span className="empty-illustration-inner"><FileSearch size={23} strokeWidth={1.55} /></span><span className="illustration-spark">✳</span></div>
      <h3>Your report will appear here.</h3>
      <p>Paste a link above and we’ll help you take<br className="desktop-break" /> a closer look at what we find.</p>
      <button type="button" className="subtle-button" onClick={onExample}>Or try an example <ArrowRight size={14} /></button>
    </div>
  );
}

const statusText = { pass: 'CHECKED', warning: 'REVIEW', danger: 'FLAGGED', unavailable: 'NOT CHECKED', info: 'OLDER REPORT' };
const checkIcons = { structure: Link2, dns: Globe2, tls: LockKeyhole, reputation: Fingerprint };

function timeOf(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Just now';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(date);
}

function Report({ report, onCopy, copyState }) {
  const { verdict } = report;
  const VerdictIcon = verdict.level === 'danger' ? ShieldAlert : verdict.level === 'warning' ? CircleAlert : verdict.level === 'limited' ? Shield : ShieldCheck;
  return (
    <div className="report-card" aria-live="polite">
      <div className={`report-summary ${verdict.level}`}>
        <span className="verdict-icon"><VerdictIcon size={23} strokeWidth={1.8} /></span>
        <div className="verdict-copy"><div className="report-overline">SCAN COMPLETE</div><h3>{verdict.title}</h3><p>{verdict.description}</p></div>
        <button type="button" className="copy-button" onClick={onCopy} title="Copy report summary">{copyState === 'success' ? <Check size={15} /> : <Copy size={15} />} <span>{copyState === 'success' ? 'Copied' : copyState === 'error' ? 'Copy failed' : 'Copy'}</span></button>
      </div>
      <div className="scanned-target">
        <span className="target-icon"><Globe2 size={17} /></span>
        <div className="target-url"><span>ANALYZED LINK</span><strong title={report.displayUrl}>{report.displayUrl}</strong></div>
        <div className="target-date"><span>COMPLETED</span><strong>{timeOf(report.scannedAt)}</strong></div>
      </div>
      <div className="breakdown-heading"><span>CHECK BREAKDOWN</span><span>{report.coverage.completed} OF {report.coverage.total} CHECKS COMPLETED</span></div>
      <div className="result-checks">
        {report.checks.map((check) => {
          const Icon = checkIcons[check.id] || Activity;
          return (
            <div className="result-check" key={check.id}>
              <span className="result-check-icon"><Icon size={17} /></span>
              <div className="result-check-main"><div className="result-check-top"><span>{check.label}</span><span className={`check-pill ${check.status}`}><i />{statusText[check.status] || 'INFO'}</span></div><strong>{check.title}</strong><p>{check.description}</p>{check.details?.length > 0 && <ul>{check.details.map((detail) => <li key={detail}>{detail}</li>)}</ul>}</div>
            </div>
          );
        })}
      </div>
      <div className="report-disclaimer"><Info size={15} /><span>This is a first-pass assessment, not a guarantee of safety. Pages, downloads, and redirects are not inspected.</span></div>
    </div>
  );
}

function HistoryPanel({ history, onClear }) {
  return (
    <section className="history-section" id="history" aria-labelledby="history-title">
      <div className="section-heading compact-heading"><div><div className="eyebrow">YOUR ACTIVITY</div><h2 id="history-title">Recent scans</h2></div>{history.length > 0 && <button className="clear-history" type="button" onClick={onClear} aria-label="Clear scan history"><Trash2 size={14} /> Clear</button>}</div>
      <div className={`history-card ${history.length ? 'has-history' : ''}`}>
        {history.length === 0 ? <div className="history-empty"><span className="history-empty-icon"><History size={20} strokeWidth={1.6} /></span><strong>Nothing here yet</strong><p>Your recently scanned domains<br />will show up here.</p></div> : <ul className="history-list">{history.map((item, index) => <li key={`${item.scannedAt}-${index}`}><span className={`history-status ${item.level}`}><span /></span><div><strong title={item.hostname}>{item.hostname}</strong><small>{item.title}</small></div><time>{timeOf(item.scannedAt)}</time></li>)}</ul>}
        <div className="history-foot"><LockKeyhole size={14} /> Hostnames are saved only in this browser.</div>
      </div>
    </section>
  );
}

function HowItWorks() {
  return (
    <section className="how-section" id="how-it-works" aria-labelledby="how-title">
      <div className="how-header"><div><div className="eyebrow">GOOD TO KNOW</div><h2 id="how-title">A little context goes a long way.</h2><p>Linkscope is a first step, not a crystal ball. Here’s what happens when you run a scan.</p></div><span className="how-header-icon"><Radar size={25} strokeWidth={1.5} /></span></div>
      <div className="how-grid">
        <div><span>01</span><h3>We inspect the link</h3><p>We look for unusual URL patterns, resolve public DNS addresses, and check the TLS certificate when possible.</p></div>
        <div><span>02</span><h3>You choose reputation</h3><p>With a configured API key and your opt-in, the full URL is sent to VirusTotal to retrieve an existing report. No new report is submitted.</p></div>
        <div id="safety-notes"><span>03</span><h3>You make the call</h3><p>We don’t open pages, follow redirects, download files, or execute malware. A clean result never guarantees a link is safe.</p></div>
      </div>
      <div className="how-foot"><Info size={15} /><span>Never paste sensitive or private links. Some checks may be unavailable due to network restrictions or missing configuration.</span></div>
    </section>
  );
}

export default function App() {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const [scanning, setScanning] = useState(false);
  const [report, setReport] = useState(null);
  const [history, setHistory] = useState(readHistory);
  const [config, setConfig] = useState(null);
  const [serverState, setServerState] = useState('connecting');
  const [includeReputation, setIncludeReputation] = useState(false);
  const [copyState, setCopyState] = useState('');
  const inputRef = useRef(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/config', { signal: controller.signal }).then((response) => {
      if (!response.ok) throw new Error('Unavailable');
      return response.json();
    }).then((data) => { setConfig(data); setServerState('online'); }).catch((err) => { if (err.name !== 'AbortError') setServerState('offline'); });
    return () => controller.abort();
  }, []);

  async function runScan(value) {
    const candidate = value.trim();
    if (!candidate) { setError('Paste a URL to start your scan.'); inputRef.current?.focus(); return; }
    if (scanning) return;
    setInput(candidate);
    setError('');
    setScanning(true);
    setReport(null);
    setCopyState('');
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 30_000);
    try {
      const response = await fetch('/api/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: candidate, includeReputation }), signal: controller.signal,
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Something went wrong. Please try again.');
      setReport(result);
      setHistory((previous) => {
        const next = [{ hostname: result.hostname, level: result.verdict.level, title: result.verdict.title, scannedAt: result.scannedAt }, ...previous].slice(0, 6);
        saveHistory(next);
        return next;
      });
      setServerState('online');
      window.setTimeout(() => document.getElementById('results')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
    } catch (err) {
      setError(err.name === 'AbortError' ? 'The scan timed out. Please try again.' : err.message === 'Failed to fetch' ? 'Could not reach the scanner. Please try again.' : err.message);
      inputRef.current?.focus();
    } finally {
      window.clearTimeout(timer);
      setScanning(false);
    }
  }

  function clearHistory() { setHistory([]); saveHistory([]); }
  async function copyReport() {
    if (!report) return;
    const summary = [`Linkscope scan: ${report.displayUrl}`, `Result: ${report.verdict.title}`, report.verdict.description, '', ...report.checks.map((check) => `${check.label}: ${check.title} — ${check.description}`), '', 'This is not a guarantee of safety.'].join('\n');
    try {
      let success = false;
      if (navigator.clipboard && window.isSecureContext) {
        try { await navigator.clipboard.writeText(summary); success = true; } catch { /* Try the fallback below. */ }
      }
      if (!success) {
        const textarea = document.createElement('textarea');
        textarea.value = summary;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        success = document.execCommand('copy');
        textarea.remove();
      }
      setCopyState(success ? 'success' : 'error');
    } catch { setCopyState('error'); }
    window.setTimeout(() => setCopyState(''), 2500);
  }

  const onExample = () => runScan(EXAMPLE_URL);
  return (
    <div className="app-shell">
      <Sidebar historyCount={history.length} />
      <main className="main-area" id="scanner">
        <Header serverState={serverState} />
        <div className="page-content">
          <div className="page-intro"><div><div className="eyebrow intro-eyebrow"><span /> URL SECURITY, MADE SIMPLE</div><h1>Look before you link<span>.</span></h1><p>A little peace of mind for the links you’re unsure about.</p></div><div className="intro-side-note"><span><ShieldCheck size={17} /></span><div>GOOD TO BE CAUTIOUS<small>Thoughtful clicks start here.</small></div></div></div>
          <ScanHero input={input} setInput={setInput} inputRef={inputRef} onSubmit={(event) => { event.preventDefault(); runScan(input); }} scanning={scanning} error={error} setError={setError} config={config} includeReputation={includeReputation} setIncludeReputation={setIncludeReputation} onExample={onExample} />
          <FeatureStrip />
          <div className="workspace-grid">
            <section className="results-section" id="results" aria-labelledby="results-title">
              <div className="section-heading compact-heading"><div><div className="eyebrow">THE BREAKDOWN</div><h2 id="results-title">Latest analysis</h2></div><span className={`section-state ${scanning ? 'working' : report ? 'complete' : ''}`}><span />{scanning ? 'ANALYZING' : report ? 'SCAN COMPLETE' : 'AWAITING URL'}</span></div>
              {report && !scanning ? <Report report={report} onCopy={copyReport} copyState={copyState} /> : <EmptyReport onExample={onExample} scanning={scanning} />}
            </section>
            <HistoryPanel history={history} onClear={clearHistory} />
          </div>
          <HowItWorks />
          <footer className="page-footer"><span>© {new Date().getFullYear()} LINKSCOPE <span className="footer-dot">✳</span> BUILT FOR MORE THOUGHTFUL CLICKS.</span><a href="#scanner">BACK TO TOP <ArrowUpRight size={13} /></a></footer>
        </div>
      </main>
    </div>
  );
}
