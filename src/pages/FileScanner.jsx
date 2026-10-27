import { useEffect, useRef, useState } from 'react';
import {
  ArrowRight,
  Check,
  FileSearch,
  FileText,
  Fingerprint,
  LoaderCircle,
  RefreshCw,
  UploadCloud,
  X,
} from 'lucide-react';
import {
  ToolPage,
  PanelHeading,
  Notice,
  FindingList,
} from '../components/ToolPage.jsx';
import { analyzeFile, MAX_FILE_SIZE } from '../lib/fileAnalysis.js';
import { postJson } from '../lib/api.js';

const steps = [
  {
    title: 'Choose a file',
    copy: 'Select a file up to 10 MB. It stays in your browser.',
  },
  {
    title: 'Inspect the signals',
    copy: 'We calculate a fingerprint and check format and filename patterns.',
  },
  {
    title: 'Look closer',
    copy: 'Optionally check an existing reputation report by fingerprint.',
  },
];
const formatSize = (size) =>
  size < 1024
    ? `${size} B`
    : size < 1024 * 1024
      ? `${(size / 1024).toFixed(1)} KB`
      : `${(size / 1024 / 1024).toFixed(2)} MB`;

export default function FileScanner() {
  const [file, setFile] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [working, setWorking] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [provider, setProvider] = useState(false);
  const [includeReputation, setIncludeReputation] = useState(false);
  const inputRef = useRef(null);
  useEffect(() => {
    const c = new AbortController();
    fetch('/api/config', { signal: c.signal })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => setProvider(Boolean(data?.reputation?.configured)))
      .catch(() => {});
    return () => c.abort();
  }, []);
  function choose(next) {
    if (working) return;
    setError('');
    setReport(null);
    if (!next) return;
    if (next.size > MAX_FILE_SIZE) {
      setFile(null);
      setError('Choose a file of 10 MB or less.');
      return;
    }
    setFile(next);
  }
  function clear() {
    if (working) return;
    setFile(null);
    setReport(null);
    setError('');
    if (inputRef.current) inputRef.current.value = '';
  }
  async function inspect(event) {
    event.preventDefault();
    if (!file) {
      setError('Choose a file first.');
      return;
    }
    setWorking(true);
    setError('');
    setReport(null);
    try {
      const result = await analyzeFile(file);
      if (includeReputation && provider) {
        try {
          result.reputation = await postJson('/api/file-reputation', {
            sha256: result.sha256,
          });
        } catch (err) {
          result.reputation = {
            status: 'unavailable',
            title: 'Reputation lookup unavailable',
            description: err.message,
          };
        }
      }
      setReport(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setWorking(false);
    }
  }
  function useSample() {
    choose(
      new File(
        ['This is a harmless Cyber Ace sample file.\n'],
        'cyberace-sample.txt',
        { type: 'text/plain' },
      ),
    );
  }
  return (
    <ToolPage
      id="file"
      intro="A little more context before you open that unexpected download."
      visualTitle="A closer look at files."
      visualCopy="Inspect a fingerprint and format without uploading your file."
      steps={steps}
    >
      <div className="ca-panel">
        <PanelHeading
          eyebrow="FILE INSPECTION"
          title="What’s in your file?"
          copy="Choose a file and we’ll check a few useful signals."
          right={
            <span className="ca-panel-badge">
              <span /> PRIVATE BY DESIGN
            </span>
          }
        />
        <form onSubmit={inspect}>
          <div
            className={`ca-dropzone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              choose(e.dataTransfer.files?.[0]);
            }}
          >
            <input
              type="file"
              ref={inputRef}
              className="sr-only"
              id="file-input"
              aria-label="Choose a file"
              disabled={working}
              onChange={(e) => choose(e.target.files?.[0])}
            />
            <span className="ca-drop-icon">
              {file ? <FileText size={27} /> : <UploadCloud size={28} />}
            </span>
            {file ? (
              <>
                <strong>{file.name}</strong>
                <p>{formatSize(file.size)} · Ready for local inspection</p>
                <button
                  type="button"
                  className="ca-inline-button"
                  disabled={working}
                  onClick={clear}
                >
                  <X size={14} /> Remove file
                </button>
              </>
            ) : (
              <>
                <strong>
                  Drop a file here, or{' '}
                  <button
                    type="button"
                    className="ca-browse"
                    disabled={working}
                    onClick={() => inputRef.current?.click()}
                  >
                    browse files
                  </button>
                </strong>
                <p>Any file type · Up to 10 MB</p>
                <button
                  type="button"
                  className="ca-inline-button"
                  disabled={working}
                  onClick={useSample}
                >
                  Try a sample text file <ArrowRight size={14} />
                </button>
              </>
            )}
          </div>
          <div className="ca-option-row">
            <label>
              <input
                type="checkbox"
                checked={includeReputation}
                onChange={(e) => setIncludeReputation(e.target.checked)}
                disabled={!provider || working}
              />{' '}
              Check VirusTotal using the file’s SHA-256
            </label>
            <span className="ca-small-pill">
              {provider ? 'OPTIONAL' : 'NOT CONNECTED'}
            </span>
          </div>
          {includeReputation && provider && (
            <p className="ca-option-explain">
              Only the SHA-256 fingerprint is sent to VirusTotal. The file
              itself never leaves your browser.
            </p>
          )}
          {error && (
            <div className="ca-error" role="alert">
              {error}
            </div>
          )}
          <div className="ca-file-limit">
            <Notice tone="caution">
              This first-pass inspection is not an antivirus scan. A file can be
              malicious even if no pattern is found.
            </Notice>
          </div>
          <div className="ca-form-footer">
            <span>
              <ShieldIcon /> File contents stay on your device.
            </span>
            <button className="ca-action" type="submit" disabled={working}>
              {working ? (
                <>
                  <LoaderCircle className="spin" size={16} /> Inspecting
                </>
              ) : (
                <>
                  Inspect file <ArrowRight size={16} />
                </>
              )}
            </button>
          </div>
        </form>
      </div>
      {report && (
        <div
          className="ca-panel ca-result-panel"
          role="region"
          aria-live="polite"
        >
          <PanelHeading
            eyebrow="INSPECTION COMPLETE"
            title="Your file breakdown"
            copy={`${report.name} · ${formatSize(report.size)}`}
            right={
              <span className="ca-result-icon">
                <FileSearch size={21} />
              </span>
            }
          />
          <Notice tone="caution">
            This is not an antivirus scan. File signatures and patterns cannot
            determine whether a file is safe.
          </Notice>
          <div className="ca-hash-box">
            <span>
              <Fingerprint size={17} /> SHA-256 FINGERPRINT
            </span>
            <code>{report.sha256}</code>
          </div>
          <FindingList checks={report.checks} />
          {report.reputation ? (
            <div className={`ca-reputation ${report.reputation.status}`}>
              <div className="ca-finding-line">
                <strong>{report.reputation.title}</strong>
                <span className={`ca-status ${report.reputation.status}`}>
                  {report.reputation.status === 'danger'
                    ? 'FLAGGED'
                    : report.reputation.status === 'present'
                      ? 'CHECKED'
                      : 'LIMITED'}
                </span>
              </div>
              <p>{report.reputation.description}</p>
              {report.reputation.total != null && (
                <small>
                  {report.reputation.malicious} malicious ·{' '}
                  {report.reputation.suspicious} suspicious ·{' '}
                  {report.reputation.total} engines ·{' '}
                  {report.reputation.ageDays == null
                    ? 'date unavailable'
                    : `${report.reputation.ageDays} days old`}
                </small>
              )}
            </div>
          ) : (
            <div className="ca-reputation">
              <strong>Threat intelligence not checked</strong>
              <p>
                Enable the optional fingerprint lookup when a provider is
                configured. No malware detection was performed.
              </p>
            </div>
          )}
          <button type="button" className="ca-text-action" onClick={clear}>
            <RefreshCw size={15} /> Inspect another file
          </button>
        </div>
      )}
    </ToolPage>
  );
}
function ShieldIcon() {
  return <Check size={14} />;
}
