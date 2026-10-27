import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  ChevronRight,
  Info,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import SiteHeader from './SiteHeader.jsx';
import { toolById, tools } from '../catalog.js';

export function ToolPage({
  id,
  intro,
  visualTitle,
  visualCopy,
  steps,
  children,
}) {
  const tool = toolById(id);
  const Icon = tool.icon;
  const related = tools.filter((item) => item.id !== id).slice(0, 3);
  return (
    <div className={`ca-site ca-tool-site ca-theme-${tool.accent}`}>
      <SiteHeader />
      <main className="ca-tool-wrap">
        <div className="ca-breadcrumb">
          <Link to="/">HOME</Link>
          <ChevronRight size={13} />
          <Link to="/#tools">THE TOOLKIT</Link>
          <ChevronRight size={13} />
          <span>{tool.name.toUpperCase()}</span>
        </div>
        <section className="ca-tool-hero">
          <div className="ca-tool-hero-copy">
            <div className="ca-tool-eyebrow">
              <span /> TOOL {tool.number} / {tool.tag}
            </div>
            <h1>
              {tool.name}
              <span>.</span>
            </h1>
            <p>{intro}</p>
            <div className="ca-tool-tags">
              <span>
                <ShieldCheck size={14} /> BUILT FOR BETTER DECISIONS
              </span>
              <span>
                <Sparkles size={14} /> NO SIGN-UP NEEDED
              </span>
            </div>
          </div>
          <div className="ca-tool-hero-art">
            <span className="ca-art-orbit one" />
            <span className="ca-art-orbit two" />
            <div className="ca-art-icon">
              <Icon size={31} strokeWidth={1.5} />
            </div>
            <div>
              <small>YOUR CYBER ACE TOOLKIT</small>
              <strong>{visualTitle}</strong>
              <p>{visualCopy}</p>
            </div>
            <span className="ca-art-count">{tool.number} / 06</span>
          </div>
        </section>
        <div className="ca-tool-workspace">
          <div className="ca-work-main">{children}</div>
          <aside className="ca-work-aside">
            <div className="ca-guide-card">
              <div className="ca-guide-top">
                <span>
                  <Sparkles size={16} />
                </span>
                <small>A LITTLE GUIDANCE</small>
              </div>
              <h2>Here’s how it works.</h2>
              <p>Good security starts with knowing what to look for.</p>
              <div className="ca-guide-steps">
                {steps.map((step, i) => (
                  <div key={step.title}>
                    <span>0{i + 1}</span>
                    <div>
                      <strong>{step.title}</strong>
                      <p>{step.copy}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="ca-aside-note">
              <ShieldCheck size={18} />
              <div>
                <strong>Made to inform, not alarm.</strong>
                <p>
                  No tool can guarantee complete safety. Always use your
                  judgment.
                </p>
              </div>
            </div>
            <Link to="/#tools" className="ca-back-link">
              <ArrowLeft size={15} /> Back to all tools
            </Link>
          </aside>
        </div>
        <section className="ca-related">
          <div>
            <div className="ca-overline">KEEP EXPLORING</div>
            <h2>There’s more in your toolkit.</h2>
          </div>
          <div className="ca-related-links">
            {related.map((item) => (
              <Link key={item.id} to={item.path}>
                <item.icon size={16} />
                <span>{item.name}</span>
                <ArrowUpRight size={15} />
              </Link>
            ))}
          </div>
        </section>
      </main>
      <footer className="ca-footer">
        <div>
          <strong>
            cyberace<span>.</span>
          </strong>
          <p>Security, made a little more human.</p>
        </div>
        <span>
          © {new Date().getFullYear()} CYBER ACE · MADE FOR THOUGHTFUL CLICKS
        </span>
        <Link to="/#tools">
          EXPLORE ALL TOOLS <ArrowUpRight size={13} />
        </Link>
      </footer>
    </div>
  );
}

export function PanelHeading({ eyebrow, title, copy, right }) {
  return (
    <div className="ca-panel-heading">
      <div>
        <div className="ca-overline">{eyebrow}</div>
        <h2>{title}</h2>
        {copy && <p>{copy}</p>}
      </div>
      {right}
    </div>
  );
}

export function Notice({ children, tone = 'neutral' }) {
  return (
    <div className={`ca-notice ${tone}`}>
      <Info size={16} />
      <span>{children}</span>
    </div>
  );
}

export function FindingList({ checks }) {
  const labels = {
    present: 'PRESENT',
    pass: 'CHECKED',
    warning: 'REVIEW',
    danger: 'FLAGGED',
    missing: 'NOT FOUND',
    unavailable: 'UNAVAILABLE',
    info: 'INFO',
  };
  return (
    <div className="ca-findings">
      {checks.map((check) => (
        <div className="ca-finding" key={check.id}>
          <span className={`ca-finding-icon ${check.status}`}>
            {check.status === 'present' || check.status === 'pass' ? (
              <Check size={15} />
            ) : (
              <Info size={15} />
            )}
          </span>
          <div className="ca-finding-body">
            <div className="ca-finding-line">
              <span>{check.label}</span>
              <span className={`ca-status ${check.status}`}>
                {labels[check.status] || 'INFO'}
              </span>
            </div>
            <strong>{check.title}</strong>
            <p>{check.description}</p>
            {check.value && <code>{check.value}</code>}
            {check.details?.length > 0 && (
              <ul>
                {check.details.map((detail, index) => (
                  <li key={`${detail}-${index}`}>{detail}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
