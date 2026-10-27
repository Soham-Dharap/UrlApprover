import { ArrowUpRight, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';

export function CyberLogo() {
  return (
    <Link className="ca-brand" to="/" aria-label="Cyber Ace home">
      <span className="ca-brand-icon">
        <ShieldCheck size={21} strokeWidth={2} />
      </span>
      <span>
        cyber<span className="ca-brand-accent">ace</span>
        <i>.</i>
        <small>SECURITY, MADE SIMPLE</small>
      </span>
    </Link>
  );
}

export default function SiteHeader() {
  return (
    <header className="ca-header">
      <div className="ca-header-inner">
        <CyberLogo />
        <nav className="ca-nav" aria-label="Site navigation">
          <Link to="/">Home</Link>
          <Link to="/#tools">Our toolkit</Link>
          <Link to="/#approach">Our approach</Link>
          <Link to="/#faq">FAQ</Link>
        </nav>
        <Link className="ca-nav-button" to="/#tools">
          Explore tools <ArrowUpRight size={15} />
        </Link>
      </div>
    </header>
  );
}
