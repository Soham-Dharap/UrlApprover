import { useState } from 'react';
import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  CircleHelp,
  Globe2,
  LockKeyhole,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import SiteHeader from '../components/SiteHeader.jsx';
import { tools } from '../catalog.js';

const questions = [
  [
    'Is Cyber Ace free to use?',
    'The tools in this prototype are available without an account. Some optional threat-intelligence features require a server-configured VirusTotal API key.',
  ],
  [
    'Can a tool guarantee that a link or file is safe?',
    'No. These tools offer first-pass signals, not guarantees. The file tool does not execute files or run antivirus locally; optional reputation uses an existing VirusTotal report.',
  ],
  [
    'What happens to my password or selected file?',
    'The password and file inspection tools process those inputs in your browser. If you opt in to a file reputation lookup, only its SHA-256 fingerprint is sent to the server and VirusTotal.',
  ],
  [
    'Who is Cyber Ace for?',
    'For curious people, security learners, and anyone who wants more context before making decisions online.',
  ],
];

export default function Home() {
  const [filter, setFilter] = useState('all');
  const visible =
    filter === 'all' ? tools : tools.filter((tool) => tool.group === filter);
  return (
    <div className="ca-site" id="top">
      <SiteHeader />
      <main>
        <section className="ca-home-hero">
          <div className="ca-home-hero-bg" />
          <div className="ca-home-hero-content">
            <div className="ca-hero-kicker">
              <span>
                <Sparkles size={13} />
              </span>{' '}
              A LITTLE MORE CONFIDENCE, ONLINE
            </div>
            <h1>
              A safer digital world
              <br />
              starts with <em>you.</em>
            </h1>
            <p>
              Meet your all-in-one security toolkit. Simple, thoughtful tools to
              help you make smarter decisions online.
            </p>
            <div className="ca-hero-actions">
              <a className="ca-button primary" href="#tools">
                Explore the toolkit <ArrowUpRight size={18} />
              </a>
              <a className="ca-hero-secondary" href="#approach">
                <span>
                  <ArrowDown size={14} />
                </span>{' '}
                Get to know us
              </a>
            </div>
            <div className="ca-hero-bottom">
              <span>
                <ShieldCheck size={15} /> BUILT FOR EVERYONE
              </span>
              <i />{' '}
              <span>
                <LockKeyhole size={15} /> NO SIGN-UP REQUIRED
              </span>
            </div>
          </div>
          <div className="ca-hero-art-tag">
            <span>
              DESIGNED FOR
              <br />
              <strong>A SAFER EVERYDAY.</strong>
            </span>
            <span>✳</span>
          </div>
          <div className="ca-hero-corner">
            <span>
              THE CYBER ACE
              <br />
              COLLECTION
            </span>
            <b>01 — 06</b>
          </div>
        </section>
        <section className="ca-proof-strip" aria-label="Platform overview">
          <div>
            <span className="ca-proof-icon">
              <ShieldCheck size={18} />
            </span>
            <strong>Good security starts here.</strong>
            <small>A little context goes a long way.</small>
          </div>
          <div>
            <strong>06</strong>
            <small>THOUGHTFUL TOOLS</small>
          </div>
          <div>
            <strong>01</strong>
            <small>CONNECTED PLATFORM</small>
          </div>
          <div>
            <strong>∞</strong>
            <small>REASONS TO STAY CURIOUS</small>
          </div>
        </section>
        <section className="ca-toolkit-section" id="tools">
          <div className="ca-section-top">
            <div>
              <div className="ca-overline">
                <span /> MEET YOUR TOOLKIT
              </div>
              <h2>
                One platform. <span>More peace of mind.</span>
              </h2>
              <p>
                Six purposeful tools for the questions you have about security.
              </p>
            </div>
            <span className="ca-section-index">
              THE COLLECTION <b> / 01</b>
            </span>
          </div>
          <div className="ca-filter-row">
            <div className="ca-filters" role="group" aria-label="Filter tools">
              <button
                className={filter === 'all' ? 'active' : ''}
                onClick={() => setFilter('all')}
                type="button"
              >
                All tools <span>06</span>
              </button>
              <button
                className={filter === 'everyday' ? 'active' : ''}
                onClick={() => setFilter('everyday')}
                type="button"
              >
                Everyday safety
              </button>
              <button
                className={filter === 'website' ? 'active' : ''}
                onClick={() => setFilter('website')}
                type="button"
              >
                Website security
              </button>
            </div>
            <div className="ca-filter-note">
              <span /> ALL TOOLS READY TO EXPLORE
            </div>
          </div>
          <div className="ca-tool-grid">
            {visible.map((tool) => (
              <Link
                to={tool.path}
                key={tool.id}
                className={`ca-tool-card ca-card-${tool.accent}`}
              >
                <div className="ca-card-top">
                  <span className="ca-card-icon">
                    <tool.icon size={23} strokeWidth={1.6} />
                  </span>
                  <span className="ca-card-number">
                    {tool.number} <i>/</i> 06
                  </span>
                </div>
                <div className="ca-card-category">{tool.category}</div>
                <h3>{tool.name}</h3>
                <p>{tool.description}</p>
                <div className="ca-card-bottom">
                  <span>{tool.action}</span>
                  <span className="ca-card-arrow">
                    <ArrowUpRight size={16} />
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </section>
        <section className="ca-approach" id="approach">
          <div className="ca-approach-copy">
            <div className="ca-overline">
              <span /> OUR APPROACH
            </div>
            <h2>
              Security shouldn’t
              <br />
              feel <em>complicated.</em>
            </h2>
            <p>
              We believe everyone deserves clear information about their digital
              world. Cyber Ace turns complex signals into a place to start.
            </p>
            <Link to="/#tools" className="ca-approach-link">
              Find your tool <ArrowRight size={16} />
            </Link>
          </div>
          <div className="ca-approach-list">
            <div>
              <span>01</span>
              <div>
                <strong>Choose what you want to check</strong>
                <p>
                  Links, files, passwords, email, or websites—start wherever you
                  are.
                </p>
              </div>
              <ArrowUpRight size={16} />
            </div>
            <div>
              <span>02</span>
              <div>
                <strong>Get context, not confusion</strong>
                <p>
                  Understand the available signals and know when a check is
                  incomplete.
                </p>
              </div>
              <ArrowUpRight size={16} />
            </div>
            <div>
              <span>03</span>
              <div>
                <strong>Make a more informed decision</strong>
                <p>
                  Use what you learn as a first step. No scanner can promise
                  complete safety.
                </p>
              </div>
              <ArrowUpRight size={16} />
            </div>
          </div>
        </section>
        <section className="ca-faq" id="faq">
          <div className="ca-faq-intro">
            <div className="ca-overline">
              <span /> GOOD TO KNOW
            </div>
            <h2>
              Curious? <em>We like that.</em>
            </h2>
            <p>A few answers before you get started.</p>
            <span className="ca-faq-icon">
              <CircleHelp size={24} />
            </span>
          </div>
          <div className="ca-faq-list">
            {questions.map(([question, answer]) => (
              <details key={question}>
                <summary>
                  {question}
                  <ChevronDown size={17} />
                </summary>
                <p>{answer}</p>
              </details>
            ))}
          </div>
        </section>
        <section className="ca-cta">
          <div>
            <div className="ca-overline">A LITTLE MORE PEACE OF MIND</div>
            <h2>Ready to look a little closer?</h2>
            <p>Your toolkit is here whenever you need it.</p>
          </div>
          <a className="ca-button dark" href="#tools">
            Explore all tools <ArrowUpRight size={17} />
          </a>
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
        <a href="#top">
          BACK TO TOP <ArrowUpRight size={13} />
        </a>
      </footer>
    </div>
  );
}
