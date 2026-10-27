import { Suspense, lazy, useEffect } from 'react';
import {
  BrowserRouter,
  Link,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom';

const Home = lazy(() => import('./pages/Home.jsx'));
const UrlScanner = lazy(() => import('./pages/UrlScanner.jsx'));
const FileScanner = lazy(() => import('./pages/FileScanner.jsx'));
const PasswordStudio = lazy(() => import('./pages/PasswordStudio.jsx'));
const EmailHeaders = lazy(() => import('./pages/EmailHeaders.jsx'));
const DomainInspector = lazy(() => import('./pages/DomainInspector.jsx'));
const SecurityHeaders = lazy(() => import('./pages/SecurityHeaders.jsx'));

function RouteScroll() {
  const { pathname, hash } = useLocation();
  useEffect(() => {
    if (!hash) window.scrollTo(0, 0);
    else {
      const timer = window.setTimeout(
        () =>
          document
            .getElementById(hash.slice(1))
            ?.scrollIntoView({ behavior: 'smooth' }),
        100,
      );
      return () => clearTimeout(timer);
    }
  }, [pathname, hash]);
  return null;
}

function NotFound() {
  return (
    <main className="ca-not-found">
      <span>404 / NOT FOUND</span>
      <h1>Looks like this page wandered off.</h1>
      <p>Let’s get you back to your security toolkit.</p>
      <Link className="ca-button dark" to="/">
        Back to Cyber Ace →
      </Link>
    </main>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <RouteScroll />
      <Suspense
        fallback={
          <div className="ca-route-loading">
            <span /> Getting things ready...
          </div>
        }
      >
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/tools/url-scanner" element={<UrlScanner />} />
          <Route path="/tools/file-scanner" element={<FileScanner />} />
          <Route path="/tools/password-studio" element={<PasswordStudio />} />
          <Route path="/tools/email-headers" element={<EmailHeaders />} />
          <Route path="/tools/domain-inspector" element={<DomainInspector />} />
          <Route path="/tools/security-headers" element={<SecurityHeaders />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
