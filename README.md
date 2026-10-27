# Cyber Ace

Cyber Ace is a single cybersecurity toolkit with six independently usable tools, a React landing page, and one Node API. Each tool explains the signals it can and cannot check; none can guarantee that a link, file, password, or website is safe.

> **Research and education prototype, not a replacement for antivirus or a full security audit.** File checks are limited to fingerprints, basic signatures and filename heuristics. Optional VirusTotal lookups retrieve existing reports only. No file or website is executed, no redirects are followed, and clean results are not proof of safety.

## The toolkit

| Tool | What it does | Where data goes |
| --- | --- | --- |
| **URL Scanner** (`/tools/url-scanner`) | Checks URL formatting, public DNS, TLS, and optionally an existing VirusTotal URL report. | The URL reaches this server. Only with opt-in, the complete URL is also sent to VirusTotal. Browser history stores hostnames, result labels, and timestamps—not full URLs. |
| **File Scanner** (`/tools/file-scanner`) | Computes SHA-256, checks basic file signatures and filename/extension signals, and calculates byte entropy. Optionally checks an existing VirusTotal file report. | File bytes are processed in the browser and are not uploaded. With opt-in, only the SHA-256 fingerprint is sent to this server and VirusTotal. |
| **Password Studio** (`/tools/password-studio`) | Estimates password strength with zxcvbn and generates random passwords using Web Crypto. It does not search breach databases. | Passwords remain in the browser and are not sent to the server or stored by this app. |
| **Email Header Analyzer** (`/tools/email-headers`) | Parses sender/reply-to fields, hop counts, and SPF/DKIM/DMARC *claims*. Those claims are not independently verified and can be forged. | Headers are processed in the browser; paste headers only, not private message bodies. |
| **Domain Inspector** (`/tools/domain-inspector`) | Queries public A, AAAA, MX, NS, SPF, and DMARC records. It does not validate DNSSEC, DKIM, ownership, or complete policy correctness. | The domain reaches this server and its DNS resolver. |
| **Security Headers** (`/tools/security-headers`) | Sends a HEAD request to a public site's root on a standard port and reports selected headers. It does not follow redirects or validate header effectiveness. | The input reaches this server; the destination receives a root HEAD request, not the supplied path or query. |

An optional VirusTotal lookup can be stale or unavailable, may produce false positives, and shares data with the provider. A TLS certificate or security header does not establish trust. DNS records and email headers can be incomplete or misleading. Always apply independent judgment.

## Run locally

Requires Node.js 20 or newer.

```sh
npm install
npm run dev
```

Open <http://localhost:3000>. The frontend and API share one server and use relative `/api` URLs. Each tool has its own client-side route; the production server handles direct visits and refreshes.

```sh
npm test       # unit, API, and deployment tests; no live external services required
npm run build  # production frontend
npm start      # serve production frontend and API
```

The server honors `PORT` (default 3000) and reads a local `.env` file if present.

## Optional VirusTotal integration

1. Copy `.env.example` to `.env` and set `VIRUSTOTAL_API_KEY` **on the server**. Never commit a key or put it in browser code.
2. Restart the server. Optional lookup controls become available in the URL and file tools.
3. Users must explicitly opt in for each lookup. URL checks send the **full URL** to VirusTotal; file checks send the **SHA-256 fingerprint only**, never the file. URLs containing credentials are not sent.

Both features use read-only lookups of **existing** VirusTotal reports, not new submissions. Unknown, outdated, rate-limited, or unavailable reports are marked as such. Review [VirusTotal's API documentation and usage terms](https://docs.virustotal.com/reference/overview) before deployment.

## Deploy on Render with a Blueprint

The root `render.yaml` provisions a single **Free** Node web service named `cyberace-security-platform` in Singapore and builds the frontend with the API. Render assigns a unique `onrender.com` address incorporating the service name; the exact address is shown in its dashboard after creation. If you already created a Blueprint service named `linkscope-url-scanner`, review the proposed changes carefully: the new name can create a replacement service rather than rename the existing URL.

1. Commit and push your changes, including `render.yaml`, to the connected GitHub branch.
2. Open [Deploy Cyber Ace to Render](https://render.com/deploy?repo=https%3A%2F%2Fgithub.com%2FSoham-Dharap%2FUrlApprover%2Ftree%2Farena%2F9f125033-urlapprover), or choose **New → Blueprint** in the Render Dashboard and connect the repository.
3. Confirm the branch `arena/9f125033-urlapprover`, review the service, and choose **Deploy Blueprint**. Render provides the `onrender.com` URL.
4. Optionally add `VIRUSTOTAL_API_KEY` in the service's **Environment** tab, then save and redeploy/restart. It is not required to deploy.

Free instances spin down after inactivity and a cold start can take around a minute; this is separate from a tool's scan timeout. Free-tier limits and availability are set by Render.

The Blueprint sets `TRUST_PROXY_HOPS=1` for the nearest forwarded hop; local use defaults to no proxy trust. Confirm your real proxy topology: extra proxies can cause shared rate-limit buckets, while trusting too many hops can allow spoofing. The in-memory, per-instance limiter is best-effort and resets on restart; use an edge/WAF and a distributed limiter before public production use.

## Safety architecture and limitations

- URL and security-header connections resolve once, reject local, private, loopback, link-local, reserved, special-use and non-global IPv6 destinations, reject mixed public/private DNS answers, and connect directly to a validated IP. The HTTP tool uses only standard ports, the root path, and a HEAD request; it never follows redirects.
- URL checking does not download or inspect pages. The header check requires a verified TLS connection for HTTPS. Proxy interception or restricted outbound networks may make results unavailable or cause certificate warnings.
- API inputs have size, concurrency, and basic IP-based rate limits. API responses use `no-store`; this app does not log submitted values or persist scans on the server. Hosting providers, resolvers and upstream intermediaries can still see data. Use HTTPS.
- Browser-local processing reduces data transmission but does not protect against browser extensions, compromised devices, or someone watching the screen. Use a password manager and avoid pasting private or sensitive data.
- These controls reduce risk but are **not a complete production security boundary**. Before broad public deployment, add an isolated worker and egress firewall, robust abuse monitoring, distributed rate limits, observability, independent security review, and a policy for abuse/false reports.

## API

- `GET /api/health` — lightweight health check.
- `GET /api/config` — provider availability, never the key.
- `POST /api/scan` — `{ "url": "https://example.com", "includeReputation": false }`.
- `POST /api/dns-audit` — `{ "domain": "example.com" }`.
- `POST /api/security-headers` — `{ "url": "https://example.com" }`.
- `POST /api/file-reputation` — `{ "sha256": "<64 hex characters>" }`; accepts a fingerprint only, not a file upload.

## Portfolio directions

This is a useful foundation for a cybersecurity portfolio, particularly when accompanied by a threat model and evidence of tests. Next steps include safely isolated dynamic analysis, independently attributed threat feeds, evaluated false-positive and false-negative rates on a documented dataset, and production-grade egress and abuse controls. Describe only the checks actually implemented.
