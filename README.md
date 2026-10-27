# Linkscope

A URL-safety **first-pass research tool**. Linkscope examines a link's formatting, public DNS resolution, and HTTPS certificate, and can optionally retrieve an existing VirusTotal report. It explains which checks ran and which were unavailable instead of claiming that a link is definitely safe.

> **Not a VirusTotal replacement or a malware sandbox.** The app does not open pages, follow redirects, download files, inspect page content, or execute malware. A clean result is not proof of safety, and legitimate links can trigger warnings. Do not paste private links, credentials, or secrets.

## Run locally

Requires Node.js 20 or later.

```sh
npm install
npm run dev
```

Open <http://localhost:3000>. The React/Vite frontend and the Node API run on the same server. The UI uses relative `/api` URLs, so it also works behind a preview proxy.

```sh
npm test       # network-isolated unit and API tests
npm run build  # build the production frontend
npm start      # serve the build and API
```

The default port is `3000`; set `PORT` to change it. The server reads a local `.env` file if present.

## Deploy on Render with a Blueprint

The root `render.yaml` provisions one **Free** Node web service in Singapore. It builds the frontend and serves it together with the API; no database or additional service is needed.

1. Commit and push this project, including `render.yaml`, to a GitHub branch.
2. In the [Render Dashboard](https://dashboard.render.com/), choose **New → Blueprint** and connect the repository.
3. Select the branch containing `render.yaml` (for the current Arena session: `arena/9f125033-urlapprover`), review the resources and click **Deploy Blueprint**. Render will build and deploy that same branch and provide an `onrender.com` URL.
4. After the deploy is live, open the URL and try a scan. The `/api/health` endpoint is used for Render health checks.
5. Optional: in the web service's **Environment** tab, add `VIRUSTOTAL_API_KEY` privately, then save and redeploy/restart. It is not required for the Blueprint to deploy. Do not paste the key into GitHub or chat.

The Free instance spins down after inactivity, so the first request after idle can take around a minute before the app is available. That startup time is separate from the scan's 30-second browser timeout; use an always-on paid plan if predictable availability is important. Free-tier limits and availability are set by Render.

The Blueprint configures `TRUST_PROXY_HOPS=1` so the scanner's basic in-memory rate limiter uses only the nearest forwarded hop rather than trusting the whole `X-Forwarded-For` chain. It defaults to `0` (no proxy trust) outside Render. Verify the actual proxy topology after deployment: extra proxies can cause users to share a rate-limit bucket, and trusting too many hops can allow spoofing. This per-instance limiter is best-effort, resets on restart, and is not a substitute for an edge/WAF and a distributed rate limiter on a public deployment.

## Optional threat intelligence

1. Copy `.env.example` to `.env` and set `VIRUSTOTAL_API_KEY` on the **server**. Do not put API keys in frontend code or commit them.
2. Restart the server. The checkbox in the scanner becomes available.
3. The user must opt in for each scan. If selected, the **full URL**, including its path and query, is sent to VirusTotal. Links containing username/password fields are never sent.

Linkscope uses a read-only `GET /api/v3/urls/{id}` lookup of an **existing** VirusTotal report; it does not submit a URL for a new analysis. A missing report, an old/undated report, quota errors, or an unavailable service are displayed explicitly. Review [VirusTotal's API documentation and usage terms](https://docs.virustotal.com/reference/overview) before deploying.

Without a key or without opt-in, threat intelligence is marked **not checked**. A scan with no obvious issues is shown as limited rather than safe.

## What is checked

- **URL patterns:** credentials in the URL, IP-based hosts, internationalized domains, excessive subdomains, long links, and non-standard ports. These are heuristics, not proof of phishing.
- **DNS:** resolves the hostname and requires every returned address to be public. This says nothing about whether the domain is trustworthy.
- **TLS:** for HTTPS on the standard port, performs a TLS handshake against an already validated IP and checks certificate identity and trust. No URL path or page content is sent. A valid certificate means encryption is available, not that the site is benign.
- **Reputation:** optionally retrieves a pre-existing VirusTotal report with the user's consent. Engine flags can be wrong or stale; an absence of detections is not proof of safety.

DNS has a 6-second limit, and TLS and reputation checks run concurrently with approximately 7-second limits. The browser stops waiting after 30 seconds. Network conditions and provider behavior can still prevent results. The scanner's network may block destinations or intercept TLS: in that case, checks can be unavailable or report a certificate that cannot be verified. The scanner reports the certificate it actually receives, not necessarily the origin's certificate.

## Security and privacy design

- Only HTTP(S) links are accepted. Local and single-label names are blocked; private, loopback, link-local, reserved, special-use, and non-global IPv6 addresses are denied. All DNS answers are checked; mixed public/private answers are rejected.
- TLS connects directly to a previously validated IP on port 443, with the original hostname used for certificate validation. This avoids a second DNS lookup at connection time and limits DNS-rebinding risk. Arbitrary ports, HTTP requests, and redirects are not followed.
- Requests have body-size, concurrency, and basic IP-based rate limits. API responses use `no-store`. The app does not log URLs or save scan results on the server.
- The displayed report masks URL credentials, query strings, and fragments. Recent history stores only hostnames, verdict labels, and timestamps in the user's browser, where it can be cleared. DNS providers, network intermediaries, a deployment's own logging infrastructure, and an opted-in VirusTotal lookup may still see data; use HTTPS in production.

These controls reduce risk but are not a complete production security boundary. For public deployment, add a dedicated isolated scanning worker, an egress firewall enforcing destination and port policy, a trusted proxy with distributed rate limits, abuse monitoring, and a security review. Never run arbitrary website content on the application server.

## API

- `GET /api/health` — lightweight process health check; does not contact third parties.
- `GET /api/config` — whether the optional provider is configured; never returns the key.
- `POST /api/scan` — JSON `{ "url": "https://example.com", "includeReputation": false }`.

The response contains a redacted display URL, hostname, timestamp, verdict, coverage, and individual check statuses (`pass`, `warning`, `danger`, `info`, or `unavailable`). URLs are rendered as text, not clickable links.

## Portfolio directions

This is a useful foundation for a cybersecurity resume, especially when accompanied by a threat model and evidence of testing. Strong next steps include a safely isolated browser/VM analysis pipeline, carefully controlled redirect inspection, multiple independently attributed threat feeds, measured false-positive/false-negative rates on a documented test set, and observability and abuse defenses. Describe exactly which checks your deployed version performs; avoid presenting it as comprehensive malware detection until it actually has that capability.
