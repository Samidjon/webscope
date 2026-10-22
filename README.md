# WebScope — Web Security Workbench

WebScope is a local-first toolkit for authorized web application testing, built with Python, mitmproxy, FastAPI, SQLite, React and TypeScript.

## Current features (0.2.0)

- **Proxy history:** local HTTP/HTTPS interception on **127.0.0.1:8080**, searchable history, request/response inspector, status/method filters and JSON export.
- **Repeater:** edit and send one manually composed HTTP request, inspect response headers/body and latency. It sends only to a hostname explicitly added to Scope, limits methods and timeouts, and does not follow redirects.
- **Passive scanner:** analyzes already captured responses for common security-header, cookie-flag, CORS and server-banner configuration gaps. It does not crawl or send probes.
- **Target map:** summarizes hosts and paths already seen in local history. It does not crawl.
- **Decoder:** Base64, URL encoding/decoding, HTML escaping/entity decoding and JWT payload display. JWT signatures are not verified.
- **Comparer:** local line-by-line text comparison.
- **Scope & settings:** persisted allowlist of exact DNS hostnames or IPv4 addresses for Repeater. Wildcards, URL schemes, paths and ports are rejected.
- **Privacy safeguards:** masks common credential headers, URL query values and JSON/form fields; Set-Cookie values are redacted while security flags are retained for passive checks. Non-text request/response bodies are omitted and stored bodies are truncated.
- **Loopback-only services:** API and proxy bind to 127.0.0.1.

This is an early, single-user tool—not a hardened shared service or a replacement for a professional security review. Passive findings are indicators, not proof of exploitability or a complete security scan.

## Requirements (Windows 10/11)

- Python 3.12, 64-bit (recommended)
- Node.js 20 or newer, including npm
- Internet access for first dependency installation

Do not install mitmproxy globally; it is installed into the project's Python environment.

## Start

1. Extract this folder somewhere writable, for example C:\Projects\webscope.
2. Open PowerShell in the project folder.
3. Run:

   ~~~powershell
   powershell -ExecutionPolicy Bypass -File .\start.ps1
   ~~~

4. On first launch, the script creates the virtual environment, installs dependencies, installs npm packages, and starts the API, proxy and frontend in separate terminals.
5. Open http://127.0.0.1:5173.

Services:
- Dashboard: http://127.0.0.1:5173
- API health: http://127.0.0.1:8000/api/health
- Proxy: 127.0.0.1:8080

## Configure Firefox

Use a separate Firefox profile for testing so that normal browser traffic remains separate.

1. Open about:preferences and locate **General → Network Settings → Settings…**.
2. Select **Manual proxy configuration**.
3. Set HTTP Proxy to 127.0.0.1, Port 8080. Set HTTPS Proxy to the same host and port, or enable the option to use the HTTP proxy for HTTPS.
4. Keep the SOCKS fields empty and leave the bypass list empty while testing.
5. Open http://mitm.it through the configured browser. Follow the official mitmproxy certificate guide for Firefox and install the local CA only in the test profile.
6. Remove the test CA after finishing your work if it is no longer needed.

An HTTP smoke test from PowerShell:

~~~powershell
curl.exe --max-time 10 -v --proxy http://127.0.0.1:8080 http://example.com/
~~~

The proxy console should print the request and response. For HTTPS inspection, Firefox must trust the locally generated mitmproxy CA. Never disable browser certificate checking globally.

Official references:
- https://docs.mitmproxy.org/stable/overview/getting-started/
- https://docs.mitmproxy.org/stable/concepts/certificates/

## Use Repeater safely

1. Open **Scope & settings**.
2. Add the exact test hostname, such as localhost, or the exact authorized lab hostname.
3. Open **Repeater**, choose a URL whose hostname matches the list, edit the request and click **Send**.
4. Check the status, response headers, body and elapsed time.

Repeater uses direct HTTP requests through httpx; these requests do **not** pass through the mitmproxy capture engine and are not inserted into Proxy history automatically. Redirects are not followed. The allowlist is hostname based; adding a hostname permits requests to its explicitly supplied ports, so only add targets you are authorized to test.

## Passive analysis

Open **Passive scanner** to analyze responses already in SQLite. Checks include missing common browser-security headers, cookie security flags, a common CORS inconsistency, and server/technology banners. Missing headers may be appropriate in some contexts; review findings and test the application in context.

## Tests and build

Backend tests:

~~~powershell
python -m unittest discover -s tests -v
~~~

Frontend build:

~~~powershell
cd frontend
npm ci
npm run build
~~~

## Local data and privacy

- History: data/webscope.sqlite3
- Exact target scope: data/scope.json
- Proxy status marker: data/proxy_status.json

Use only against systems you own or are explicitly authorized to test. Avoid capturing production secrets or personal data. Redaction is best-effort and does not guarantee every custom format is scrubbed. Keep WebScope on loopback; do not expose it to a public or shared network.
