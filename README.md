# WebScope — Web Security Workbench (MVP)

WebScope is a local-first starter project for authorized web application security testing. It combines a `mitmproxy` capture engine, a FastAPI API, SQLite history, and a React/TypeScript dashboard.

## Included in this first MVP

- Local HTTP/HTTPS proxy on `127.0.0.1:8080` using mitmproxy.
- HTTP history with method, host, path, status, content type, time, and latency.
- Request/response header and body inspector.
- Search by host/path/method and method/status filters.
- SQLite storage in `data/webscope.sqlite3`.
- Periodic UI refresh and JSON export of the currently displayed history.
- Privacy safeguards: common auth/cookie headers, sensitive query parameters, and common JSON/form fields are masked before they are written to history; non-text bodies are omitted; stored bodies are truncated.
- Services bind to loopback (`127.0.0.1`) and are not exposed to the local network.

Repeater, target map, scanner, and active tests are intentionally placeholders for later iterations.

## Requirements (Windows 10/11)

- Python 3.12, 64-bit (recommended)
- Node.js 20 or newer, including npm
- Internet access for the first dependency installation

Install mitmproxy via this project's Python environment; you do not need a separate global mitmproxy install.

## Start it

1. Extract this folder somewhere writable, for example `C:\Projects\webscope`.
2. Open PowerShell in the extracted `webscope` folder.
3. Run:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start.ps1
   ```

4. The first launch creates `.venv`, installs dependencies, then opens two additional PowerShell windows for the API and proxy. The original window runs Vite.
5. Open <http://127.0.0.1:5173>.

The API health endpoint is <http://127.0.0.1:8000/api/health>. The proxy listens on `127.0.0.1:8080`.

## Capture your own test traffic

Use a separate browser profile, preferably Firefox, so you do not accidentally proxy every app on Windows.

1. Start WebScope and confirm that the dashboard says **Proxy online**.
2. In Firefox, open **Settings → General → Network Settings → Settings…**.
3. Select **Manual proxy configuration**. Set **HTTP Proxy** to `127.0.0.1`, port `8080`. Enable the option to also use this proxy for HTTPS, if shown.
4. With that browser configured, open `http://mitm.it` and follow mitmproxy's Windows certificate instructions. The proxy's local CA is generated in `%USERPROFILE%\.mitmproxy` after the first proxy start. For the Windows import file, look for `mitmproxy-ca-cert.p12`.
5. Only trust this locally generated CA on a test machine/profile you control. Remove the CA from the trust store when you no longer need HTTPS inspection.
6. Browse a local app, a lab such as OWASP Juice Shop that you run yourself, or another explicitly authorized test target. Requests should appear in the history view.

Without trusting the local CA, HTTPS interception will show certificate errors or will not be inspectable. Some applications use certificate pinning and may not work through an intercepting proxy.

Official references:
- mitmproxy setup: <https://docs.mitmproxy.org/stable/overview/getting-started/>
- mitmproxy certificates: <https://docs.mitmproxy.org/stable/concepts/certificates/>

## Run tests

From the project root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Build the frontend:

```powershell
cd frontend
npm run build
```

## Security and data notes

- Use only against systems you own or have explicit permission to test.
- WebScope is an early MVP, not a hardened multi-user product. Do not run it as a shared/public service.
- History lives locally in `data/webscope.sqlite3`. Delete the history in the UI or stop the app and remove the `data` folder to purge it.
- Header/query/body redaction is best-effort, not a guarantee that every secret in every custom format is detected. Avoid capturing real personal or production data.
- The Repeater and Scanner pages are not implemented yet; no active vulnerability tests run in this version.
