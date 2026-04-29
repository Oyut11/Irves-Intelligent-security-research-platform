# Network Intercept

The **Network Intercept** feature provides real-time HTTP/HTTPS traffic capture and analysis for Android applications. It uses mitmproxy as the underlying proxy engine, with a custom addon that ingests flows, detects security issues, and streams data to your browser via WebSocket.

---

## Table of Contents

- [Concept](#concept)
- [Architecture](#architecture)
- [Setup Workflow](#setup-workflow)
- [Flow Table](#flow-table)
- [Flow Inspector](#flow-inspector)
- [Intercept Rules](#intercept-rules)
- [Diff Viewer](#diff-viewer)
- [Security Analysis](#security-analysis)
- [Protocol Support](#protocol-support)
- [Troubleshooting](#troubleshooting)

---

## Concept

Static analysis shows you what network code *exists*. Network intercept shows you what traffic *actually flows*:

- Which endpoints does the app call in production?
- What sensitive data leaks in request/response bodies?
- How does the app handle SSL pinning and certificate validation?
- Are there hidden APIs or debug endpoints?

Network intercept is typically used **after** static analysis (to confirm findings) and **before** exploitation (to understand the attack surface).

### Key Concepts

#### Man-in-the-Middle (MitM)

Network intercept works by positioning IRVES as a **man-in-the-middle proxy** between the Android app and the internet. All HTTP/HTTPS traffic is routed through IRVES's proxy (port 8080), allowing you to inspect, modify, and analyze each request and response in real time.

#### HTTPS and SSL/TLS

HTTPS encrypts traffic using SSL/TLS to prevent eavesdropping. To intercept HTTPS traffic, IRVES must:
1. Present its own certificate to the app (acting as the server)
2. Decrypt the traffic, inspect/modify it
3. Re-encrypt it and forward to the real server
4. Do the reverse for the server's response

This requires the device to trust IRVES's CA certificate.

#### CA Certificate

A **Certificate Authority (CA) certificate** is a root certificate that signs other certificates. IRVES generates a custom CA certificate that signs per-site certificates on-the-fly. For HTTPS interception to work, the Android device must trust this CA certificate. Without this trust, the app will reject the connection (certificate validation error).

#### SSL Pinning

**SSL pinning** is a security technique where apps hardcode or embed the expected server certificate (or its public key) and reject any certificate that doesn't match. This defeats standard MitM attacks, including IRVES's proxy. Common pinning implementations include:
- **OkHttp3** — CertificatePinner with SHA-256 hashes
- **TrustManager** — Custom validation logic
- **Network Security Config** — Android 7+ pinning rules

IRVES provides two bypass mechanisms:
1. **SSL Pinning Bypass Hook** (Runtime Workspace) — Patches Java-level validation
2. **SSL Capture** (Network Intercept) — Hooks BoringSSL at the native layer to capture plaintext before encryption

#### SSL Capture

**SSL Capture** is IRVES's native-layer hooking mechanism for bypassing SSL pinning. It injects a Frida hook into the app's BoringSSL/OpenSSL library to intercept `SSL_read` and `SSL_write` calls. This captures plaintext traffic **before** it's encrypted and **after** it's decrypted, bypassing certificate pinning entirely. This is more reliable than Java-level bypasses for apps with native networking code.

#### Stealth Mode

**Stealth Mode** hides IRVES's instrumentation from anti-tampering and anti-debugging mechanisms. It includes:
- **Camouflaged CA Certificate** — IRVES's CA certificate uses benign metadata (common issuer name, standard validity period) to evade detection by apps that check certificate properties
- **Zymbiote Stealth Cloak** (Runtime Workspace) — Hides Frida from `/proc/self/maps`, masks thread names, and removes instrumentation artifacts
- **Proxy Signature Evasion** — Modifies proxy headers to avoid detection by server-side anti-proxy checks

Stealth Mode is essential for analyzing apps with RASP (Runtime Application Self-Protection).

#### Intercept Rules

**Intercept rules** let you target specific flows for modification or deep inspection. Rules define:
- **Match criteria** — URL patterns, HTTP methods, header values
- **Actions** — Log only, break for manual inspection, or modify responses
- **Priority** — Rules are evaluated in order; first match wins

Use rules to:
- Test API bypasses by modifying response bodies
- Force specific error conditions
- Replay requests with altered parameters
- Isolate specific endpoints for focused analysis

#### API Surface Mapping

**API surface mapping** is the process of discovering and cataloging all endpoints an app uses. IRVES automates this by:
- Capturing every HTTP request during app usage
- Extracting endpoint paths, methods, and parameters
- Grouping by API version or base URL
- Detecting hidden or undocumented endpoints

The resulting map shows the complete attack surface, including authentication endpoints, data APIs, and configuration endpoints.

#### CORS (Cross-Origin Resource Sharing)

**CORS** is a browser security mechanism that restricts cross-origin requests. While primarily a web security concern, mobile apps using WebView or hybrid frameworks may implement CORS checks. IRVES can:
- Detect CORS headers in responses (`Access-Control-Allow-Origin`)
- Identify misconfigurations (e.g., overly permissive `*` origin)
- Test CORS bypasses by modifying request headers

CORS issues in mobile apps often indicate insecure WebView configurations or improper backend policies.

---

## Architecture

```
Android App → mitmdump (port 8080) → mitm_addon.py → IRVES Backend → WebSocket → Browser
```

**Components:**
- **mitmdump** — mitmproxy's command-line tool, runs as a subprocess
- **mitm_addon.py** — Custom addon that loads intercept rules, matches flows, detects secrets
- **IRVES Backend** — FastAPI service that ingests flow data and broadcasts to WebSocket listeners
- **Camouflaged CA** — IRVES generates a custom CA certificate with benign metadata to evade pinning detection

---

## Setup Workflow

### 1. Start the Proxy

Navigate to the **Network Intercept** tab. The proxy starts automatically on port 8080 when the page loads. You'll see a status indicator showing "Proxy Active".

### 2. Configure Device Proxy

Configure your Android device to use the proxy:

**Option A: ADB Reverse (Recommended)**
```bash
adb reverse tcp:8080 tcp:8080
```
This forwards device port 8080 to your host machine — no manual device configuration needed.

**Option B: Manual Proxy Settings**
- Go to device Wi-Fi settings
- Long-press your network → Modify network
- Advanced options → Proxy → Manual
- Set proxy host to your machine's IP and port to 8080

### 3. Install the CA Certificate

For HTTPS interception, the device must trust IRVES's CA certificate:

1. Click the certificate download link in the Network Intercept header
2. Transfer the `.pem` file to your device (via ADB push or email)
3. Open the file on the device — Android will prompt to install it
4. Name it "IRVES CA" and mark it as "VPN and apps" trusted

**Note:** On Android 7+, apps can ignore user-installed CAs. You may need to use the **SSL Pinning Bypass** hook in Runtime Workspace to fully capture HTTPS traffic.

### 4. Capture Traffic

Trigger network activity in your app (open it, perform actions, navigate screens). Flows will appear in the **Flow Table** in real time.

---

## Flow Table

The flow table displays all captured HTTP/HTTPS requests in a scrollable list:

| Column | Description |
|--------|-------------|
| **Method** | HTTP verb (GET, POST, PUT, DELETE) — color-coded |
| **URL** | Request endpoint, truncated if long |
| **Status** | HTTP status code (2xx, 3xx, 4xx, 5xx) — color-coded |
| **Size** | Response body size in bytes |
| **Time** | Request duration in milliseconds |
| **Badges** | Security indicators (pinning, secrets, protocol) |

**Color coding:**
- **GET** — green
- **POST** — blue
- **PUT** — orange
- **DELETE** — red
- **2xx** — green
- **3xx** — blue
- **4xx** — orange
- **5xx** — red

**Badges:**
- **PINNING** — certificate pinning detected (orange = standard, red = high)
- **WS** — WebSocket connection
- **gRPC** — gRPC protocol detected
- **SECRET** — potential secret (API key, token) in body
- **CRITICAL** — high-severity security issue

---

## Flow Inspector

Click any row in the flow table to open the **Flow Inspector**. This shows full request/response details in a split-pane view:

**Left pane — Request:**
- Headers (all request headers)
- Body (raw request body, formatted if JSON)
- Query parameters (if present)

**Right pane — Response:**
- Headers (all response headers)
- Body (raw response body, formatted if JSON)
- Status code and message

The inspector is syntax-highlighted and supports line-wrapping for long payloads.

---

## Intercept Rules

Intercept rules let you **target specific flows** for modification or deep inspection. Rules are stored in the database and loaded by the mitm_addon.

**Create a rule:**
1. Click **+ Add Rule** in the rules panel
2. Specify match criteria:
   - **URL pattern** (e.g., `api.example.com/*`)
   - **HTTP method** (GET, POST, etc.)
   - **Header match** (e.g., `Authorization: Bearer *`)
3. Choose action:
   - **Log only** — flag for later review
   - **Break** — pause the flow for manual inspection
   - **Modify** — apply response body changes
4. Save the rule

**Rule matching:**
Rules are evaluated in order. The first matching rule applies. Use drag-and-drop to reorder.

---

## Diff Viewer

The **Diff Viewer** shows the difference between the original response and a modified response (after applying an intercept rule).

**View a diff:**
1. Apply a "Modify" intercept rule to a flow
2. Click the flow in the table
3. Click **View Diff** in the inspector

The diff viewer shows:
- **Original** (left) — the response as received from the server
- **Modified** (right) — the response after your changes
- **Changes** — highlighted in green (added) or red (removed)

This is useful for testing API bypasses, privilege escalation, or response tampering.

---

## Security Analysis

IRVES automatically analyzes each flow for security issues:

**Secret Detection:**
- API keys (AWS, Google, Stripe patterns)
- Auth tokens (Bearer, Basic)
- Session IDs and cookies
- Passwords in request bodies

**SSL Pinning Detection:**
- Checks for certificate pinning headers
- Analyzes TLS handshake for custom validation
- Flags apps that may reject your CA certificate

**Risk Scoring:**
- **Critical** — hardcoded secrets, auth bypass, data exfiltration
- **High** — sensitive data in URL, weak auth, missing HTTPS
- **Medium** — insecure headers, CORS issues
- **Low** — informational leaks, verbose errors

**Security Checklist:**
The checklist panel shows common security checks for the selected flow. Toggle items to mark them as verified during your assessment.

---

## Protocol Support

IRVES's mitm_addon detects and handles multiple protocols beyond standard HTTP:

**WebSocket:**
- Detects upgrade headers
- Tracks message frames
- Shows bidirectional communication in the inspector

**gRPC:**
- Detects protobuf content-type
- Attempts to decode protobuf messages (if schema available)
- Flags gRPC-specific issues (unencrypted streams, metadata leaks)

**Protobuf:**
- Detects binary protobuf payloads
- Shows hex dump for analysis
- Can be paired with external protobuf decoders

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No flows appearing | Proxy not configured, app not using network | Verify ADB reverse or manual proxy settings; trigger network activity |
| HTTPS flows show "CONNECT" only | CA certificate not trusted | Install IRVES CA on device; use SSL Pinning Bypass hook |
| App crashes on network calls | App has SSL pinning / RASP | Inject SSL Pinning Bypass hook in Runtime Workspace |
| Proxy fails to start | Port 8080 already in use | Kill other processes using port 8080 (`lsof -i :8080`) |
| Flows not streaming to browser | WebSocket disconnected | Refresh the page; check backend logs for errors |
| Diff viewer shows no changes | Rule not matching or not applied | Verify rule URL pattern matches the flow; check rule is enabled |
| gRPC flows show binary only | No protobuf schema available | Export binary and decode with external tool (protoc) |

---

## Security Notes

- **Man-in-the-middle** interception requires CA trust — this is a privileged operation
- **Certificate pinning bypass** may be required for HTTPS on modern apps
- **Intercept rules** can modify traffic — use responsibly in testing environments only
- **Captured data** may contain sensitive information — clear the table after assessment
