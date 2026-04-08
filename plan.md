# IRVES — Intelligent Security Tool
## Phase-Based Implementation Plan

---

## Overview

**IRVES** is a desktop security analysis platform built on:

- **Tauri** — Desktop shell (spawns FastAPI on launch)
- **FastAPI (Python)** — Core analysis engine with tool orchestration
- **HTMX + Jinja2** — Frontend UI rendered inside the Tauri window

Its goal is to provide highly intelligent security analysis and easy-to-use diagnosis for professional security solutions, following OWASP Top Ten and enterprise-grade security standards.

---

## Design Identity (Non-Negotiable)

All UI work must strictly follow these principles.

**Tone:** Precise. Minimal. Commanding. Irves feels like a tool built by someone who respects the developer's intelligence — not a dashboard built to impress a manager.

**Visual anchor:** Dark surfaces. The mountain background appears as a blurred, darkened hero element — atmospheric, not decorative. It grounds the app in something physical and permanent. Think less "cyberpunk hacker" and more "alpine research station at night."

### Color System

| Role            | Color                    | Usage                    |
|-----------------|--------------------------|--------------------------|
| Background      | `#0f0f0d`                | Base surface             |
| Surface         | `#161614`                | Cards, panels            |
| Surface Raised  | `#1e1d1b`                | Elevated elements        |
| Border          | `rgba(255,255,255,0.07)` | Subtle separation        |
| Text Primary    | `#e8e6e1`                | Main content             |
| Text Muted      | `#6e6c68`                | Labels, metadata         |
| Accent          | `#4f98a3`                | CTAs, active states      |
| Critical        | `#c0392b`                | Severity: Critical       |
| High            | `#e67e22`                | Severity: High           |
| Medium          | `#f1c40f`                | Severity: Medium         |
| Low             | `#27ae60`                | Severity: Low            |
| Info            | `#2980b9`                | Severity: Info           |

### Typography
- **JetBrains Mono** — code blocks, findings, terminal output (terminal authenticity)
- **Satoshi** — all UI text (clean, modern, not overused)

---

## App Shell (Persistent — All Screens)

The shell is always present across every screen.

### Top Bar (Fixed)
- Left: sidebar toggle icon + wordmark **"IRVES"** in Satoshi medium; small version badge underneath in muted text.
- Center: global search (`⌘K` shortcut) that opens a command palette.
- Right: notification bell (scan completion alerts) + profile avatar.

### Sidebar (Collapsible)
- Expanded: **220px** wide. Collapsed to icon-only: **56px**.
- Active item has a **left accent bar** in `--accent` (`#4f98a3`).
- No filled icon backgrounds — icons sit raw against the dark surface.

**Navigation items:**
```
Irves
├── Projects           (overview, entry point)
├── Scan               (new scan setup)
├── Live Scan View     (automated pipeline progress)
├── Runtime Workspace  (interactive Frida sessions)
├── Dashboard          (unified findings from both paths)
├── Finding Detail     (AI analysis per finding)
├── Reports            (OWASP, SBOM, Privacy output)
└── Settings           (tools, profiles, device config)
```

---

## Phase 1 — Project Scaffold & App Shell
**Goal:** Stand up the Tauri + FastAPI skeleton and implement the persistent app shell with all navigation.

### Deliverables
- Tauri desktop app project initialized. Tauri is configured to spawn the FastAPI Python process on launch and terminate it on close.
- FastAPI project structure created with placeholder route stubs for all planned endpoints:
  - `/scan/android`, `/scan/ios`, `/scan/desktop`, `/scan/web`
  - `/analysis/ai`
  - `/report/owasp`, `/report/sbom`, `/report/privacy`
- HTMX + Jinja2 rendering layer wired into the FastAPI server, serving all UI templates.
- Global stylesheet implementing the full color system, typography (Satoshi + JetBrains Mono loaded via Google Fonts), and base component tokens.
- Persistent top bar implemented with wordmark, version badge, global search trigger, notification bell, and avatar placeholder.
- Collapsible sidebar implemented with all 8 navigation items, icon-only collapsed state (56px), expanded state (220px), and active accent bar behavior.

---

## Phase 2 — Screen 1: Projects (Home)
**Goal:** The entry point. Where users see all existing projects and begin new ones.

### Visual
- The mountain background image is rendered here as a full-bleed hero element, blurred to ~40%, darkened with a `rgba(0,0,0,0.65)` overlay. It is atmospheric — not decorative wallpaper.

### Project Cards
Each card displays:
- App name
- Platform badge: **Android / iOS / Web / Desktop**
- Issue count with a severity dot (color-coded by worst severity)
- Last scan timestamp

### Layout
```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   Your Projects                    [+ New Project]  │
│                                                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │ BankApp.apk │ │ MyApp.ipa   │ │ webapp.com  │   │
│  │ Android     │ │ iOS         │ │ Web         │   │
│  │ ● 14 issues │ │ ✓ Clean     │ │ ⏳ Scanning │   │
│  │ 2h ago      │ │ Yesterday   │ │ Running...  │   │
│  └─────────────┘ └─────────────┘ └─────────────┘   │
│                                                     │
│  ┌─────────────┐ ┌──────────────────────────────┐   │
│  │ + New       │ │  Drop file anywhere to start  │   │
│  │   Project   │ │  APK · IPA · EXE · URL        │   │
│  └─────────────┘ └──────────────────────────────┘   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Drop Zone
- Persistent across the entire Projects page — drag an APK, IPA, EXE, or URL anywhere to immediately begin a new project.
- No buried "Add File" button. The drop zone is the file-add action.
- Clicking a project card navigates directly to that project's Dashboard.

---

## Phase 3 — Screen 2: New Scan
**Goal:** Configure and initiate a scan. Launched by dropping a file or clicking `+ New Project`.

### Presentation
- Full-screen modal overlay on dark surface.
- Clean, minimal form. No clutter.

### Layout
```
┌──────────────────────────────────────────────────────┐
│                                          [✕ Cancel]  │
│                                                      │
│   New Scan                                           │
│                                                      │
│   Target                                             │
│   ┌────────────────────────────────────────────┐     │
│   │  📦 BankApp-v2.3.apk          [Change]     │     │
│   └────────────────────────────────────────────┘     │
│                                                      │
│   Platform    [Android ▾]                            │
│                                                      │
│   Scan Profile                                       │
│   ◉ Full Scan      — All tools, full pipeline        │
│   ○ Quick Scan     — Static only, no device needed   │
│   ○ Runtime Only   — Frida + mitmproxy, device req.  │
│   ○ Custom         — Select tools manually ▾         │
│                                                      │
│   ┌──────────────────────────────────────────────┐   │
│   │  Custom tools (collapsed by default)         │   │
│   │  ☑ APKTool   ☑ JADX   ☑ MobSF              │   │
│   │  ☑ Frida     ☑ mitmproxy   ☐ SBOM           │   │
│   └──────────────────────────────────────────────┘   │
│                                                      │
│   Project name   [BankApp v2.3          ]            │
│                                                      │
│                            [Begin Scan →]            │
└──────────────────────────────────────────────────────┘
```

### Scan Profiles
- **Full Scan** — All tools, full pipeline. The default for most developers.
- **Quick Scan** — Static analysis only. No physical device needed.
- **Runtime Only** — Frida + mitmproxy. Physical device required. Triggers Pre-flight check before starting.
- **Custom** — Reveals individual tool checkboxes (APKTool, JADX, MobSF, Frida, mitmproxy, SBOM). Power-user mode, no friction for the 90% case.

---

## Phase 4 — Screen 3: Live Scan View
**Goal:** Real-time scan progress. This is the screen that builds trust.

### Design Principle
Findings appear as they are discovered — not after the full scan completes. The wait must feel productive. The developer can already start thinking before the scan finishes.

### Layout
```
┌─────────────────────────────────────────────────────┐
│  BankApp v2.3  —  Android  —  Full Scan             │
│                                                     │
│  ████████████████████░░░░░░░░░░  67%   ~2 min left  │
│                                                     │
│  Pipeline                                           │
│  ✓  APKTool       Unpacked in 1.2s                  │
│  ✓  JADX          Decompiled 847 classes            │
│  ⟳  MobSF         Running static analysis...        │
│  ○  Frida         Waiting for device                │
│  ○  mitmproxy     Queued                            │
│  ○  AI Analysis   Queued                            │
│                                                     │
│  Live findings                                      │
│  ┌───────────────────────────────────────────────┐  │
│  │ 🔴 Hardcoded API key — com.bank.auth.Config   │  │
│  │ 🟠 Cleartext HTTP — api.legacy.bank.com       │  │
│  │ 🟡 Exported Activity — .LoginActivity         │  │
│  │ 🔴 Debuggable flag enabled in manifest        │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  [Cancel Scan]              [View Full Results →]   │
└─────────────────────────────────────────────────────┘
```

### Pipeline Stages (Android)

| Stage           | Tool               | What It Does                       |
|-----------------|--------------------|------------------------------------|
| Unpack          | APKTool            | Decompile APK to smali + manifest  |
| Decompile       | JADX               | Smali → readable Java              |
| Static analysis | MobSF API          | Automated deep scan                |
| Runtime         | Frida              | Hook live process, intercept calls |
| Network         | mitmproxy          | Capture all HTTP/S traffic         |

- Each stage shows: ✓ complete with elapsed time, ⟳ in progress with live status text, ○ queued.
- Live findings stream in in real time, color-coded by severity dot.
- `[View Full Results →]` becomes active once the scan is complete.

---

## Phase 5 — Screen 4: Runtime Pre-flight (Runtime Scans Only)
**Goal:** When the dev selects the Runtime scan profile, Irves does not start immediately. It shows a pre-flight checklist so the developer knows exactly what is missing before anything attempts and fails silently.

### Layout
```
Runtime Pre-flight
✓  Device detected — Pixel 7 via USB
✓  ADB authorized
✓  App installed — com.bank.app found
✗  App not running — Launch it manually then continue
○  Frida server — Installing on device...

[Continue when ready →]
```

- Each condition is clearly ✓ passed, ✗ failed (with plain-language instruction), or ○ in-progress.
- `[Continue when ready →]` activates only when all conditions are met.
- This transparency makes Runtime mode trustworthy rather than frustrating.

---

## Phase 6 — Screen 5: Runtime Workspace
**Goal:** An interactive environment for live Frida analysis sessions.

### Layout
```
┌─────────────────────────────────────────────────────┐
│  Runtime Workspace  ·  BankApp v2.3                 │
│                                                     │
│  Device         Pixel 7 · USB · Connected ●        │
│  Process        com.bank.app (PID 4821) · Running   │
│                                                     │
│  ┌─ Active Hooks ────────────────────────────────┐  │
│  │  ● SSL_verify  →  bypassed                    │  │
│  │  ● RootCheck   →  intercepted                 │  │
│  │  ● AES.encrypt →  watching                    │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌─ Live Output ─────────────────────────────────┐  │
│  │  [timestamp] RootCheck called → returning false│  │
│  │  [timestamp] AES key: 3a9f...c2               │  │
│  │  [timestamp] HTTP POST → api.bank.com/login   │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌─ Script Editor ───────────────────────────────┐  │
│  │  Java.perform(function() {                    │  │
│  │    var RootCheck = Java.use(                  │  │
│  │      "com.bank.security.RootDetection");      │  │
│  │    RootCheck.isRooted.implementation =        │  │
│  │      function() { return false; }             │  │
│  │  });                                          │  │
│  └───────────────────────────────────────────────┘  │
│  [Run Script]  [Save Hook]  [Clear Output]          │
└─────────────────────────────────────────────────────┘
```

### Two Levels of Frida in Irves

**Level 1 — Guided Hooks (for most developers)**
Irves ships with pre-written Frida scripts for common tasks:
- SSL bypass
- Root detection bypass
- Crypto key capture
- Network interception

The developer selects from a menu, clicks inject, Irves handles the script. No Frida knowledge required.

**Level 2 — Script Editor (for researchers)**
Raw editor inside the Runtime Workspace. Write custom hooks, run them live, see the output stream in real time. Full Frida power with no abstraction. This is researcher mode. The script editor uses **JetBrains Mono** font for full terminal authenticity.

The Live Output panel streams all Frida intercepts, with timestamps, in real time. `[Clear Output]` resets the stream. `[Save Hook]` persists a script into the guided hooks library for future use.

---

## Phase 7 — Screen 6: Dashboard
**Goal:** The unified findings view for a completed scan across all tools and scan modes.

### Layout
```
┌─────────────────────────────────────────────────────┐
│  BankApp v2.3  ·  Android  ·  Scanned 2h ago       │
│  [Re-scan]  [Export Report]  [Share]                │
│                                                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │
│  │   4    │ │   9    │ │   7    │ │   3    │       │
│  │Critical│ │  High  │ │ Medium │ │  Low   │       │
│  └────────┘ └────────┘ └────────┘ └────────┘       │
│                                                     │
│  ┌──────────────────────┐ ┌────────────────────┐   │
│  │  Distribution        │ │  By Category       │   │
│  │   [Pie chart]        │ │  [Bar chart]       │   │
│  │  Static vs Runtime   │ │  OWASP categories  │   │
│  └──────────────────────┘ └────────────────────┘   │
│                                                     │
│  ┌────────────────────────────────────────────────┐ │
│  │  Findings                          [Filter ▾]  │ │
│  │                                                │ │
│  │  🔴 CRIT  Hardcoded Firebase key              │ │
│  │           com.bank.auth.Config:47  →           │ │
│  │  🔴 CRIT  Debuggable manifest flag            │ │
│  │           AndroidManifest.xml      →           │ │
│  │  🟠 HIGH  Cleartext HTTP traffic              │ │
│  │           api.legacy.bank.com      →           │ │
│  │  🟠 HIGH  No certificate pinning              │ │
│  │           OkHttpClient.java:112    →           │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

- Summary severity cards at the top (Critical / High / Medium / Low) using their respective colors from the design system.
- Two charts: pie chart (Static vs Runtime distribution), bar chart (findings by OWASP category).
- Findings table is sortable by severity (default), filterable by tool, category, OWASP mapping, and severity.
- Each finding row has a `→` arrow indicating more detail is available. Clicking navigates to Finding Detail.

---

## Phase 8 — Screen 7: Finding Detail (The AI Screen)
**Goal:** The screen that separates Irves from every competitor. Per-finding deep analysis powered by the AI reasoning layer.

### Layout
```
┌─────────────────────────────────────────────────────┐
│  ← Back to Dashboard                               │
│                                                     │
│  🔴 CRITICAL                                        │
│  Hardcoded Firebase API Key                         │
│                                                     │
│  Location   com.bank.auth.Config · line 47          │
│  Detected   JADX static analysis                    │
│  OWASP      M9 — Insecure Data Storage              │
│                                                     │
│  ┌─ Code ─────────────────────────────────────┐    │
│  │  private static final String API_KEY =     │    │
│  │    "AIzaSyD3x...k9mP";    ← flagged        │    │
│  └────────────────────────────────────────────┘    │
│                                                     │
│  ┌─ Irves Analysis ───────────────────────────┐    │
│  │                                            │    │
│  │  This key grants write access to your      │    │
│  │  Firebase Realtime Database. Any user      │    │
│  │  who installs this APK can extract it      │    │
│  │  with a single JADX decompile — no         │    │
│  │  special knowledge required.               │    │
│  │                                            │    │
│  │  Attack path:                              │    │
│  │  1. Attacker downloads APK from Play Store │    │
│  │  2. Runs JADX (free, 2 minutes)            │    │
│  │  3. Searches for "AIzaSy" string prefix    │    │
│  │  4. Uses key to read/write your database   │    │
│  │                                            │    │
│  │  Fix: Move key to server-side. Use         │    │
│  │  Firebase App Check for client auth.       │    │
│  │  Never embed secrets in client code.       │    │
│  └────────────────────────────────────────────┘    │
│                                                     │
│  ┌─ Ask Irves ────────────────────────────────┐    │
│  │  How do I implement Firebase App Check?  → │    │
│  └────────────────────────────────────────────┘    │
│                                                     │
│  [Mark Resolved]  [Ignore]  [Export Finding]       │
└─────────────────────────────────────────────────────┘
```

### Metadata Block
- Finding title, severity badge (severity color from design system)
- Location: file path + line number
- Detected by: which tool surfaced this finding
- OWASP mapping: MASVS category or Top 10 category

### Code Block
The raw flagged code rendered in **JetBrains Mono** with the flagged line clearly indicated. This is not a diff view — it is the exact snippet in context.

### Irves Analysis Block (`/analysis/ai`)
This is the AI reasoning layer made visible. **Not a chatbot. Not a generic disclaimer.** A direct, plain-language explanation written specifically for this finding — including:
- What the vulnerability is
- Why it is dangerous
- The exact attack path (numbered, concrete, realistic)
- The fix (specific, actionable, not vague)

This block is generated per-finding from the AI reasoning layer and is the core intelligence product of Irves.

### Ask Irves
A single-line prompt at the bottom of the screen. Opens a contextual AI chat anchored to this specific finding. The developer asks follow-up questions without leaving the screen. The chat context is always the current finding — it never drifts into generic security advice.

### Actions
- `[Mark Resolved]` — flags the finding as addressed
- `[Ignore]` — suppresses the finding with an optional reason
- `[Export Finding]` — exports the finding as a standalone report

---

## Phase 9 — Screen 8: Reports
**Goal:** Generate enterprise-grade, auditable compliance reports in multiple formats.

### Layout
```
┌─────────────────────────────────────────────────────┐
│  Reports  ·  BankApp v2.3                           │
│                                                     │
│  ┌─ Generate Report ───────────────────────────┐   │
│  │                                             │   │
│  │  Template                                   │   │
│  │  ◉ OWASP MASVS        — Mobile standard     │   │
│  │  ○ OWASP Top 10       — Web standard        │   │
│  │  ○ SBOM               — Dependency bill     │   │
│  │  ○ Privacy Audit      — Data flow report    │   │
│  │  ○ Executive Summary  — Non-technical       │   │
│  │  ○ Custom             — Build your own      │   │
│  │                                             │   │
│  │  Format   [PDF ▾]    [Markdown]  [JSON]     │   │
│  │  Scope    ◉ Full project  ○ Selected findings│  │
│  │                                             │   │
│  │                    [Generate Report →]      │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  Past Reports                                       │
│  ┌───────────────────────────────────────────────┐  │
│  │  OWASP MASVS  ·  BankApp v2.3  ·  2h ago  ↓  │  │
│  │  Privacy Audit · BankApp v2.3  ·  Yesterday ↓ │  │
│  │  SBOM  ·  MyApp v1.0  ·  3 days ago       ↓  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Report Templates

**OWASP MASVS Report** (Mobile)
Maps every finding to its MASVS control category. Pass/fail compliance document. Accepted directly by auditors, app store reviewers, and enterprise procurement teams.
```
MASVS-STORAGE-1   Insecure Data Storage     FAIL  3 findings
MASVS-CRYPTO-1    Weak Cryptography         PASS
MASVS-NETWORK-1   Secure Communication      FAIL  2 findings
MASVS-AUTH-1      Authentication            PASS
```

**OWASP Top 10 Report** (Web)
Same pass/fail structure but mapped to web categories (Injection, Broken Auth, SSRF, etc.). Used when Irves scanned a web target via ZAP / Nuclei.

**SBOM — Software Bill of Materials**
Lists every dependency found inside the app — libraries, SDKs, frameworks — with version numbers and known CVEs. Enterprise buyers increasingly require this before approving third-party apps.
```
Library              Version   License    CVEs
okhttp               3.12.0    Apache 2   CVE-2021-0341 (HIGH)
firebase-auth        21.0.1    Apache 2   None
openssl              1.0.2k    OpenSSL    CVE-2019-1543 (MEDIUM)
com.facebook.sdk     12.1.0    Facebook   None
```

**Privacy Audit Report**
Data flow focused. Shows what personal data the app collects, where it sends it, and whether it is disclosed and encrypted properly. Feeds GDPR/CCPA compliance evidence, privacy teams, legal teams, and app store privacy labels.
```
Data Type        Collected   Transmitted To        Encrypted
Location         Yes         analytics.firebase    Yes
Device ID        Yes         graph.facebook.com    Yes
Contacts         Yes         api.bankapp.com       NO ←
Email            Yes         mailchimp.com         Yes
```

**Executive Summary**
Non-technical. Plain language. No code snippets, no CVE IDs, no OWASP categories. What a CTO, product manager, or client reads. No security knowledge required.
```
Overall Risk: HIGH

BankApp v2.3 contains 4 critical vulnerabilities that expose
user data and allow unauthorized access. Immediate action
required before release.

Top 3 Issues:
1. API key embedded in app code — exploitable in minutes
2. User data transmitted without encryption
3. App can be debugged by third parties

Estimated fix time: 3–5 days
```

**Custom Report**
Drag-and-drop builder. Developer picks which sections to include, reorders them, adds their own branding (logo, company name). For consultants delivering reports to clients under their own name.

### Export Formats
| Format       | Use Case                                                                |
|--------------|-------------------------------------------------------------------------|
| **PDF**      | Formatted, printable, signable. Default for compliance delivery.        |
| **Markdown** | Drops into GitHub wikis, Notion, Confluence. Developer-native.          |
| **JSON**     | Machine-readable. Feeds CI/CD pipelines and ticketing systems like Jira.|
| **HTML**     | Self-contained report. Opens in any browser, shareable without tooling. |

### Scan Fingerprint
Every report includes a scan fingerprint at the bottom:
- Timestamp of scan
- Tool versions used
- Scan profile selected
- Device info (if runtime was involved)

This makes reports reproducible and auditable. An auditor can review a report from 6 months ago and know exactly what was run and how.

---

## Phase 10 — Settings
**Goal:** Tool configuration, device profiles, and credential management. Not a feature dumping ground.

### Sections
- **Tools** — Paths or auto-detection for APKTool, JADX, Frida, mitmproxy, MobSF, ZAP, Nuclei, Ghidra. Health-check indicators showing which tools are installed and ready.
- **Scan Profiles** — Save and edit custom scan profiles beyond the four built-in ones.
- **Device Config** — ADB device management, Frida server install helpers.
- **AI** — API key configuration for the AI reasoning layer. Model selection if applicable.
- **Appearance** — Theme settings (dark only by design, but density or font size controls may live here).

---

## FastAPI Endpoint Map

| Endpoint             | Tools Invoked                        | Purpose                                |
|----------------------|--------------------------------------|----------------------------------------|
| `/scan/android`      | APKTool, JADX, MobSF API, Frida, mitmproxy | Android full pipeline          |
| `/scan/ios`          | class-dump, otool, Frida             | iOS analysis pipeline                  |
| `/scan/desktop`      | Ghidra headless, Frida               | Win/Mac/Linux binary analysis          |
| `/scan/web`          | ZAP, Nuclei                          | HTTP target dynamic analysis           |
| `/analysis/ai`       | LLM reasoning layer                  | Per-finding explanation + attack path  |
| `/report/owasp`      | Internal mapper                      | MASVS / Top 10 compliance output       |
| `/report/sbom`       | Dependency extractor                 | Library inventory + CVE mapping        |
| `/report/privacy`    | Data flow analyzer                   | Privacy data collection audit          |

---

## Summary of Screens

| Screen               | Phase | Description                                              |
|----------------------|-------|----------------------------------------------------------|
| Projects (Home)      | 2     | Project grid with mountain background, drop zone         |
| New Scan             | 3     | Modal: target, platform, scan profile, tool selection    |
| Live Scan View       | 4     | Real-time pipeline progress + streaming findings         |
| Runtime Pre-flight   | 5     | Device/ADB/Frida readiness checklist before runtime scan |
| Runtime Workspace    | 6     | Frida hooks manager, live output stream, script editor   |
| Dashboard            | 7     | Unified findings, severity cards, charts, filterable list|
| Finding Detail       | 8     | AI analysis, attack path, fix guidance, Ask Irves chat   |
| Reports              | 9     | Template picker, format selector, past reports list      |
| Settings             | 10    | Tools, devices, AI, scan profiles                        |
