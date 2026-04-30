
IRVES

Irves: Intelligent Security Research Platform

*A desktop-native security analysis platform that unifies static analysis, dynamic instrumentation,*
*network interception, and AI-powered reasoning into a single, coherent interface — aligned with*
*OWASP MASVS, OWASP Top 10, and CWE standards.*



---

 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running](#running)
  - [Docker Deployment](#docker-deployment)
  - [Advanced Deployment](#advanced-deployment)
- [Screens & Workflows](#screens--workflows)
- [AI Intelligence Engine](#ai-intelligence-engine)
- [Supported Platforms](#supported-platforms)
- [Report Templates](#report-templates)
- [Security Tools Integration](#security-tools-integration)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

 Overview

IRVES replaces fragmented security toolchains — multiple disjointed tools for static analysis, dynamic testing, and network interception — with a **single unified platform** where every tool feeds into one database, one dashboard, and one AI reasoning layer.

Whether you are performing a penetration test on an Android APK, auditing a Git repository for secrets and architectural debt, or intercepting live network traffic from a target application, IRVES provides a consistent, context-aware workspace across the entire assessment lifecycle.

---

## Key Features

### 🔍 Static Application Security Testing (SAST)
- **Binary Analysis** — APK decompilation via APKTool & JADX, iOS IPA parsing, desktop binary inspection
- **Source Code Analysis** — 8-category deep audit: Architecture, Scalability, Code Quality, Security, Dependencies, Secrets, Technical Debt & Contributor Risk
- **AST Engine** — Abstract Syntax Tree–based semantic code analysis for precise vulnerability detection
- **Dependency Scanning** — Automated CVE matching against known vulnerability databases

### ⚡ Dynamic Application Security Testing (DAST)
- **Frida Integration** — Full runtime instrumentation with hook injection, SSL pinning bypass, root detection bypass, and stealth cloaking (Zymbiote)
- **Network Interception** — Built-in mitmproxy with real-time WebSocket streaming of HTTP/S traffic
- **eBPF Probes** — Kernel-level syscall tracing for packer detection (`memfd_create`, `mmap` events)
- **MTE (Memory Tagging Extension)** — Hardware-based memory corruption detection with surgical precision (`SEGV_MTESERR` fault analysis)

### 🧠 AI Intelligence Engine
- **Provider-Agnostic** — Supports Anthropic, OpenAI, Google Gemini, xAI, DeepSeek, Together AI, HuggingFace, and local models (Ollama / vLLM)
- **Context-Aware Chat** — Screen-aware AI assistant that adapts to the user's current workspace (dashboard, finding detail, runtime, network intercept)
- **Three-Module Architecture** — Parsing → Reasoning → Generation pipeline with cost tracking
- **Agentic Execution** — AI can directly inject Frida hooks and execute security operations from the chat interface
- **Finding Enhancement** — Every vulnerability is enriched with AI-generated attack paths, exploitability assessments, and fix guidance

### 📊 Compliance & Reporting
- **OWASP MASVS** — Mobile Application Security Verification Standard compliance matrices
- **OWASP Top 10** — Web application vulnerability classification and mapping
- **CWE Mapping** — Common Weakness Enumeration cross-referencing for every finding
- **Executive Reports** — PDF/HTML/Markdown/JSON reports with severity distributions and remediation priorities
- **SBOM Generation** — Software Bill of Materials for dependency auditing
- **Privacy Impact Reports** — Data handling and privacy compliance documentation

### 🔗 Git Integration
- **GitHub & GitLab OAuth** — One-click repository connection with OAuth 2.0 flow
- **Repository Scanning** — Clone, branch-select, and run full SAST pipelines on source repositories
- **Cross-Phase Correlation** — Correlate static findings with runtime behavior for validated exploitability

---

## Getting Started

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.12+ | Core backend runtime |
| Rust | Latest stable (via `rustup`) | Required for Tauri desktop shell |
| Node.js | 20+ | Tauri CLI and build toolchain |
| Frida | 16+ | *Included* — bundled with IRVES for runtime instrumentation |
| mitmproxy | 10+ | *Included* — bundled with IRVES for network interception |
| APKTool | 2.9+ | *Included* — bundled with IRVES for APK decompilation |
| JADX | 1.5+ | *Included* — bundled with IRVES for DEX-to-Java decompilation |

### Installation

**One-command install (Linux / macOS):**

```bash
git clone https://github.com/Oyut11/Irves-Intelligent-security-research-platform.git
cd Irves-Intelligent-security-research-platform
bash install.sh
```

**One-command install (Windows — PowerShell as Administrator):**

```powershell
git clone https://github.com/Oyut11/Irves-Intelligent-security-research-platform.git
cd Irves-Intelligent-security-research-platform
Set-ExecutionPolicy -Scope Process Bypass; .\install.ps1
```

The installer handles everything:
- ✅ Java JDK 21 (if missing)
- ✅ Python 3.12+ (if missing)
- ✅ Virtual environment & Python packages (Frida, mitmproxy, androguard, …)
- ✅ APKTool 2.9.3
- ✅ JADX 1.5.5
- ✅ PATH configuration

**Manual installation — Backend (web server):**

```bash
git clone https://github.com/Oyut11/Irves-Intelligent-security-research-platform.git
cd Irves-Intelligent-security-research-platform/backend

# Create environment config and generate SECRET_KEY (required for startup)
cp .env.example .env
python generate_secret.py  # Copy output into .env as SECRET_KEY=...

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python setup_tools.py  # Installs APKTool + JADX
source ~/.bashrc
cd .. && python backend/main.py
```

**Manual installation — Desktop app (optional):**

If you want the native desktop shell (Tauri) instead of using a browser:

```bash
cd Irves-Intelligent-security-research-platform
npm install           # Tauri build toolchain
npm run build         # Compile desktop installer
```

### Quick Start (Docker)

The fastest way to run IRVES without installing dependencies locally:

```bash
docker pull ghcr.io/oyut11/irves-intelligent-security-research-platform:main

# Run directly (configure AI provider in Settings after launch)
docker run -d -p 8765:8765 \
  -e HOST=0.0.0.0 \
  -e SECRET_KEY=$(openssl rand -hex 32) \
  ghcr.io/oyut11/irves-intelligent-security-research-platform:main
```

Or use Docker Compose:

```bash
git clone https://github.com/Oyut11/Irves-Intelligent-security-research-platform.git
cd Irves-Intelligent-security-research-platform
cp .env.docker.example .env
docker compose up -d
```

→ http://localhost:8765

### Configuration

Copy the example environment file and fill in your values:

```bash
cp backend/.env.example backend/.env
```

**Required:**

| Variable | Description |
|---|---|
| `SECRET_KEY` | Required. Secure random string for OAuth session encryption. Generate with: `python backend/generate_secret.py` |

**Recommended:**

| Variable | Description |
|---|---|
| `AI_API_KEY` | Generic API key for any supported AI provider |
| `AI_MODEL` | Provider/model format (e.g. `anthropic/claude-3-5-sonnet`, `openai/gpt-4o`, `ollama/llama3`) |
| `GITHUB_CLIENT_ID` | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth App client secret |

> [!TIP]
> IRVES supports hot-switching AI providers at runtime via th\e Settings screen. You can configure API keys for Anthropic, OpenAI, Gemini, xAI, DeepSeek, Together AI, HuggingFace, or point to a local Ollama instance — all without restarting the application.

### Running

**Backend only** (recommended for development):

```bash
cd backend
source .venv/bin/activate
python main.py
# → http://localhost:8765
```

**Full Tauri desktop application** (backend auto-spawned):

```bash
npm run dev
```

**Production build:**

```bash
npm run build
```

### Docker Deployment

IRVES can be deployed using Docker for a consistent, containerized environment.

**Quick start with Docker Compose:**

```bash
# Clone and navigate
git clone https://github.com/Oyut11/Irves-Intelligent-security-research-platform.git
cd Irves-Intelligent-security-research-platform

# Configure environment
cp .env.docker.example .env
# Edit .env and set at least SECRET_KEY and ANTHROPIC_API_KEY

# Start with PostgreSQL (recommended for production)
docker compose up -d

# Or start with SQLite (simpler, single-file database)
# Edit .env: DATABASE_URL=sqlite+aiosqlite:///./irves.db
# Comment out postgres service in docker-compose.yml
docker compose up -d
```

**Access:** http://localhost:8765

**Docker Compose services:**
- `irves` — Main application with Java, APKTool, JADX, Python dependencies
- `postgres` — PostgreSQL database (optional, can use SQLite instead)

**Volumes:**
- `irves-projects` — Project data persistence
- `irves-reports` — Report output persistence
- `postgres-data` — Database persistence (if using PostgreSQL)

**Build from source:**

```bash
docker build -t irves:latest .
docker run -d -p 8765:8765 \
  -e HOST=0.0.0.0 \
  -e SECRET_KEY=$(python backend/generate_secret.py) \
  -v irves-projects:/app/.irves/projects \
  -v irves-reports:/app/.irves/reports \
  irves:latest
```


## Screens & Workflows

| Screen | Route | Purpose |
|---|---|---|
| **Projects** | `/` | Project dashboard — create, list, and manage security analysis projects |
| **New Scan** | `/scan` | Configure and launch scans (profile selection, tool picker, target upload) |
| **Live Scan** | `/live-scan` | Real-time scan progress with tool-by-tool status and live finding stream |
| **Dashboard** | `/dashboard` | Findings overview — severity distribution, category breakdown, finding list |
| **Finding Detail** | `/findings/{id}` | Deep-dive into a vulnerability with AI analysis, attack paths, and fix guidance |
| **Runtime Workspace** | `/runtime` | Frida session management — hook injection, script console, live output |
| **Network Intercept** | `/network` | mitmproxy traffic viewer — request/response inspection, security analysis |
| **Source Analysis** | `/source-analysis` | 8-category source code audit with per-category drill-down reports |
| **Repository Scan** | (via New Scan) | GitHub/GitLab repository connection with branch selection |
| **Reports** | `/reports` | Generate and download compliance reports (MASVS, Executive, SBOM, Privacy) |
| **Settings** | `/settings` | AI provider configuration, tool paths, MobSF connection, Git OAuth |

---

## AI Intelligence Engine

The AI subsystem is designed as a **context-aware security copilot** that adapts its behavior based on which screen the user is viewing and what data is available.

### Contextual Modes

| Mode | Trigger | Behavior |
|---|---|---|
| **Finding Analysis** | Viewing a specific finding | Explains root cause, maps attack path, provides platform-idiomatic fix |
| **Project Summary** | Dashboard view | Executive risk posture, top 3 priorities, architectural risk patterns |
| **Runtime Workspace** | Frida session active | Generates hooks, interprets output, pivots on failure with self-healing |
| **Network Intercept** | Viewing intercepted traffic | Identifies data leakage, suggests fuzzing payloads, OWASP API Top 10 |
| **Source Analysis** | Reviewing code audit results | References specific files/lines, prioritizes by severity, explains context |
| **Runtime Orchestration** | Multi-source telemetry active | Correlates eBPF + MTE + Frida events for packer and corruption detection |

### Provider Support

Configure any provider via the Settings screen or environment variables:

| Provider | Model Examples | Key Variable |
|---|---|---|
| Anthropic | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` |
| OpenAI | `gpt-4o`, `o1-preview` | `OPENAI_API_KEY` |
| Google | `gemini-2.5-pro` | `GEMINI_API_KEY` |
| xAI | `grok-3` | `XAI_API_KEY` |
| DeepSeek | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| Together AI | `meta-llama/Meta-Llama-3.1-405B` | `TOGETHER_AI_API_KEY` |
| Ollama (local) | `llama3`, `codestral` | Set `AI_API_BASE` to your Ollama URL |

---

## Supported Platforms

IRVES can analyze targets across the following platforms:

| Platform | Binary Analysis | Source Analysis | Runtime Instrumentation | Network Interception |
|---|---|---|---|---|
| **Android** | ✅ APK / AAB | ✅ Java / Kotlin | ✅ Frida + eBPF + MTE | ✅ mitmproxy |
| **iOS** | ✅ IPA | ✅ Swift / Obj-C | ✅ Frida | ✅ mitmproxy |
| **Web** | — | ✅ Full stack | — | ✅ mitmproxy |
| **Desktop** | ✅ ELF / PE / Mach-O | ✅ Any language | ✅ Frida | ✅ mitmproxy |
| **Git Repository** | — | ✅ 8-category audit | — | — |

---

## Report Templates

| Template | Format | Description |
|---|---|---|
| **Executive** | PDF / HTML | High-level risk summary for stakeholders and management |
| **MASVS** | PDF / HTML | OWASP Mobile Application Security Verification Standard compliance matrix |
| **SBOM** | JSON / HTML | Software Bill of Materials — full dependency inventory |
| **Privacy** | PDF / HTML | Data handling assessment and privacy impact documentation |

---

## Security Tools Integration

IRVES orchestrates the following external security tools. Check tool availability at runtime via `GET /api/tools/status`.

| Tool | Purpose | Platform | Category | Prerequisites |
|---|---|---|---|---|
| [APKTool](https://apktool.org/) | Full APK decode — smali code, resources & AndroidManifest.xml | Android | Static | — |
| [JADX](https://github.com/skylot/jadx) | Decompile DEX bytecode to readable Java source code | Android | Static | — |
| [Frida](https://frida.re/) | Runtime process instrumentation & hook injection (SSL pinning bypass, root detection bypass, debugger bypass) | Android, iOS | Dynamic | Connected device + `frida-server` running on target |
| [mitmproxy](https://mitmproxy.org/) | HTTP/HTTPS traffic capture, flow analysis & sensitive data detection | Android, iOS, Web | Dynamic | — |

**Scan profiles** select which tools to run automatically:

| Profile | Tools |
|---|---|
| `quick` | APKTool + JADX |
| `full` | APKTool + JADX + Frida + mitmproxy |
| `runtime` | Frida + mitmproxy |
| `custom` | User-selected |

> [!NOTE]
> No external tools are required for source code analysis of Git repositories. The built-in analysis engine handles Architecture, Scalability, Code Quality, Security, Dependencies, Secrets, Technical Debt, and Contributor Risk categories natively.

---

## Documentation

For detailed technical documentation, see:

- **[Architecture](docs/architecture.md)** — System overview, data flow, database schema, and component breakdown
- **[API Documentation](docs/api.md)** — REST endpoints, WebSocket connections, and usage examples
- **[Roadmap](ROADMAP.md)** — Planned features, release timeline, and community contribution opportunities

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup instructions
- Code style guidelines (Python PEP 8, Rust `rustfmt`, CSS design system)
- Pull request workflow
- Issue reporting guidelines

---

## License

IRVES is licensed under the [GNU General Public License v3.0](LICENSE).

```
Copyright (C) 2026 IRVES

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

---
