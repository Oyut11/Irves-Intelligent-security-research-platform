# IRVES v1.0 Launch Checklist

This is the comprehensive tracking plan to take IRVES from its current late-stage development environment to a production-ready v1.0 release.

## 1. 🧠 AI Reasoning Layer (Intelligence Integration)
*The UI is fully wired. This phase connects the backend to the LLM for real intelligence.*
- [x] **Multi-Provider AI Service:** Implement `services/ai_service.py` as a router capable of dynamically connecting to multiple AI endpoints, including:
  - Commercial APIs: OpenAI (ChatGPT), Anthropic (Claude), Google (Gemini), xAI, Deepseek.
  - Open Source / Cloud Inference: Together AI, Hugging Face.
  - Local & Offline Inference: Ollama and local standalone AI models.
- [x] **Data Formatting:** Create a prompt abstraction layer that injects raw code snippets, finding locations, and JADX metadata into the LLM prompt.
- [x] **Dashboard AI Partner:** Implement the `POST /api/analysis/project-summary` endpoint to read all project findings and stream a high-level executive vulnerability summary back to the Dashboard Drawer.
- [x] **Finding Deep Dive:** Implement the `POST /api/analysis/finding-detail` to generate the "Attack Path" and "Actionable Fix" sections dynamically.
- [x] **Ask Irves Chat:** Implement the conversational endpoint for follow-up questions, ensuring the context strictly limits the LLM to the security finding at hand.

## 2. 📄 Report Generation Engine (Compliance)
*Translating database findings into tangible compliance artifacts for enterprise auditors.*
- [x] **Template Engine:** Build the internal data-mapper to translate IRVES findings into the OWASP MASVS standard categories.
- [x] **Markdown Generator:** Implement a programmatic Markdown builder for GitHub Wiki/Notion compatible exports (`GET /api/report/markdown`).
- [x] **PDF Generator:** Integrate a library (like ReportLab or WeasyPrint) to render the Jinja2 report templates into styled, signable PDFs.
- [x] **SBOM Integration:** Hook into the project manifests (e.g., Gradle, npm) during static analysis phase to extract dependencies and output standard SBOM JSON.
- [x] **Executive Summary:** Implement a non-technical summary report template meant for C-suite readability.

## 3. ⚙️ Tool Dependency Management 
*Ensuring a frictionless onboarding experience for new analysts.*
- [x] **Health Endpoint Finalization:** Fully wire the `/api/tools/status` endpoint to verify binaries in real-time.
- [x] **Auto-Provisioning Script:** Build a Python bootstrapper (`setup_tools.py`) that automatically downloads, extracts, and adds APKTool, JADX, and Frida-tools to the local environment path.
- [x] **Device Sync Automation:** Add a helper to automatically push the correct `frida-server` binary to connected Android devices based on CPU architecture (`arm64`, `x86`).

## 4. 📱 Multi-Platform Pipeline Expansion
*Branching out from the stabilized Android pipeline.*
- [x] **iOS Extraction:** Add support for `.ipa` unzipping and binary parsing using `otool`/`strings` and Info.plist inspection (`ios_analyzer.py`).
- [x] **iOS Frida Profiling:** Frida `attach()` logic already covers USB-connected jailbroken iOS devices via the frida-tools bridge; the deploy_server helper now correctly targets non-Android devices too.
- [x] **Web Targets:** Integrated Nuclei into `web_analyzer.py` as an async subprocess runner with graceful fallback to passive header analysis if Nuclei is not installed.
- [x] **Desktop Binaries:** Implemented `desktop_analyzer.py` with SHA-256 fingerprinting, strings-based vulnerability pattern scanning, format detection (PE/ELF/Mach-O) and optional Ghidra headless integration.

## 5. 🛡️ Hardening, Testing & QA
*Final polish before release.*
- [x] **Cross-Device Testing:** Frida service `_resolve_device()` updated with 3-attempt retry + ADB serial fallback, backporting support for Android 10-12 device detection patterns.
- [x] **Large APK Handling:** 150 MB guard added to `apk_analyzer.py` — Androguard (the memory-intensive stage) is skipped for oversized APKs, manifest + pattern scans still run.
- [x] **SQLite Concurrency:** `database/connection.py` hardened with `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`, `pool_pre_ping=True`, and a 5s busy timeout to prevent write-lock stalls.
- [x] **Error Boundaries:** All scan stages wrapped in `asyncio.wait_for(timeout=600)`. Network proxy has an exponential-backoff watchdog task that auto-restarts mitmdump up to 3 times before emitting a structured error.
- [x] **Tauri Build:** Platform dispatch in scanner wired through the unified `_run_stage()` dispatcher — IPC boundary between Tauri shell and Python backend is stable and well-defined.
