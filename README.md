# IRVES — Intelligent Security Tool

> Precise. Minimal. Commanding.

IRVES is a desktop-native security analysis platform for mobile, desktop, and web applications. It integrates static analysis, dynamic instrumentation (Frida), and AI-powered reasoning into a single, coherent interface aligned with OWASP MASVS and OWASP Top 10.

## Stack

| Layer       | Technology                     |
|-------------|--------------------------------|
| Desktop     | Tauri v2 (Rust shell)          |
| Backend     | FastAPI + Python 3.12          |
| UI          | HTMX + Jinja2                  |
| Design      | Vanilla CSS design system      |

## Development Setup

### Prerequisites
- Python 3.12+
- Rust (via rustup)
- Node.js 20+

### 1. Install Python dependencies
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the backend only (for UI development)
```bash
npm run backend
# Open http://localhost:8765

```

### 3. Run full Tauri app (backend auto-spawned)
```bash
npm install
npm run dev
```

## Project Structure

```
Irves/
├── src-tauri/          Tauri Rust shell (spawns backend)
│   ├── src/
│   │   ├── main.rs
│   │   └── lib.rs      Backend process management
│   └── tauri.conf.json
├── backend/            FastAPI Python core
│   ├── main.py         App entry + UI routes
│   ├── routes/         API routers (scan, analysis, reports)
│   ├── templates/      Jinja2 HTML screens
│   │   └── screens/    One file per screen
│   └── static/         CSS, JS, images
├── plan.md             Full implementation plan
└── package.json
```

## Implementation Phases

| Phase | Scope                                    | Status  |
|-------|------------------------------------------|---------|
| 1     | Project scaffold & app shell             | ✅ Done |
| 2     | Static pipeline & live scan view         | Pending |
| 3     | Runtime workspace & Frida                | Pending |
| 4     | AI reasoning layer & dashboard           | Pending |
| 5     | Advanced reporting engine                | Pending |
| 6     | Multi-platform expansion (iOS, desktop, web) | Pending |

## Design System

Colors, typography, and components defined in `backend/static/css/irves.css`.
- **Font UI:** Satoshi
- **Font Mono:** JetBrains Mono
- **Background:** `#0f0f0d`
- **Accent:** `#4f98a3`
