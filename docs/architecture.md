# IRVES Architecture

## System Overview

IRVES (Intelligent Reverse Engineering & Vulnerability Evaluation System) is a multi-platform security analysis platform with an AI-powered intelligence engine. The system is built as a modular FastAPI backend with a Tauri desktop shell and web interface.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User Interface                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Projects   │  │  New Scan    │  │  Dashboard   │  │  Runtime     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Network    │  │  Source      │  │  Reports     │  │  Settings    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FastAPI Backend                                    │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        API Layer (Routes)                               │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │  │
│  │  │ Projects │ │  Scans   │ │ Findings │ │ Runtime  │ │ Settings │   │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Service Layer                                      │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │  │
│  │  │ Scan Runner  │ │ Tool Runner  │ │ AI Service   │ │ Parser       │ │  │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                 │  │
│  │  │ Correlation  │ │ Report Gen   │ │ AST Engine   │                 │  │
│  │  └──────────────┘ └──────────────┘ └──────────────┘                 │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Data Layer                                         │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                 │  │
│  │  │  Database    │ │  File Store  │ │  Tool Cache  │                 │  │
│  │  │  (SQLite/PG) │ │  (~/.irves)  │ │  (APK/JADX)  │                 │  │
│  │  └──────────────┘ └──────────────┘ └──────────────┘                 │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        External Tools & Services                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ APKTool  │ │   JADX   │ │  Frida   │ │mitmproxy │ │  AI API  │         │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                                     │
│  │  GitHub  │ │  GitLab  │ │  Ollama  │                                     │
│  └──────────┘ └──────────┘ └──────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### Backend (`backend/`)

#### Core Application (`main.py`)
- FastAPI application entry point
- WebSocket server for real-time communication
- CORS configuration
- Static file serving
- Health check endpoint

#### Routes (`routes/`)
- `project_routes.py` — Project CRUD operations
- `scan_routes.py` — Scan creation, execution, status
- `finding_routes.py` — Finding retrieval, filtering, AI analysis
- `runtime_routes.py` — Frida session management, script injection
- `network_routes.py` — mitmproxy traffic streaming
- `source_routes.py` — Source code analysis endpoints
- `settings_routes.py` — Configuration management
- `correlation_routes.py` — Cross-tool finding correlation
- `auth_routes.py` — GitHub/GitLab OAuth

#### Services (`services/`)
- `scan_runner.py` — Orchestrates multi-tool scan execution
- `tool_runner.py` — Base class for tool execution
- `tools/` — Tool-specific runners (APKTool, JADX, Frida, mitmproxy)
- `finding_parser.py` — Parses tool outputs into standardized findings
- `correlation_service.py` — Correlates findings across tools
- `report_generator.py` — Generates compliance reports (MASVS, SBOM, etc.)
- `ai_service.py` — AI chat, real-time pivoting, provider routing

#### AI Modules (`ai_modules/`)
- `parsing_module.py` — Finding parsing with AI
- `cost_tracker.py` — Token usage and cost tracking
- `chat_module.py` — Context-aware chat interface

#### AST Engine (`ast_engine/`)
- `models.py` — AST node models
- `templates.py` — Analysis task templates
- `executor.py` — AST execution engine

#### Parsers (`parsers/`)
- `registry.py` — Parser registration system
- `base.py` — Base parser class
- `mobile/` — Mobile-specific parsers (Frida, APKTool, JADX)
- `web/` — Web security parsers
- `desktop/` — Desktop security parsers

#### Database (`database/`)
- `models.py` — SQLAlchemy ORM models
- `crud.py` — Database operations
- `session.py` — Database session management

### Frontend (`backend/templates/`)

#### Screens (`templates/screens/`)
- `projects.html` — Project dashboard
- `new_scan.html` — Scan configuration
- `live_scan.html` — Real-time scan progress
- `dashboard.html` — Findings overview
- `finding_detail.html` — Deep-dive finding analysis
- `runtime.html` — Frida workspace
- `network.html` — mitmproxy traffic viewer
- `source_analysis.html` — Source code audit
- `reports.html` — Report generation
- `settings.html` — Configuration

#### Components (`templates/components/`)
- Reusable UI components (modals, tables, charts)

### Desktop Shell (Tauri)
- `src-tauri/` — Rust-based desktop application
- Provides native window management
- System tray integration
- Auto-update support

## Data Flow

### Scan Execution Flow

```
User submits scan
    ↓
scan_routes.create_scan()
    ↓
scan_runner.run_scan()
    ↓
For each tool in profile:
    ├─ tool_runner.run()
    ├─ Execute external tool (APKTool, JADX, Frida, etc.)
    ├─ Capture output
    ├─ finding_parser.parse()
    ├─ Store findings in database
    └─ Emit WebSocket update
    ↓
correlation_service.correlate_findings()
    ↓
Generate report (if requested)
    ↓
Return results to UI
```

### AI Chat Flow

```
User sends message
    ↓
ai_service.stream_chat()
    ↓
Determine context (current screen, selected findings)
    ↓
Build system prompt with context
    ↓
Call AI provider (Anthropic, OpenAI, etc.)
    ↓
Stream response via WebSocket
    ↓
Update UI in real-time
```

### Real-Time Frida Error Pivot

```
Frida tool encounters error
    ↓
WebSocket handler detects error
    ↓
Record error in shared buffer
    ↓
Trigger AI pivot generation
    ↓
AI analyzes error and suggests fix
    ↓
Stream pivot response to UI
    ↓
User can auto-inject suggested script
```

## Database Schema

### Core Tables

- `projects` — Project metadata, target info
- `scans` — Scan configuration, status, results
- `findings` — Vulnerability findings with severity, category
- `tools` — Tool execution records
- `ai_chats` — Chat history for context persistence
- `reports` — Generated report metadata

### Relationships

```
projects (1) ──< (N) scans
scans (1) ──< (N) findings
scans (1) ──< (N) tools
projects (1) ──< (N) ai_chats
scans (1) ──< (N) reports
```

## Security Architecture

### Authentication
- GitHub OAuth 2.0
- GitLab OAuth 2.0
- Session-based authentication with SECRET_KEY

### Authorization
- Project-based access control
- User-scoped data isolation

### Data Protection
- API keys stored in environment variables (never in code)
- SECRET_KEY for session encryption
- HTTPS recommended for production

### Tool Isolation
- External tools run in subprocesses
- Output captured and sanitized
- No direct shell access from web interface

## Performance Considerations

### Async Operations
- FastAPI async/await for I/O-bound operations
- WebSocket streaming for real-time updates
- Background tasks for long-running scans

### Caching
- Tool output caching (APK decompilation, JADX results)
- AST execution caching
- AI response caching (optional)

### Database
- SQLite for single-user deployments
- PostgreSQL for multi-user production
- Connection pooling

## Extensibility

### Adding New Tools
1. Create tool runner in `services/tools/`
2. Register in `services/tool_registry.py`
3. Create parser in `parsers/`
4. Add to scan profile configuration

### Adding New AI Providers
1. Add provider to LiteLLM configuration
2. Add API key to `.env.example`
3. Update UI provider selector

### Adding New Report Types
1. Create template in `templates/reports/`
2. Add generator in `services/report_generator.py`
3. Register in report types enum
