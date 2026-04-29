# IRVES API Documentation

IRVES provides a RESTful API for programmatic access to all security analysis features. The API is built on FastAPI and includes WebSocket endpoints for real-time updates.

**Base URL:** `http://localhost:8765` (or your configured host/port)

**Authentication:** Session-based (via GitHub/GitLab OAuth) or API key (future)

---

## Endpoints

### Health

#### GET /api/health
Health check endpoint for monitoring.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

---

### Projects

#### GET /api/projects
List all projects.

**Response:**
```json
{
  "projects": [
    {
      "id": 1,
      "name": "My App",
      "platform": "android",
      "target": "app.apk",
      "created_at": "2026-04-28T00:00:00Z"
    }
  ]
}
```

#### POST /api/projects
Create a new project.

**Request:**
```json
{
  "name": "My App",
  "platform": "android",
  "target": "app.apk",
  "description": "Optional description"
}
```

**Response:**
```json
{
  "id": 1,
  "name": "My App",
  "platform": "android",
  "target": "app.apk",
  "created_at": "2026-04-28T00:00:00Z"
}
```

#### GET /api/projects/{id}
Get project details.

#### DELETE /api/projects/{id}
Delete a project.

---

### Scans

#### POST /api/scans
Create and start a new scan.

**Request:**
```json
{
  "project_id": 1,
  "profile": "full",
  "tools": ["apktool", "jadx", "frida"],
  "branch": "main"
}
```

**Profiles:** `quick`, `full`, `runtime`, `custom`

**Response:**
```json
{
  "id": 1,
  "project_id": 1,
  "profile": "full",
  "status": "running",
  "created_at": "2026-04-28T00:00:00Z"
}
```

#### GET /api/scans/{id}
Get scan status and results.

**Response:**
```json
{
  "id": 1,
  "status": "completed",
  "progress": 100,
  "tools": [
    {
      "name": "apktool",
      "status": "completed",
      "duration": 15.5
    }
  ],
  "findings_count": 42
}
```

#### GET /api/scans
List all scans (with optional filtering).

**Query Parameters:**
- `project_id` — Filter by project
- `status` — Filter by status (running, completed, failed)
- `limit` — Maximum results (default: 50)

---

### Findings

#### GET /api/findings
List findings with filtering.

**Query Parameters:**
- `scan_id` — Filter by scan
- `severity` — Filter by severity (critical, high, medium, low, info)
- `category` — Filter by category (e.g., "injection", "crypto")
- `limit` — Maximum results (default: 100)

**Response:**
```json
{
  "findings": [
    {
      "id": 1,
      "title": "Hardcoded API Key",
      "severity": "high",
      "category": "secrets",
      "tool": "apk_analyzer",
      "location": "MainActivity.java:42",
      "cwe": "CWE-798"
    }
  ],
  "total": 42
}
```

#### GET /api/findings/{id}
Get detailed finding information with AI analysis.

**Response:**
```json
{
  "id": 1,
  "title": "Hardcoded API Key",
  "severity": "high",
  "description": "API key exposed in source code",
  "remediation": "Remove hardcoded key, use secure storage",
  "ai_analysis": {
    "explanation": "...",
    "attack_paths": ["..."],
    "code_examples": ["..."]
  }
}
```

#### POST /api/findings/{id}/ai-chat
Send a message to AI about a specific finding.

**Request:**
```json
{
  "message": "How can I fix this?"
}
```

**Response:** Server-Sent Events (SSE) stream with AI response.

---

### Runtime (Frida)

#### POST /api/runtime/session
Start a Frida session.

**Request:**
```json
{
  "device_id": "emulator-5554",
  "package": "com.example.app",
  "spawn": true
}
```

**Response:**
```json
{
  "session_id": "abc123",
  "status": "attached"
}
```

#### POST /api/runtime/inject
Inject a Frida script.

**Request:**
```json
{
  "session_id": "abc123",
  "script": "Java.perform(function() { ... })"
}
```

#### WebSocket: /api/runtime/ws
Real-time Frida output streaming.

**Connection:** `ws://localhost:8765/api/runtime/ws?session_id=abc123`

**Messages:**
```json
{
  "type": "output",
  "data": "Script loaded successfully"
}
```

---

### Network (mitmproxy)

#### POST /api/network/start
Start network interception.

**Request:**
```json
{
  "device_id": "emulator-5554",
  "port": 8080
}
```

#### WebSocket: /api/network/ws
Real-time traffic streaming.

**Connection:** `ws://localhost:8765/api/network/ws`

**Messages:**
```json
{
  "type": "request",
  "method": "GET",
  "url": "https://api.example.com/data",
  "headers": {...}
}
```

---

### Source Analysis

#### POST /api/source/analyze
Analyze source code repository.

**Request:**
```json
{
  "project_id": 1,
  "repo_url": "https://github.com/user/repo",
  "branch": "main"
}
```

**Response:**
```json
{
  "analysis_id": 1,
  "status": "running"
}
```

#### GET /api/source/analysis/{id}
Get source analysis results.

**Response:**
```json
{
  "categories": {
    "security": {
      "score": 75,
      "findings": [...]
    },
    "code_quality": {
      "score": 82,
      "findings": [...]
    }
  }
}
```

---

### Reports

#### POST /api/reports/generate
Generate a compliance report.

**Request:**
```json
{
  "scan_id": 1,
  "type": "masvs",
  "format": "pdf"
}
```

**Types:** `masvs`, `executive`, `sbom`, `privacy`

**Formats:** `pdf`, `html`, `json`

**Response:**
```json
{
  "report_id": 1,
  "download_url": "/api/reports/1/download"
}
```

#### GET /api/reports/{id}/download
Download generated report.

---

### Settings

#### GET /api/settings
Get current configuration.

**Response:**
```json
{
  "ai_provider": "anthropic",
  "ai_model": "claude-3-5-sonnet-20240620",
  "tools": {
    "apktool": "/usr/local/bin/apktool",
    "jadx": "/usr/local/bin/jadx"
  }
}
```

#### PUT /api/settings
Update configuration.

**Request:**
```json
{
  "ai_provider": "openai",
  "ai_model": "gpt-4o"
}
```

#### GET /api/settings/tools-status
Check tool installation status.

**Response:**
```json
{
  "tools": [
    {
      "name": "apktool",
      "installed": true,
      "version": "2.9.3"
    },
    {
      "name": "jadx",
      "installed": true,
      "version": "1.5.5"
    }
  ]
}
```

---

### AI Chat

#### POST /api/ai/chat
Send a message to the AI assistant.

**Request:**
```json
{
  "message": "What is certificate pinning?",
  "context": {
    "screen": "runtime",
    "selected_finding": 123
  }
}
```

**Response:** Server-Sent Events (SSE) stream with AI response.

---

### Authentication

#### GET /api/auth/github
Initiate GitHub OAuth flow.

#### GET /api/auth/callback
OAuth callback endpoint.

#### GET /api/auth/logout
Logout and clear session.

---

## WebSocket Endpoints

### /api/runtime/ws
Real-time Frida session output.

**Query Parameters:**
- `session_id` — Frida session identifier

**Message Types:**
- `output` — Script output
- `error` — Error message
- `ai_pivot_start` — AI pivot analysis started
- `ai_pivot_token` — AI pivot response token
- `ai_pivot_done` — AI pivot complete

### /api/network/ws
Real-time network traffic streaming.

**Message Types:**
- `request` — HTTP request
- `response` — HTTP response
- `error` — Network error

---

## Error Responses

All endpoints may return error responses:

```json
{
  "error": "Invalid request",
  "detail": "Project not found",
  "status_code": 404
}
```

**Status Codes:**
- `400` — Bad Request
- `401` — Unauthorized
- `403` — Forbidden
- `404` — Not Found
- `500` — Internal Server Error

---

## Rate Limiting

Rate limits are enforced at the nginx reverse proxy level:
- Default: 30 requests per second
- Burst: 50 requests

Configure in `nginx.conf` if needed.

---

## SDKs

Official SDKs are planned for:
- Python
- JavaScript/TypeScript
- Go

For now, use the REST API directly with standard HTTP clients.
