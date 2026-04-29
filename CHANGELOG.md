# Changelog

All notable changes to IRVES will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Docker containerization support with multi-stage build
- Docker Compose configuration with PostgreSQL option
- One-command installers for Linux/macOS (`install.sh`) and Windows (`install.ps1`)
- Nginx reverse proxy configuration with SSL/TLS support
- Systemd service file for Linux production deployments
- Secure SECRET_KEY generator script
- Docker environment template (`.env.docker.example`)

### Changed
- Removed MobSF integration completely
- Repurposed `full` scan profile to include APKTool, JADX, Frida, and mitmproxy
- Updated README with comprehensive deployment documentation

### Security
- Removed MobSF dependencies and API endpoints
- Added security policy documentation (SECURITY.md)

## [1.0.0] - 2026-04-28

### Added
- Initial public release of IRVES
- Multi-platform security analysis (Android, iOS, Web, Desktop)
- Static Application Security Testing (SAST) with APKTool, JADX, native analyzers
- Dynamic Application Security Testing (DAST) with Frida and mitmproxy
- AI Intelligence Engine with provider-agnostic support (Anthropic, OpenAI, Gemini, xAI, DeepSeek, Together AI, HuggingFace, Ollama)
- Context-aware AI chat that adapts to current screen and data
- Real-time Frida error analysis with AI pivot responses
- Network interception with WebSocket streaming
- AST Engine for semantic code analysis
- Dependency scanning with CVE matching
- Git integration (GitHub/GitLab OAuth)
- OWASP MASVS compliance reporting
- OWASP Top 10 classification
- CWE mapping for all findings
- Executive, SBOM, and Privacy report templates
- 8-category source code audit (Architecture, Scalability, Code Quality, Security, Dependencies, Secrets, Technical Debt, Contributor Risk)
- Scan profiles: quick, full, runtime, custom
- Tauri desktop application shell

### Security
- Certificate pinning detection and bypass (Frida)
- Root/jailbreak detection and bypass
- SSL pinning bypass techniques
- Hardcoded secrets detection
- HTTP URL cleartext traffic detection
- Known vulnerable library detection (CVE database)
- Intent redirection analysis (Android)
- Keychain vulnerability analysis (iOS)
- ATS enforcement checking (iOS)

## [0.9.0] - 2026-04-15

### Added
- MobSF integration for mobile security scanning
- Basic APK decompilation with APKTool
- JADX integration for DEX-to-Java decompilation
- Frida hook injection framework
- mitmproxy network interception
- Basic AI chat interface
- Project management system
- Finding dashboard with severity filtering

### Changed
- Initial alpha release for internal testing

## [0.1.0] - 2026-03-01

### Added
- Project inception
- Basic architecture design
- Core database schema
- Initial UI scaffolding

[Unreleased]: https://github.com/your-org/irves/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/irves/releases/tag/v1.0.0
[0.9.0]: https://github.com/your-org/irves/releases/tag/v0.9.0
[0.1.0]: https://github.com/your-org/irves/releases/tag/v0.1.0
