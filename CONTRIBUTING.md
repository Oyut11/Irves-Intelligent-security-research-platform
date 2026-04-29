# Contributing to IRVES

Thank you for your interest in contributing! This guide covers the basics.

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

## Code Style

- **Python**: Follow PEP 8. Use `logging` instead of `print()`. Async everywhere for routes and services.
- **Rust**: Follow `rustfmt` defaults.
- **HTML/CSS/JS**: Follow the existing design system in `backend/static/css/irves.css`. Use the established component classes.

## Project Structure

```
backend/
├── main.py              App entry + UI routes
├── config.py             Pydantic settings
├── routes/               API routers (one per domain)
├── services/             Business logic layer
│   └── tools/           Tool-specific runners
├── models/              Pydantic schemas
├── database/            SQLAlchemy models + CRUD
├── templates/           Jinja2 HTML screens
└── static/              CSS, JS, fonts, images
src-tauri/
└── src/                 Rust shell (backend process management)
```

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Test manually — start the backend with `npm run backend` and verify your change
5. Commit with a descriptive message
6. Open a pull request against `main`

## Reporting Issues

- Use GitHub Issues
- Include steps to reproduce, expected behavior, and actual behavior
- Include relevant log output from `backend/backend.log`

## License

By contributing, you agree that your contributions will be licensed under the [GPL v3](LICENSE).
