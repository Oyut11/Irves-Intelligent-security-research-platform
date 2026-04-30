# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IRVES — Dockerfile for containerized deployment                              ║
# ║  Note: Runtime instrumentation (Frida, eBPF) requires host device access     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

FROM python:3.12-bookworm

# ── System dependencies ───────────────────────────────────────────────────────
# Build tools for compiled Python packages + weasyprint GTK libs + curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    make \
    curl \
    unzip \
    default-jdk \
    libffi-dev \
    libssl-dev \
    zlib1g-dev \
    libxml2-dev \
    libxslt1-dev \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# ── Install APKTool ────────────────────────────────────────────────────────────
RUN curl -fsSL https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -o /opt/apktool.jar && \
    curl -fsSL https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool && \
    sed -i 's|apktool.jar|/opt/apktool.jar|g' /usr/local/bin/apktool

# ── Install JADX ────────────────────────────────────────────────────────────────
RUN curl -fsSL https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip -o /tmp/jadx.zip && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    rm /tmp/jadx.zip && \
    chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui && \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx

# ── Set up Python environment ───────────────────────────────────────────────────
WORKDIR /app/backend

# Copy requirements and install core dependencies first
COPY backend/requirements.txt .

# Install packages that work in containers. 
# bcc requires kernel headers (host-specific) — skip in Docker.
# frida-tools may fail on some architectures — tolerate failure.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
        fastapi uvicorn[standard] python-multipart jinja2 markdown \
        sqlalchemy[asyncio] aiosqlite pydantic-settings python-dotenv \
        httpx aiofiles anthropic litellm \
        scikit-learn numpy \
        frida frida-tools \
        mitmproxy fritap \
        weasyprint \
        lizard radon pylint bandit safety trufflehog locust py-spy \
        pytest pytest-asyncio \
        google-generativeai google-cloud-aiplatform && \
    echo "Core packages installed. Note: bcc (eBPF) is host-only and excluded."

# ── Copy application ─────────────────────────────────────────────────────────────
COPY backend/ .
COPY docs/ /app/docs/

# ── Create directories ─────────────────────────────────────────────────────────
RUN mkdir -p /app/.irves/projects /app/.irves/reports

# ── Environment variables (override with docker-compose or -e) ───────────────────
ENV PYTHONUNBUFFERED=1
ENV APKTOOL_PATH=apktool
ENV JADX_PATH=jadx
ENV FRIDA_PATH=frida
ENV MITMPROXY_PATH=mitmproxy
ENV PROJECTS_DIR=/app/.irves/projects
ENV REPORTS_DIR=/app/.irves/reports

# ── Expose port ────────────────────────────────────────────────────────────────
EXPOSE 8765

# ── Health check ───────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8765/api/health || exit 1

# ── Run ────────────────────────────────────────────────────────────────────────
CMD ["python", "main.py"]
