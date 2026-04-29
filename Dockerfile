# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IRVES — Dockerfile for containerized deployment                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

FROM python:3.12-slim

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    openjdk-21-jdk \
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
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application ─────────────────────────────────────────────────────────────
COPY backend/ .

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
