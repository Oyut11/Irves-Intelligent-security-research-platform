#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IRVES — One-Command Installer (Linux & macOS)                             ║
# ║  Usage: bash install.sh                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
set -euo pipefail

IRVES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$IRVES_DIR/backend"
TOOLS_DIR="$HOME/.irves/bin"
BIN_DIR="$HOME/.local/bin"

JADX_VERSION="1.5.5"
APKTOOL_VERSION="2.9.3"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✓${NC}  $1"; }
info() { echo -e "  ${BLUE}→${NC}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $1"; }
fail() { echo -e "  ${RED}✗${NC}  $1"; exit 1; }
step() { echo -e "\n${BOLD}$1${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}${BOLD}"
echo "  ██╗██████╗ ██╗   ██╗███████╗███████╗"
echo "  ██║██╔══██╗██║   ██║██╔════╝██╔════╝"
echo "  ██║██████╔╝╚██╗ ██╔╝█████╗  ███████╗"
echo "  ██║██╔══██╗ ╚████╔╝ ██╔══╝  ╚════██║"
echo "  ██║██║  ██║  ╚██╔╝  ███████╗███████║"
echo "  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "  ${BOLD}Intelligent Reverse Engineering & Vulnerability Evaluation System${NC}"
echo -e "  Installer for Linux / macOS\n"
echo "  ──────────────────────────────────────────────────────────────────────"

# ── Detect OS & package manager ───────────────────────────────────────────────
OS="unknown"
PKG_MGR=""
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"; PKG_MGR="apt-get"
elif [[ -f /etc/fedora-release ]] || [[ -f /etc/redhat-release ]]; then
    OS="fedora"; PKG_MGR="dnf"
elif [[ -f /etc/arch-release ]]; then
    OS="arch"; PKG_MGR="pacman"
else
    OS="linux"
fi
info "Detected OS: $OS"

mkdir -p "$TOOLS_DIR" "$BIN_DIR"

# ══════════════════════════════════════════════════════════════════════════════
step "[ 1 / 7 ]  Java"
# ══════════════════════════════════════════════════════════════════════════════
check_java() {
    if command -v java &>/dev/null; then
        JAVA_VER=$(java -version 2>&1 | grep -oP '(?<=")\d+' | head -1 || true)
        [[ "${JAVA_VER:-0}" -ge 11 ]] && { ok "Java $JAVA_VER already installed"; return 0; }
    fi
    return 1
}

if ! check_java; then
    info "Installing Java 21..."
    case "$OS" in
        macos)
            command -v brew &>/dev/null || fail "Homebrew not found. Install from https://brew.sh then re-run."
            brew install --quiet openjdk@21
            sudo ln -sfn "$(brew --prefix)/opt/openjdk@21/libexec/openjdk.jdk" \
                /Library/Java/JavaVirtualMachines/openjdk-21.jdk 2>/dev/null || true
            ;;
        debian)
            sudo "$PKG_MGR" update -qq
            sudo "$PKG_MGR" install -y -q default-jdk
            ;;
        fedora)  sudo "$PKG_MGR" install -y -q java-21-openjdk ;;
        arch)    sudo pacman -Sy --noconfirm jdk-openjdk ;;
        *)       fail "Cannot auto-install Java. Please install JDK 11+ manually then re-run." ;;
    esac
    check_java || fail "Java installation failed."
fi

# ══════════════════════════════════════════════════════════════════════════════
step "[ 2 / 7 ]  Python 3.12+"
# ══════════════════════════════════════════════════════════════════════════════
PYTHON_BIN=""
check_python() {
    for cmd in python3.13 python3.12 python3; do
        if command -v "$cmd" &>/dev/null; then
            MAJOR=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || true)
            MINOR=$("$cmd" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || true)
            if [[ "${MAJOR:-0}" -eq 3 && "${MINOR:-0}" -ge 12 ]]; then
                PYTHON_BIN="$cmd"
                ok "Python $MAJOR.$MINOR found ($(command -v "$cmd"))"
                return 0
            fi
        fi
    done
    return 1
}

if ! check_python; then
    info "Installing Python 3.12..."
    case "$OS" in
        macos)
            brew install --quiet python@3.12
            PYTHON_BIN="$(brew --prefix)/bin/python3.12"
            ;;
        debian)
            sudo "$PKG_MGR" install -y -q python3.12 python3.12-venv python3-pip
            ;;
        fedora)  sudo "$PKG_MGR" install -y -q python3.12 ;;
        arch)    sudo pacman -Sy --noconfirm python ;;
        *)       fail "Cannot auto-install Python. Install Python 3.12+ manually then re-run." ;;
    esac
    check_python || fail "Python 3.12+ installation failed."
fi

# ══════════════════════════════════════════════════════════════════════════════
step "[ 3 / 7 ]  Python virtual environment & dependencies"
# ══════════════════════════════════════════════════════════════════════════════
VENV_DIR="$BACKEND_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    ok "Created .venv"
else
    ok ".venv already exists — skipping creation"
fi

PIP="$VENV_DIR/bin/pip"
info "Installing Python packages (Frida, mitmproxy, androguard, …)"
"$PIP" install -q --upgrade pip
"$PIP" install -q -r "$BACKEND_DIR/requirements.txt"
ok "Python dependencies installed"

# ── Optional: eBPF / kernel monitoring ─────────────────────────────────────────
if [[ "$OS" == "debian" ]] && command -v apt-get &>/dev/null; then
    info "Installing eBPF tools (optional — requires kernel headers)..."
    sudo apt-get install -y -q bpfcc-tools linux-headers-$(uname -r) 2>/dev/null || \
        warn "eBPF tools require matching kernel headers — skipping"
fi

# ══════════════════════════════════════════════════════════════════════════════
step "[ 4 / 7 ]  APKTool $APKTOOL_VERSION"
# ══════════════════════════════════════════════════════════════════════════════
if command -v apktool &>/dev/null; then
    ok "APKTool already installed at $(command -v apktool)"
else
    APKTOOL_JAR="$TOOLS_DIR/apktool.jar"
    APKTOOL_BIN="$BIN_DIR/apktool"
    info "Downloading APKTool $APKTOOL_VERSION…"
    curl -fsSL \
        "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" \
        -o "$APKTOOL_JAR"
    curl -fsSL \
        "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
        -o "$APKTOOL_BIN"
    chmod +x "$APKTOOL_BIN"
    # Point wrapper to our jar
    sed -i.bak "s|apktool.jar|$APKTOOL_JAR|g" "$APKTOOL_BIN" && rm -f "${APKTOOL_BIN}.bak"
    ok "APKTool $APKTOOL_VERSION installed → $APKTOOL_BIN"
fi

# ══════════════════════════════════════════════════════════════════════════════
step "[ 5 / 7 ]  JADX $JADX_VERSION"
# ══════════════════════════════════════════════════════════════════════════════
if command -v jadx &>/dev/null; then
    ok "JADX already installed at $(command -v jadx)"
else
    JADX_DIR="$TOOLS_DIR/jadx"
    JADX_BIN="$BIN_DIR/jadx"
    JADX_ZIP="$TOOLS_DIR/jadx.zip"
    info "Downloading JADX $JADX_VERSION…"
    curl -fsSL \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        -o "$JADX_ZIP"
    mkdir -p "$JADX_DIR"
    unzip -q "$JADX_ZIP" -d "$JADX_DIR"
    rm -f "$JADX_ZIP"
    chmod +x "$JADX_DIR/bin/jadx" "$JADX_DIR/bin/jadx-gui"
    ln -sf "$JADX_DIR/bin/jadx" "$JADX_BIN"
    ok "JADX $JADX_VERSION installed → $JADX_BIN"
fi

# ══════════════════════════════════════════════════════════════════════════════
step "[ 6 / 7 ]  PATH configuration"
# ══════════════════════════════════════════════════════════════════════════════
PATH_LINE="export PATH=\"\$PATH:$BIN_DIR\""
for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [[ -f "$RC" ]] && ! grep -qF "$BIN_DIR" "$RC"; then
        printf '\n# IRVES tools\n%s\n' "$PATH_LINE" >> "$RC"
        ok "Added $BIN_DIR to $RC"
    fi
done
export PATH="$PATH:$BIN_DIR"

# ══════════════════════════════════════════════════════════════════════════════
step "[ 7 / 7 ]  Environment configuration"
# ══════════════════════════════════════════════════════════════════════════════
ENV_FILE="$BACKEND_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$BACKEND_DIR/.env.example" "$ENV_FILE"
    # Generate a secure SECRET_KEY
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || openssl rand -hex 32)
    sed -i "s|SECRET_KEY=change-this-to-a-secure-random-string|SECRET_KEY=$SECRET_KEY|" "$ENV_FILE"
    ok "Created backend/.env from .env.example"
    ok "Auto-generated SECRET_KEY"
    warn "Open backend/.env and set at least one AI API key (e.g. ANTHROPIC_API_KEY)"
else
    ok "backend/.env already exists — skipping"
fi

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}  IRVES is ready!${NC}"
echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Start the server:${NC}"
echo -e "    cd backend && source .venv/bin/activate && python main.py"
echo ""
echo -e "  ${BOLD}Open in browser:${NC}"
echo -e "    http://127.0.0.1:8765"
echo ""
echo -e "  ${YELLOW}Next:${NC} Edit ${BOLD}backend/.env${NC} and set your AI API key."
echo ""
