#!/bin/sh
# WIZARD Universal Installer
# Compatible with Android Termux, Debian proot, Debian, Ubuntu, Fedora, Arch, and standard Linux.
set -e

CYAN="\033[96m"
GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
BOLD="\033[1m"
RESET="\033[0m"

echo "${CYAN}${BOLD}"
echo "  ╭─────────────────────────────────────────────────────────────╮"
echo "  │   █   █  █  █████    ██    ████   ████                      │"
echo "  │   █ █ █  █     █    █  █   █   █  █   █                     │"
echo "  │   ██ ██  █    █    ██████  ████   █   █                     │"
echo "  │   █   █  █   ████  █    █  █   █  ████                      │"
echo "  │                                                             │"
echo "  │   ✦ CYBERSECURITY RESEARCH & REVERSE ENGINEERING PLATFORM ✦ │"
echo "  │        Defensive Analysis • Memory Hardening • Auditing     │"
echo "  ╰─────────────────────────────────────────────────────────────╯${RESET}"
echo ""
echo "[*] Initializing Wizard universal setup..."

# Determine repository root dynamically
PRG="$0"
while [ -h "$PRG" ]; do
  ls=$(ls -ld "$PRG")
  link=$(expr "$ls" : '.*-> \(.*\)$')
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=$(dirname "$PRG")"/$link"
  fi
done
INSTALL_DIR="$(cd "$(dirname "$PRG")" && pwd)"
echo "[*] Repository directory: ${INSTALL_DIR}"

# 1. Environment Detection
ARCH="$(uname -m)"
IS_TERMUX=0
if [ -n "$TERMUX_VERSION" ] || ([ -d "/data/data/com.termux/files/usr" ] && [ ! -f "/etc/debian_version" ]); then
    IS_TERMUX=1
    echo "[*] Detected Environment: ${GREEN}Android / Termux${RESET} (${ARCH})"
elif [ "$(uname)" = "Darwin" ]; then
    echo "[*] Detected Environment: ${GREEN}macOS (Darwin)${RESET} (${ARCH})"
else
    DISTRO="Linux"
    if [ -f "/etc/os-release" ]; then
        DISTRO=$(grep -E '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"' || echo "Linux")
    fi
    echo "[*] Detected Environment: ${GREEN}${DISTRO}${RESET} (${ARCH})"
fi

# 2. Dependency Resolution & Python Environment
echo "[*] Configuring Python environment and core dependencies..."

if [ "$IS_TERMUX" -eq 1 ]; then
    # Termux Environment: Use Debian proot for robust pre-compiled aarch64 Python wheels
    if ! command -v proot-distro >/dev/null 2>&1; then
        echo "[*] Installing proot-distro via pkg..."
        pkg install -y proot-distro
    fi

    if ! proot-distro list 2>&1 | grep -q "debian"; then
        echo "[*] Setting up Debian container in proot-distro..."
        proot-distro install debian
    fi

    echo "[*] Verifying Debian proot packages (python3, venv, binutils, file, g++, make)..."
    proot-distro login debian -- bash -c "
        if ! command -v python3 >/dev/null 2>&1 || ! dpkg -s python3-venv >/dev/null 2>&1 || ! command -v g++ >/dev/null 2>&1; then
            apt-get update && apt-get install -y python3 python3-venv python3-pip binutils file g++ make
        fi
    "

    echo "[*] Setting up Python virtual environment in backend/.venv..."
    proot-distro login debian -- bash -c "
        cd '$INSTALL_DIR/backend'
        if [ ! -x '.venv/bin/python' ]; then
            python3 -m venv .venv
        fi
        .venv/bin/pip install --upgrade pip
        .venv/bin/pip install -r requirements.txt
    "

    echo "[*] Compiling C++ native acceleration core (libwizard_core.so)..."
    proot-distro login debian -- bash -c "
        cd '$INSTALL_DIR/backend/app/native'
        make clean && make
    " || true

    # Also check if Termux node is present for frontend bundling
    if ! command -v node >/dev/null 2>&1; then
        echo "[*] Installing nodejs in Termux for UI compilation..."
        pkg install -y nodejs || true
    fi
else
    # Standard Linux / Debian proot / Darwin
    if ! command -v python3 >/dev/null 2>&1; then
        echo "${RED}[!] Error: Python 3 is not installed.${RESET}" >&2
        echo "    Please install python3 (>= 3.10) and python3-venv:" >&2
        echo "      Debian/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip" >&2
        echo "      Arch Linux:    sudo pacman -S python python-pip" >&2
        echo "      Fedora:        sudo dnf install -y python3 python3-pip" >&2
        exit 1
    fi

    if [ ! -x "$INSTALL_DIR/backend/.venv/bin/python" ]; then
        echo "[*] Creating Python virtualenv in backend/.venv..."
        python3 -m venv "$INSTALL_DIR/backend/.venv"
    fi

    echo "[*] Installing backend dependencies from requirements.txt..."
    "$INSTALL_DIR/backend/.venv/bin/pip" install --upgrade pip
    "$INSTALL_DIR/backend/.venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt"

    echo "[*] Compiling C++ native acceleration core (libwizard_core.so)..."
    if command -v g++ >/dev/null 2>&1 || command -v clang++ >/dev/null 2>&1; then
        make -C "$INSTALL_DIR/backend/app/native" clean all || true
    fi
fi

# 3. Frontend Build
echo "[*] Building frontend distribution..."
if command -v node >/dev/null 2>&1; then
    (cd "$INSTALL_DIR/frontend" && node build.js)
elif [ -f "$INSTALL_DIR/frontend/dist/index.html" ]; then
    echo "    Using pre-existing frontend build in frontend/dist."
else
    echo "${YELLOW}[!] Note: Node.js is not installed. To build UI assets, install nodejs.${RESET}"
fi

# 4. Configure CLI Launcher in PATH
TARGET_BIN=""

if [ "$IS_TERMUX" -eq 1 ]; then
    PREFIX_BIN="${PREFIX:-/data/data/com.termux/files/usr}/bin"
    if [ -d "$PREFIX_BIN" ] && [ -w "$PREFIX_BIN" ]; then
        TARGET_BIN="$PREFIX_BIN/wizard"
    fi
fi

if [ -z "$TARGET_BIN" ]; then
    USER_BIN="$HOME/.local/bin"
    mkdir -p "$USER_BIN"
    TARGET_BIN="$USER_BIN/wizard"
fi

echo "[*] Configuring Wizard CLI launcher: ${CYAN}${TARGET_BIN}${RESET}"
chmod +x "$INSTALL_DIR/bin/wizard"
ln -sf "$INSTALL_DIR/bin/wizard" "$TARGET_BIN"
chmod +x "$TARGET_BIN"

# Check PATH availability
BIN_DIR_PATH="$(dirname "$TARGET_BIN")"
case ":$PATH:" in
  *":$BIN_DIR_PATH:"*) ;;
  *)
    echo "${YELLOW}[!] Notice: ${BIN_DIR_PATH} is not in your current PATH.${RESET}"
    echo "    Add it to your session with:"
    echo "      export PATH=\"${BIN_DIR_PATH}:\$PATH\""
    echo "    Or add that export line to your ~/.bashrc or ~/.zshrc."
    ;;
esac

# 5. Verification
echo ""
echo "[*] Verifying installation..."
if "$TARGET_BIN" --version >/dev/null 2>&1; then
    echo "${GREEN}${BOLD}✓ Wizard installation complete.${RESET}\n"
    "$TARGET_BIN" --version
else
    echo "${YELLOW}[!] Launcher installed at ${TARGET_BIN}. Check permissions or run directly:${RESET}"
    echo "    ${TARGET_BIN} --version"
fi

echo ""
echo "Wizard installation complete."
echo ""
echo "Run:"
echo "  wizard --version"
echo "  wizard doctor"
echo "  wizard --help"
echo ""
