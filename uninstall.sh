#!/bin/sh
# WIZARD Safe Uninstaller
set -e

CYAN="\033[96m"
GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
BOLD="\033[1m"
RESET="\033[0m"

echo "${CYAN}${BOLD}[*] Running WIZARD safe uninstaller...${RESET}"

REMOVED=0

# Check Termux prefix bin
if [ -n "$PREFIX" ] && [ -e "$PREFIX/bin/wizard" ]; then
    rm -f "$PREFIX/bin/wizard"
    echo "    Removed launcher: $PREFIX/bin/wizard"
    REMOVED=1
fi

if [ -e "/data/data/com.termux/files/usr/bin/wizard" ]; then
    rm -f "/data/data/com.termux/files/usr/bin/wizard"
    echo "    Removed launcher: /data/data/com.termux/files/usr/bin/wizard"
    REMOVED=1
fi

# Check user local bin
if [ -e "$HOME/.local/bin/wizard" ]; then
    rm -f "$HOME/.local/bin/wizard"
    echo "    Removed launcher: $HOME/.local/bin/wizard"
    REMOVED=1
fi

# Check system local bin
if [ -e "/usr/local/bin/wizard" ] && [ -w "/usr/local/bin/wizard" ]; then
    rm -f "/usr/local/bin/wizard"
    echo "    Removed launcher: /usr/local/bin/wizard"
    REMOVED=1
fi

# Clean local virtualenv if --clean-env flag passed
if [ "$1" = "--clean-env" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -d "$SCRIPT_DIR/backend/.venv" ]; then
        echo "    Removing backend virtual environment: $SCRIPT_DIR/backend/.venv"
        rm -rf "$SCRIPT_DIR/backend/.venv"
    fi
fi

if [ "$REMOVED" -eq 1 ]; then
    echo "${GREEN}${BOLD}✓ Wizard CLI launcher successfully uninstalled.${RESET}"
    echo "  (Note: Your project data and source files have been preserved)."
else
    echo "${YELLOW}[!] No global launcher found in standard bin paths.${RESET}"
fi
