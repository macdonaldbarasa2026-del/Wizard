#!/bin/sh
# WIZARD Backend & Web Dashboard Launcher
set -e

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
DIR="$(cd "$(dirname "$PRG")" && pwd)"

# Detect environment
IS_TERMUX=0
if [ -n "$TERMUX_VERSION" ] || ([ -d "/data/data/com.termux/files/usr" ] && [ ! -f "/etc/debian_version" ]); then
    IS_TERMUX=1
fi

echo "=================================================="
echo " Starting WIZARD Cybersecurity Research Platform  "
echo "=================================================="

# Ensure frontend is built
if [ ! -f "$DIR/frontend/dist/index.html" ]; then
    echo "[*] Building frontend assets..."
    if command -v node >/dev/null 2>&1; then
        (cd "$DIR/frontend" && node build.js)
    else
        echo "[!] Warning: Node.js is not installed; frontend assets could not be built."
    fi
fi

HOST="${1:-0.0.0.0}"
PORT="${2:-8000}"

if [ "$IS_TERMUX" -eq 1 ] && command -v proot-distro >/dev/null 2>&1 && proot-distro list 2>&1 | grep -q "debian"; then
    echo "[*] Launching Wizard API inside Debian proot on http://${HOST}:${PORT}"
    exec proot-distro login debian -- bash -c "cd '$DIR/backend' && .venv/bin/uvicorn app.main:app --host '$HOST' --port '$PORT'"
elif [ -x "$DIR/backend/.venv/bin/uvicorn" ]; then
    echo "[*] Launching Wizard API on http://${HOST}:${PORT}"
    export PYTHONPATH="$DIR/backend:$PYTHONPATH"
    exec "$DIR/backend/.venv/bin/uvicorn" app.main:app --host "$HOST" --port "$PORT"
else
    echo "[*] Launching Wizard API on http://${HOST}:${PORT}"
    export PYTHONPATH="$DIR/backend:$PYTHONPATH"
    exec uvicorn app.main:app --host "$HOST" --port "$PORT"
fi
