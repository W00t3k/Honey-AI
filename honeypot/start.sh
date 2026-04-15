#!/usr/bin/env bash
# =============================================================================
# AI Honeypot — Startup Script
# Usage:
#   ./start.sh              # run in foreground (Ctrl+C to stop)
#   ./start.sh --bg         # run in background
#   ./start.sh --stop       # stop background instance
#   ./start.sh --restart    # stop + start in background
#   ./start.sh --status     # show running status
#   ./start.sh --logs       # tail the background log
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PID_FILE="honeypot.pid"
LOG_FILE="honeypot.log"

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  echo -e "${RED}${BOLD}"
  echo "  ╔═══════════════════════════════════════╗"
  echo "  ║   🍯  AI Honeypot  —  Multi-Protocol  ║"
  echo "  ║   OpenAI · Anthropic · Gemini · MCP   ║"
  echo "  ╚═══════════════════════════════════════╝"
  echo -e "${NC}"
}

# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo -e "${RED}ERROR: $*${NC}" >&2; exit 1; }
info() { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠  $*${NC}"; }

check_python() {
  if ! command -v python3 &>/dev/null; then
    die "python3 not found — install Python 3.10+ and retry"
  fi
  PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  info "Python $PY_VER"
}

setup_venv() {
  if [ ! -d "venv" ]; then
    info "Creating virtual environment..."
    python3 -m venv venv
  fi
  # shellcheck source=/dev/null
  source venv/bin/activate
  ok "Virtual environment active"

  STAMP="venv/.deps_ok"
  if [ ! -f "$STAMP" ] || [ "requirements.txt" -nt "$STAMP" ]; then
    info "Installing / updating dependencies..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    touch "$STAMP"
    ok "Dependencies installed"
  else
    ok "Dependencies up-to-date"
  fi
}

setup_env() {
  if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
      warn "No .env found — copying from .env.example"
      cp .env.example .env
      warn "Edit .env and set ADMIN_PASSWORD, JWT_SECRET, and ADMIN_PATH before deploying publicly"
    else
      warn "No .env file — running with built-in defaults"
    fi
  fi

  # Auto-generate JWT_SECRET if placeholder is still present
  if grep -q "your-256-bit-secret-here" .env 2>/dev/null; then
    JWT=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' "s/your-256-bit-secret-here/$JWT/" .env
    else
      sed -i "s/your-256-bit-secret-here/$JWT/" .env
    fi
    ok "JWT_SECRET auto-generated"
  fi
}

read_env_var() {
  # Read a var from .env, stripping quotes and comments
  local var="$1" default="$2"
  local val
  val=$(grep -E "^${var}=" .env 2>/dev/null | head -1 | cut -d= -f2- | tr -d "\"'" | sed 's/#.*//' | xargs || true)
  echo "${val:-$default}"
}

show_info() {
  PORT=$(read_env_var PORT 8000)
  ADMIN_PATH=$(read_env_var ADMIN_PATH /admin)
  echo ""
  info "  Honeypot endpoint : http://0.0.0.0:${PORT}"
  info "  Admin UI          : http://127.0.0.1:${PORT}${ADMIN_PATH}"
  echo ""
}

pid_running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

# ── sub-commands ──────────────────────────────────────────────────────────────
cmd_status() {
  if pid_running; then
    PID=$(cat "$PID_FILE")
    ok "Honeypot is running  (PID $PID)"
    info "  Logs : tail -f $SCRIPT_DIR/$LOG_FILE"
    info "  Stop : $0 --stop"
  else
    warn "Honeypot is NOT running"
    rm -f "$PID_FILE"
  fi
  exit 0
}

cmd_stop() {
  if pid_running; then
    PID=$(cat "$PID_FILE")
    kill "$PID"
    sleep 1
    # Force-kill if still alive
    kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null || true
    rm -f "$PID_FILE"
    ok "Honeypot stopped  (was PID $PID)"
  else
    warn "Honeypot is not running (no PID file)"
    rm -f "$PID_FILE"
  fi
  exit 0
}

cmd_logs() {
  if [ ! -f "$LOG_FILE" ]; then
    die "No log file found at $LOG_FILE — is the honeypot running in background mode?"
  fi
  exec tail -f "$LOG_FILE"
}

cmd_bg() {
  if pid_running; then
    PID=$(cat "$PID_FILE")
    warn "Honeypot already running  (PID $PID) — use --stop first or --restart"
    exit 0
  fi
  nohup python main.py > "$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 1
  if pid_running; then
    ok "Honeypot started in background  (PID $(cat $PID_FILE))"
    info "  Logs : tail -f $SCRIPT_DIR/$LOG_FILE"
    info "  Stop : $0 --stop"
  else
    die "Process exited immediately — check $LOG_FILE for errors"
  fi
  exit 0
}

cmd_restart() {
  if pid_running; then
    cmd_stop 2>/dev/null || true
    sleep 1
  fi
  cmd_bg
}

# ── main ──────────────────────────────────────────────────────────────────────
banner

MODE="${1:-}"

check_python
setup_venv
setup_env
show_info

case "$MODE" in
  --status)  cmd_status ;;
  --stop)    cmd_stop ;;
  --logs)    cmd_logs ;;
  --bg|--background) cmd_bg ;;
  --restart) cmd_restart ;;
  "")
    info "Starting in foreground  (Ctrl+C to stop)..."
    echo ""
    exec python main.py
    ;;
  *)
    echo "Usage: $0 [--bg | --stop | --restart | --status | --logs]"
    exit 1
    ;;
esac
