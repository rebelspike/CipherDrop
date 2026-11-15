#!/usr/bin/env bash
# Runs the full CipherDrop security audit against a THROWAWAY data folder.
# Starts the backend (port 8000) and the real Vite dev server (port 5173), runs
# audit_tests.py and redteam_tests.py, saves logs to m3/src/audit/results/, then stops
# both servers and deletes the throwaway data. Real CipherDrop data is never touched.
# Prerequisite: run `make` once from the project root (creates .venv and node_modules).
set -euo pipefail

AUDIT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$AUDIT_DIR/../../.." && pwd)"
PY="${PY:-$ROOT/.venv/bin/python}"
VITE_BIN="$ROOT/frontend/node_modules/.bin/vite"
RESULTS="$AUDIT_DIR/results"

[[ -x "$PY" ]] || { echo "Missing $PY. Run 'make' in $ROOT first." >&2; exit 1; }
[[ -x "$VITE_BIN" ]] || { echo "Missing $VITE_BIN. Run 'make' in $ROOT first." >&2; exit 1; }
for port in 8000 5173; do
  if "$PY" -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',$port)) else 1)"; then :; else
    echo "Port $port is in use. Stop CipherDrop (or whatever uses it) and retry." >&2; exit 1
  fi
done

echo "[1/4] Installing test dependencies (httpx, cryptography)..."
"$PY" -m pip install -q -r "$ROOT/backend/requirements-test.txt"

DATA="$(mktemp -d)"
mkdir -p "$RESULTS"
API_PID=""; WEB_PID=""
cleanup() {
  [[ -n "$API_PID" ]] && kill "$API_PID" 2>/dev/null || true
  [[ -n "$WEB_PID" ]] && kill "$WEB_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$DATA"
}
trap cleanup EXIT INT TERM

echo "[2/4] Starting backend and Vite with throwaway data in $DATA ..."
CIPHERDROP_DATA_DIR="$DATA" "$PY" -m uvicorn app.main:app --app-dir "$ROOT/backend" \
  --host 127.0.0.1 --port 8000 > "$RESULTS/backend.log" 2>&1 &
API_PID=$!
(cd "$ROOT/frontend" && exec "$VITE_BIN" --host 127.0.0.1 --port 5173 --strictPort) > "$RESULTS/vite.log" 2>&1 &
WEB_PID=$!
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:5173/api/health >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -sf http://127.0.0.1:5173/api/health >/dev/null || { echo "Servers did not start; see $RESULTS/*.log" >&2; exit 1; }

echo "[3/4] Running attack scenarios (about 1 minute)..."
"$PY" "$AUDIT_DIR/audit_tests.py" http://127.0.0.1:8000 "$DATA" "$RESULTS/audit_results.json" | tee "$RESULTS/audit_tests.log"

echo "[4/4] Running AI red-team checks (about 1 minute)..."
"$PY" "$AUDIT_DIR/redteam_tests.py" http://127.0.0.1:5173 http://127.0.0.1:8000 "$DATA" "$RESULTS/redteam_results.json" | tee "$RESULTS/redteam_tests.log"

echo
echo "Summary:"
grep -hE '^\[[A-Z0-9-]+\]' "$RESULTS/audit_tests.log" "$RESULTS/redteam_tests.log"
echo "HTTP 500 responses in backend log: $(grep -c ' 500 ' "$RESULTS/backend.log" || true)"
echo "Logs and JSON results: $RESULTS"
