#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CIPHERDROP_DOMAIN:?Set CIPHERDROP_DOMAIN to your public DNS hostname}"
if [[ "$CIPHERDROP_DOMAIN" == *"/"* || "$CIPHERDROP_DOMAIN" == *":"* ]]; then
  echo 'Set CIPHERDROP_DOMAIN to the hostname only (no scheme/port)' >&2; exit 1
fi
if ! command -v caddy >/dev/null; then echo 'Install Caddy first' >&2; exit 1; fi
if [[ ! -f frontend/dist/index.html ]]; then echo 'Run: cd frontend && npm ci && npm run build' >&2; exit 1; fi
PY=.venv/bin/python
if [[ ! -x "$PY" ]]; then echo 'Create venv and install backend requirements first' >&2; exit 1; fi
export CIPHERDROP_ENV=production
export CIPHERDROP_COOKIE_SECURE=true
export CIPHERDROP_PUBLIC_ORIGIN="https://${CIPHERDROP_DOMAIN}"
"$PY" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 &
API_PID=$!
trap 'kill "$API_PID" 2>/dev/null || true' EXIT INT TERM
caddy run --config deploy/Caddyfile --adapter caddyfile
