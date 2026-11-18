#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python
if [[ ! -x "$PY" ]]; then PY=python3; fi
printf '\n=== Python regression tests ===\n'
"$PY" -m pytest -q tests || exit 1
printf '\n=== Frontend TypeScript and production build ===\n'
if command -v npm >/dev/null && [[ -d frontend/node_modules ]]; then
  (cd frontend && npm run build) || exit 1
else
  echo 'SKIPPED: run npm ci in frontend first'
fi
printf '\n=== Python dependency vulnerability scan ===\n'
if "$PY" -m pip_audit --version >/dev/null 2>&1; then
  "$PY" -m pip_audit -r backend/requirements.txt || echo 'WARNING: Python dependency audit found issues or could not reach advisory database'
else
  echo 'SKIPPED: install pip-audit into the virtual environment first'
fi
printf '\n=== npm dependency vulnerability scan ===\n'
if command -v npm >/dev/null; then
  (cd frontend && npm audit --audit-level=high) || echo 'WARNING: npm audit found issues or could not reach registry'
else
  echo 'SKIPPED: npm is unavailable'
fi
