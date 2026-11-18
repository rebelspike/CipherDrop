#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ -x .venv/bin/python ]]; then
  PYTHON_BIN="$(pwd)/.venv/bin/python"
else
  PYTHON_BIN="$(sh scripts/select_python.sh)"
fi

if [[ -z "$PYTHON_BIN" ]] || ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' >/dev/null 2>&1; then
  echo 'ERROR: CipherDrop requires Python 3.11 or newer. Run make to set up a compatible environment.' >&2
  exit 1
fi
exec "$PYTHON_BIN" cipherdrop.py
