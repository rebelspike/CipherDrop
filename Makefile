# CipherDrop: simple reproducible build and safety checks.
.DEFAULT_GOAL := all
SHELL := /bin/sh
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PYTHON ?= python3
PY := $(ROOT).venv/bin/python
.PHONY: all setup run test audit clean clean-all help check-tools frontend-lock

all: setup

check-tools:
	@command -v $(PYTHON) >/dev/null || { echo 'ERROR: Install Python 3.11+ first.' >&2; exit 1; }
	@command -v node >/dev/null || { echo 'ERROR: Install Node.js 20.19+ (with npm) first.' >&2; exit 1; }
	@command -v npm >/dev/null || { echo 'ERROR: npm not found; install Node.js.' >&2; exit 1; }
	@node -e 'const n=process.versions.node.split(".").map(Number); if(n[0]<20 || (n[0]===20 && n[1]<19)) { console.error("ERROR: Node.js 20.19+ required; found "+process.version); process.exit(1) }'

$(PY):
	$(PYTHON) -m venv "$(ROOT).venv"

# The lockfile from older builds can still point at vulnerable Vite 8.3.1.
# Refresh it ONLY if it does not lock the patched version required by package.json.
frontend-lock: check-tools
	@node -e 'const fs=require("fs"),path=require("path"); const p=JSON.parse(fs.readFileSync(path.join("$(ROOT)","frontend/package.json"))); const l=JSON.parse(fs.readFileSync(path.join("$(ROOT)","frontend/package-lock.json"))); if(p.dependencies.vite!=="8.3.6") {console.error("ERROR: expected Vite 8.3.6 in package.json");process.exit(1)} if(l.packages?.["node_modules/vite"]?.version !== "8.3.6" || l.packages?.[""]?.dependencies?.vite !== "8.3.6")process.exit(2)' || { echo '[→] Updating npm lockfile for patched Vite 8.3.6 (network required)...'; cd "$(ROOT)frontend" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund; }

PY_DEPS_STAMP := $(ROOT).venv/.cipherdrop-app-deps
TEST_DEPS_STAMP := $(ROOT).venv/.cipherdrop-test-deps
AUDIT_DEPS_STAMP := $(ROOT).venv/.cipherdrop-audit-deps
NODE_DEPS_STAMP := $(ROOT)frontend/node_modules/.cipherdrop-installed
FRONTEND_BUILD := $(ROOT)frontend/dist/index.html

$(PY_DEPS_STAMP): $(PY) $(ROOT)backend/requirements.txt
	"$(PY)" -m pip install -r "$(ROOT)backend/requirements.txt"
	@touch "$@"

$(TEST_DEPS_STAMP): $(PY_DEPS_STAMP) $(ROOT)backend/requirements-test.txt
	"$(PY)" -m pip install -r "$(ROOT)backend/requirements-test.txt"
	@touch "$@"

$(AUDIT_DEPS_STAMP): $(PY_DEPS_STAMP)
	"$(PY)" -m pip install pip-audit
	@touch "$@"

$(NODE_DEPS_STAMP): $(ROOT)frontend/package.json $(ROOT)frontend/package-lock.json
	cd "$(ROOT)frontend" && npm ci
	@touch "$@"

$(FRONTEND_BUILD): $(NODE_DEPS_STAMP) $(ROOT)frontend/src/main.tsx $(ROOT)frontend/src/styles.css $(ROOT)frontend/index.html $(ROOT)frontend/vite.config.ts
	cd "$(ROOT)frontend" && npm run build

setup: check-tools frontend-lock $(PY_DEPS_STAMP) $(FRONTEND_BUILD)
	@printf '\n[✓] CipherDrop setup complete. Run: make run\n'

# Safe for a clean installation: install/build only when necessary.
run: setup
	cd "$(ROOT)" && bash ./start.sh

test: $(TEST_DEPS_STAMP)
	cd "$(ROOT)" && "$(PY)" -m pytest -q tests

audit: $(AUDIT_DEPS_STAMP)
	cd "$(ROOT)" && "$(PY)" -m pip_audit -r backend/requirements.txt
	cd "$(ROOT)frontend" && npm audit --audit-level=high

# Never delete data/, encrypted/, audit_hmac.key, or .env.
clean:
	rm -rf "$(ROOT)frontend/dist" "$(ROOT).pytest_cache" "$(ROOT).ruff_cache" "$(ROOT).mypy_cache"
	find "$(ROOT)backend" "$(ROOT)tests" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@echo '[✓] Build caches cleaned. Accounts and encrypted files preserved.'

clean-all: clean
	rm -rf "$(ROOT)frontend/node_modules" "$(ROOT).venv"
	@echo '[✓] Dependencies removed. Run make before next launch.'

help:
	@printf 'make           Install dependencies and build\nmake run       Start CipherDrop locally (no menu)\nmake test      Run backend regression tests\nmake audit     Check dependencies for known vulnerabilities\nmake clean     Clear generated build caches, NOT user data\nmake clean-all Remove dependencies too, NOT user data\n'
