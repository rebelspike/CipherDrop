#!/usr/bin/env python3
import os, sys, subprocess, secrets, time, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV = ROOT / '.env'
VENV = ROOT / '.venv'
BANNER = r'''
╔══════════════════════════════════╗
║          CIPHERDROP SETUP        ║
╚══════════════════════════════════╝
'''

def ensure_env(mode):
    if not ENV.exists():
        ENV.write_text('# Generated locally by CipherDrop. Do not commit this file.\n'
                       f'CIPHERDROP_MODE={mode}\nSESSION_SECRET={secrets.token_urlsafe(48)}\n'
                       'DATABASE_URL=sqlite:///./data/cipherdrop.db\nSTORAGE_PATH=./data/encrypted\n')
        print('[✓] Generated local configuration and security secret')

def run(cmd, cwd=None):
    subprocess.run(cmd, cwd=cwd or ROOT, check=True)

def ensure_dependencies():
    py = VENV / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not py.exists():
        print('[→] Creating lightweight Python environment...')
        run([sys.executable, '-m', 'venv', str(VENV)])
    try:
        subprocess.run([str(py), '-c', 'import fastapi,uvicorn,sqlalchemy,argon2'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print('[→] Installing backend dependencies (first run only)...')
        run([str(py), '-m', 'pip', 'install', '-r', str(ROOT/'backend/requirements.txt')])
    if not shutil.which('npm'):
        raise SystemExit('[!] Node.js/npm is required for the web interface. Install Node.js 20+ and retry.')
    if not (ROOT/'frontend/node_modules').exists():
        print('[→] Installing frontend dependencies (first run only)...')
        run(['npm', 'install'], ROOT/'frontend')
    return py

def launch(py):
    api = subprocess.Popen([str(py), '-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'], cwd=ROOT/'backend')
    web = subprocess.Popen(['npm', 'run', 'dev', '--', '--host', '127.0.0.1'], cwd=ROOT/'frontend')
    print('\n[✓] CipherDrop services launched')
    print('[→] Web UI: http://localhost:5173')
    print('[→] API:    http://localhost:8000')
    print('[i] Press Ctrl+C to stop CipherDrop.\n')
    try:
        while api.poll() is None and web.poll() is None: time.sleep(.5)
    except KeyboardInterrupt:
        pass
    finally:
        for p in (api, web):
            if p.poll() is None: p.terminate()
        for p in (api, web):
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill()
        print('\n[✓] CipherDrop stopped')

def main():
    print(BANNER)
    print('[→] Starting CipherDrop in Standalone mode (localhost only)')
    ensure_env('standalone')
    try:
        py = ensure_dependencies()
    except (subprocess.CalledProcessError, OSError) as e:
        print(f'[!] Setup failed: {e}')
        return 1
    launch(py)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
