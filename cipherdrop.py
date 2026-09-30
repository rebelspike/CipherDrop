#!/usr/bin/env python3
import os, sys, subprocess, platform, secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV = ROOT / '.env'

BANNER = r'''
╔══════════════════════════════════╗
║          CIPHERDROP SETUP        ║
╚══════════════════════════════════╝
'''

def ensure_env(mode):
    if ENV.exists():
        return
    secret = secrets.token_urlsafe(48)
    ENV.write_text(
        '# Generated locally by CipherDrop. Do not commit this file.\n'
        f'CIPHERDROP_MODE={mode}\n'
        f'SESSION_SECRET={secret}\n'
        'DATABASE_URL=sqlite:///./data/cipherdrop.db\n'
        'STORAGE_PATH=./data/encrypted\n'
    )
    print('[✓] Generated local configuration and security secret')

def menu():
    print(BANNER)
    print('How would you like to run CipherDrop?\n')
    print('[1] Standalone')
    print('    Everything runs on this computer.')
    print('    Recommended for most users.\n')
    print('[2] Server')
    print('    Host CipherDrop for other devices')
    print('    on your network.\n')
    print('[3] Development')
    print('    Run frontend/backend separately.\n')
    print('[Q] Quit\n')
    return input('Select: ').strip().lower()

def main():
    choice = menu()
    modes = {'1':'standalone','2':'server','3':'development'}
    if choice in ('q','quit','exit'):
        return 0
    if choice not in modes:
        print('\n[!] Invalid selection.')
        return 1
    mode = modes[choice]
    ensure_env(mode)
    print(f'\n[✓] Mode selected: {mode.title()}')
    if mode == 'standalone':
        print('[→] CipherDrop will bind only to this computer.')
        print('[→] Next build step: launch the local API + web UI automatically.')
    elif mode == 'server':
        print('[→] CipherDrop will be configured for LAN clients over HTTPS.')
        print('[→] Next build step: TLS + trusted network configuration.')
    else:
        print('[→] Frontend and backend will run separately with hot reload.')
        print('[→] Next build step: Vite + FastAPI developer launchers.')
    print('\nCipherDrop setup bootstrap is working.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
