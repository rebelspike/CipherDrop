# CipherDrop Setup

## Requirements
- Python 3.11+
- Node.js 20+ (includes npm)
- A modern browser with Web Crypto support

No Docker, PostgreSQL server, AWS account, or cloud service is required for Standalone mode.

## Start
### macOS/Linux
```bash
chmod +x start.sh
./start.sh
```

### Windows PowerShell
```powershell
.\start.ps1
```

Choose:
1. **Standalone** — binds services to this computer only. Recommended.
2. **Server** — LAN-visible development server. TLS is not implemented yet; trusted networks only.
3. **Development** — LAN-visible hot-reload development mode.

First launch automatically creates `.venv`, installs Python packages, installs npm packages, and creates `.env` with a random local secret. These generated files are ignored by Git.

## Local data
- SQLite database: `data/cipherdrop.db`
- Encrypted blobs: `data/encrypted/*.enc`

Neither is committed to Git.

## Reset development data
Stop CipherDrop, then delete `data/cipherdrop.db` and files ending in `.enc` inside `data/encrypted/`. Keep `.gitkeep`.
