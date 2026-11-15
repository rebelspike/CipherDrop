# Setup Guide
## [Your Application Name]

This guide lets someone unfamiliar with the project get it running from scratch.

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | Or your language/runtime |
| [Database] | [Version] | e.g., SQLite (built-in) or PostgreSQL 15 |
| [Other dependency] | [Version] | |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourteam/your-repo.git
cd your-repo
```

### 2. Create a virtual environment (Python)

```bash
python -m venv venv
source venv/bin/activate        # macOS / Linux
# or: venv\Scripts\activate     # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy the example environment file and fill in required values:

```bash
cp .env.example .env
```

Edit `.env`:

```
SECRET_KEY=your-random-secret-key-here   # generate with: python -c "import secrets; print(secrets.token_hex(32))"
DATABASE_URL=sqlite:///app.db            # or your database connection string
# Add any other required variables
```

**Important:** Never commit `.env` to git. The `.gitignore` should already exclude it.

### 5. Initialize the database

```bash
python init_db.py
# or: flask db upgrade (if using Flask-Migrate)
```

---

## Running the Application

```bash
python app.py
```

Open your browser to: `http://localhost:5000`

### Default accounts (development only)

| Username | Password | Role |
|---|---|---|
| admin@example.com | [see .env.example] | Admin |
| viewer@example.com | [see .env.example] | Viewer |

**These accounts exist only in development. Production setup requires creating accounts manually.**

---

## Running with Docker (optional)

```bash
docker build -t myapp .
docker run -p 5000:5000 --env-file .env myapp
```

---

## Troubleshooting

**Error: `ModuleNotFoundError: No module named 'cryptography'`**
→ Make sure your virtual environment is activated and you ran `pip install -r requirements.txt`.

**Error: `DATABASE_URL not set`**
→ Make sure you copied `.env.example` to `.env` and filled in the values.

**[Add other common errors and fixes here]**

---

## CLI Tools (if applicable)

If your application includes CLI components, document them here:

```bash
python cli.py --help
# Output:
# Usage: cli.py [OPTIONS] COMMAND
# ...
```

| Command | Description | Example |
|---|---|---|
| `cli.py encrypt <file>` | Encrypt a file | `python cli.py encrypt secret.txt` |
| [command] | [description] | [example] |
