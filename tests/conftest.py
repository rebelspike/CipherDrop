"""Run tests against isolated local data: never touch a developer vault."""
import os
import sys
import tempfile
from pathlib import Path

_TEST_DATA = tempfile.TemporaryDirectory(prefix="cipherdrop-security-tests-")
os.environ["CIPHERDROP_DATA_DIR"] = _TEST_DATA.name
os.environ["CIPHERDROP_ENV"] = "development"
os.environ["CIPHERDROP_COOKIE_SECURE"] = "false"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c
