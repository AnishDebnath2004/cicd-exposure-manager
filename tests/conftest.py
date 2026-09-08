"""
tests/conftest.py
Global pytest configuration and isolation fixture.
Ensures that all automated tests execute against an isolated temporary SQLite database,
preventing any test accounts, scans, or schedules from ever touching or being added to
the real/remote PostgreSQL database.
"""
import os
import sys
import shutil
import tempfile
# pyrefly: ignore [missing-import]
import pytest

# Ensure root directory is on sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.config import settings
from app.core.storage import storage, SQLiteStorageAdapter


@pytest.fixture(scope="session", autouse=True)
def isolate_test_database():
    """
    Session-wide fixture that redirects storage to an isolated temporary SQLite DB
    so that tests never pollute PostgreSQL or permanent SQLite with test users.
    """
    # Create isolated temp test DB directory
    temp_dir = tempfile.mkdtemp(prefix="shieldci_test_")
    test_db_path = os.path.join(temp_dir, "test_shieldci.db")

    # Store original state
    orig_engine_type = storage.engine_type
    orig_adapter = storage.adapter
    orig_db_url = settings.DATABASE_URL
    orig_db_path = settings.DB_PATH

    # Switch to isolated SQLite test adapter
    settings.DATABASE_URL = None
    settings.DB_PATH = test_db_path

    test_adapter = SQLiteStorageAdapter(test_db_path)
    storage.adapter = test_adapter
    storage.engine_type = "sqlite"
    storage.refresh()

    yield

    # Teardown: remove temporary test directory
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass

    # Restore original storage configuration
    settings.DATABASE_URL = orig_db_url
    settings.DB_PATH = orig_db_path
    storage.adapter = orig_adapter
    storage.engine_type = orig_engine_type
    storage.refresh()
