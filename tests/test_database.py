"""
tests/test_database.py
Verification suite for ShieldCI Dual-Engine Storage Architecture (PostgreSQL & SQLite Fallback).
"""

import os
import sys
import asyncio

# Ensure root dir is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.core.storage import StorageEngine, SQLiteStorageAdapter, storage
from app.main import health_check


def test_default_storage_engine():
    print("Testing default storage engine initialization...")
    assert storage.engine_type in ("sqlite", "postgresql")
    assert storage.check_connection() is True
    print(f"[OK] Default storage engine is '{storage.engine_type}' and connection check passed")


def test_health_check_database_metadata():
    print("Testing /api/health database metadata...")
    health = asyncio.run(health_check())
    assert health["status"] == "healthy"
    assert "database" in health
    assert health["database"]["engine"] in ("sqlite", "postgresql")
    assert health["database"]["connected"] is True
    assert health["features"].get("postgresql_support") is True
    print(f"[OK] Health check reports active database: {health['database']}")


def test_graceful_fallback_on_unreachable_postgres():
    print("Testing graceful fallback to SQLite on unreachable PostgreSQL URL...")
    # Attempt to initialize with an unreachable PostgreSQL URL
    bad_pg_url = "postgresql://invalid_user:invalid_pass@127.0.0.1:59999/non_existent_db"
    test_engine = StorageEngine(database_url=bad_pg_url)
    
    # Must have fallen back to SQLite without raising unhandled exceptions
    assert test_engine.engine_type == "sqlite"
    assert test_engine.check_connection() is True
    print("[OK] Graceful fallback to SQLite on unreachable PostgreSQL verified successfully")


if __name__ == "__main__":
    print("=" * 50)
    print(" ShieldCI Database & Dual-Engine Test Suite ")
    print("=" * 50)
    test_default_storage_engine()
    test_health_check_database_metadata()
    test_graceful_fallback_on_unreachable_postgres()
    print("=" * 50)
    print(" ALL DATABASE TESTS COMPLETED SUCCESSFULLY! ")
    print("=" * 50)
