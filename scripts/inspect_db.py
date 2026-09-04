"""
scripts/inspect_db.py
Database Inspection Tool: Inspects records stored in the active ShieldCI database (PostgreSQL or SQLite).

Usage:
    python scripts/inspect_db.py              # Shows summary and all tables
    python scripts/inspect_db.py users        # Shows registered user accounts
    python scripts/inspect_db.py scans        # Shows recent scan history
    python scripts/inspect_db.py settings     # Shows configured system settings
    python scripts/inspect_db.py schedules    # Shows continuous schedules
"""

import os
import sys

# Ensure root dir is in sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.config import settings
from app.core.storage import storage


def print_table(title, headers, rows):
    print(f"\n=== {title} ({len(rows)} records) ===")
    if not rows:
        print("  (empty)")
        return

    col_widths = [len(h) for h in headers]
    str_rows = []
    for r in rows:
        if isinstance(r, dict):
            row_strs = [str(r.get(h.lower().replace(" ", "_"), "-")) for h in headers]
        else:
            row_strs = [str(val) if val is not None else "-" for val in r]
        str_rows.append(row_strs)
        for i, val in enumerate(row_strs):
            disp = val if len(val) <= 40 else val[:37] + "..."
            col_widths[i] = max(col_widths[i], len(disp))

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    divider = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    print(header_line)
    print(divider)
    for r in str_rows:
        line_parts = []
        for i, val in enumerate(r):
            disp = val if len(val) <= 40 else val[:37] + "..."
            line_parts.append(disp.ljust(col_widths[i]))
        print(" | ".join(line_parts))


def inspect():
    engine = storage.engine_type.upper()
    is_connected = storage.check_connection()

    print("=" * 60)
    print(f" ShieldCI Database Inspector ")
    print(f" Active Engine: {engine}")
    print(f" Status:        {'CONNECTED (Healthy)' if is_connected else 'DISCONNECTED / ERROR'}")
    if engine == "SQLITE":
        print(f" Database File: {storage.db_path}")
    else:
        # Mask password in URL for display
        url = settings.normalized_database_url or ""
        masked_url = url
        if "@" in url and "://" in url:
            prefix, rest = url.split("://", 1)
            creds, host_part = rest.split("@", 1)
            user = creds.split(":")[0] if ":" in creds else creds
            masked_url = f"{prefix}://{user}:****@{host_part}"
        print(f" Remote Target: {masked_url}")
    print("=" * 60)

    if not is_connected:
        print("[!] Could not establish connection to the active database.")
        return

    table_filter = sys.argv[1].lower() if len(sys.argv) > 1 else None

    # Retrieve connection and cursor via storage adapter
    adapter = storage.adapter

    with adapter._get_connection() as conn:
        if storage.engine_type == "postgresql":
            cursor = adapter._get_cursor(conn)
        else:
            cursor = conn.cursor()

        # Row counts summary
        if not table_filter:
            print("\nTable Row Counts:")
            for tbl in ("users", "scans", "schedules", "guest_quotas", "system_settings"):
                try:
                    cursor.execute(f"SELECT COUNT(*) as cnt FROM {tbl}")
                    res = cursor.fetchone()
                    count = res["cnt"] if isinstance(res, dict) or hasattr(res, "keys") else res[0]
                    print(f"  - {tbl.ljust(18)}: {count} rows")
                except Exception as e:
                    print(f"  - {tbl.ljust(18)}: error ({e})")

        # Users
        if not table_filter or table_filter in ("users", "user"):
            cursor.execute("SELECT id, email, full_name, organization, role, created_at, token_version FROM users ORDER BY created_at DESC LIMIT 20")
            rows = cursor.fetchall()
            print_table("Registered Users (Top 20)", ["ID", "Email", "Full Name", "Organization", "Role", "Created At", "Ver"], [
                (r["id"], r["email"], r["full_name"], r["organization"], r["role"], r["created_at"], r["token_version"] if "token_version" in r.keys() else 1)
                for r in rows
            ])

        # Scans
        if not table_filter or table_filter in ("scans", "scan"):
            cursor.execute("SELECT scan_id, target_path, target_type, policy_passed, pipeline_exposure_score, user_email, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10")
            rows = cursor.fetchall()
            print_table("Recent Scans (Last 10)", ["Scan ID", "Target", "Type", "Passed", "PES", "User", "Timestamp"], [
                (r["scan_id"], r["target_path"], r["target_type"] if "target_type" in r.keys() else "repository", bool(r["policy_passed"]), r["pipeline_exposure_score"], r["user_email"] if "user_email" in r.keys() else None, r["timestamp"])
                for r in rows
            ])

        # Settings
        if not table_filter or table_filter in ("settings", "system_settings"):
            cursor.execute("SELECT key, updated_at, value_json FROM system_settings")
            rows = cursor.fetchall()
            print_table("System Settings", ["Key", "Updated At", "Value Preview"], [
                (r["key"], r["updated_at"], r["value_json"][:45] + "...")
                for r in rows
            ])

        # Schedules
        if not table_filter or table_filter in ("schedules", "schedule"):
            cursor.execute("SELECT id, target, target_type, interval_minutes, enabled, user_email FROM schedules")
            rows = cursor.fetchall()
            print_table("Continuous Schedules", ["ID", "Target", "Type", "Interval (m)", "Enabled", "User"], [
                (r["id"], r["target"], r["target_type"] if "target_type" in r.keys() else "repository", r["interval_minutes"], bool(r["enabled"]), r["user_email"] if "user_email" in r.keys() else None)
                for r in rows
            ])


if __name__ == "__main__":
    inspect()
