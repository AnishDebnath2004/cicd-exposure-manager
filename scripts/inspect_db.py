"""
scripts/inspect_db.py
Convenience utility to inspect and view records stored in the ShieldCI SQLite database.

Usage:
    python scripts/inspect_db.py              # Shows all tables
    python scripts/inspect_db.py users        # Shows registered user accounts
    python scripts/inspect_db.py scans        # Shows recent scan history
    python scripts/inspect_db.py settings     # Shows configured system settings
    python scripts/inspect_db.py schedules    # Shows continuous schedules
"""

import os
import sys
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "shieldci.db")


def print_table(title, headers, rows):
    print(f"\n=== {title} ({len(rows)} records) ===")
    if not rows:
        print("  (empty)")
        return

    col_widths = [len(h) for h in headers]
    str_rows = []
    for r in rows:
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
    if not os.path.isfile(DB_PATH):
        print(f"Database file not found at: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    table_filter = sys.argv[1].lower() if len(sys.argv) > 1 else None

    # Users
    if not table_filter or table_filter in ("users", "user"):
        cursor.execute("SELECT id, email, full_name, organization, role, created_at, token_version FROM users ORDER BY created_at DESC")
        rows = cursor.fetchall()
        print_table("Registered Users", ["ID", "Email", "Full Name", "Organization", "Role", "Created At", "Ver"], rows)

    # Scans
    if not table_filter or table_filter in ("scans", "scan"):
        cursor.execute("SELECT scan_id, target_path, target_type, policy_passed, pipeline_exposure_score, user_email, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10")
        rows = cursor.fetchall()
        print_table("Recent Scans (Last 10)", ["Scan ID", "Target", "Type", "Passed", "PES", "User", "Timestamp"], rows)

    # Settings
    if not table_filter or table_filter in ("settings", "system_settings"):
        cursor.execute("SELECT key, updated_at, value_json FROM system_settings")
        rows = cursor.fetchall()
        print_table("System Settings", ["Key", "Updated At", "Value Preview"], [(r["key"], r["updated_at"], r["value_json"][:45] + "...") for r in rows])

    # Schedules
    if not table_filter or table_filter in ("schedules", "schedule"):
        cursor.execute("SELECT id, target, target_type, interval_minutes, enabled, user_email FROM schedules")
        rows = cursor.fetchall()
        print_table("Continuous Schedules", ["ID", "Target", "Type", "Interval (m)", "Enabled", "User"], rows)

    conn.close()


if __name__ == "__main__":
    inspect()
