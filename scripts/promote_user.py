"""
Promotes anish2004bmg@gmail.com to administrator and verifies all users.
"""
import sys
import os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app.core.storage import storage

print("Connecting to storage...")
with storage.adapter._get_connection() as conn:
    with storage.adapter._get_cursor(conn) as cur:
        cur.execute("UPDATE users SET role = 'admin' WHERE email = 'anish2004bmg@gmail.com'")
        conn.commit()

storage.refresh()

print("\n--- Current Users in Database ---")
with storage.adapter._get_connection() as conn:
    with storage.adapter._get_cursor(conn) as cur:
        cur.execute("SELECT id, email, full_name, role, preferred_domain FROM users")
        for r in cur.fetchall():
            print(" ", r)

# Also check SQLite fallback
sqlite_path = os.path.join(ROOT_DIR, "data", "shieldci.db")
if os.path.exists(sqlite_path):
    import sqlite3
    sconn = sqlite3.connect(sqlite_path)
    scur = sconn.cursor()
    scur.execute("UPDATE users SET role = 'admin' WHERE email = 'anish2004bmg@gmail.com'")
    sconn.commit()
    sconn.close()
    print("Updated SQLite fallback if present.")
