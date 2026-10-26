"""database.py - all SQLite code. Every query uses ? placeholders (no SQL injection)."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

MAX_ROWS = 500  # old rows are deleted automatically so the file stays small


def _connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path):
    with closing(_connect(db_path)) as conn, conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            indicators TEXT NOT NULL,      -- JSON list of indicator titles
            result_json TEXT NOT NULL,     -- full result so it can be revisited
            scanned_at TEXT NOT NULL)""")


def save_scan(db_path, result):
    """Store a result; returns (scan_id, timestamp). No IP address or user data is stored."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    titles = [i["title"] for i in result["indicators"]]
    with closing(_connect(db_path)) as conn, conn:
        cur = conn.execute(
            "INSERT INTO scans (url, risk_score, risk_level, indicators, result_json, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (result["url"], result["score"], result["level"], json.dumps(titles),
             json.dumps(result), stamp))
        conn.execute("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                     (MAX_ROWS,))
        return cur.lastrowid, stamp


def get_recent(db_path, limit=20):
    with closing(_connect(db_path)) as conn:
        rows = conn.execute("SELECT id, url, risk_score, risk_level, indicators, scanned_at "
                            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "url": r["url"], "risk_score": r["risk_score"],
             "risk_level": r["risk_level"], "indicators": json.loads(r["indicators"]),
             "scanned_at": r["scanned_at"]} for r in rows]


def get_scan(db_path, scan_id):
    with closing(_connect(db_path)) as conn:
        row = conn.execute("SELECT id, result_json, scanned_at FROM scans WHERE id = ?",
                           (scan_id,)).fetchone()
    if row is None:
        return None
    return {"id": row["id"], "scanned_at": row["scanned_at"], "result": json.loads(row["result_json"])}


def clear_history(db_path):
    with closing(_connect(db_path)) as conn, conn:
        return conn.execute("DELETE FROM scans").rowcount
