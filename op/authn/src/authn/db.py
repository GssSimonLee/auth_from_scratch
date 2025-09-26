# db.py
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional
from .settings import settings

DB_PATH = Path(settings.DB_PATH)

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    cur = conn.cursor()

    # Improve concurrency for dev
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")

    # Sessions table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen  INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        absolute_expires_at INTEGER NOT NULL,
        ip         TEXT,
        user_agent TEXT,
        csrf_token TEXT NOT NULL,
        revoked    INTEGER NOT NULL DEFAULT 0
    );""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);")

    # DEV-ONLY: local users table (to let you test M0 without Users service)
    if settings.DEV_LOCAL_USERS:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            given_name TEXT,
            family_name TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER,
            password_changed_at INTEGER NOT NULL
        );""")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);")

    conn.commit()
    conn.close()

def fetchone_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return dict(row) if row else None
