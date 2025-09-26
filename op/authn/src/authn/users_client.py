# users_client.py
import sqlite3
import time
from typing import Optional, Dict, Any
from .db import get_conn, fetchone_dict
from .security import hash_password, verify_password
from .settings import settings

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?;", (username,))
    row = cur.fetchone()
    conn.close()
    return fetchone_dict(row)

def create_user_dev(username: str, password: str, email: str | None = None,
                    given_name: str | None = None, family_name: str | None = None,
                    is_admin: int = 0) -> Dict[str, Any]:
    assert settings.DEV_LOCAL_USERS, "DEV_LOCAL_USERS is false"
    conn = get_conn()
    cur = conn.cursor()
    now = int(time.time())
    cur.execute("""
        INSERT INTO users(username, password_hash, email, given_name, family_name, is_admin, password_changed_at)
        VALUES(?,?,?,?,?,?,?)
    """, (username, hash_password(password), email, given_name, family_name, is_admin, now))
    conn.commit()
    cur.execute("SELECT * FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return fetchone_dict(row)  # type: ignore[return-value]

def verify_user_password(user: Dict[str, Any], password: str) -> bool:
    return verify_password(password, user["password_hash"])
