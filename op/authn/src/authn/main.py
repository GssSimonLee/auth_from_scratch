# main.py
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict, Any, Tuple
import sqlite3
from contextlib import asynccontextmanager

from .settings import settings
from .db import init_db, get_conn, fetchone_dict
from .models import LoginRequest, LoginResponse, UserPublic, SessionMeResponse, LogoutRequest
from .users_client import get_user_by_username, verify_user_password, create_user_dev
from .tokens import new_session_id, new_csrf_token, session_expiries, now

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    yield
    # Shutdown (if needed)

app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

# (Optional) CORS if you'll hit this from a JS SPA during dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

def _cookie_params() -> Dict[str, Any]:
    samesite = settings.COOKIE_SAMESITE.lower()
    if samesite not in ("lax", "strict", "none"):
        samesite = "lax"
    return {
        "httponly": True,
        "secure": settings.COOKIE_SECURE,
        "samesite": samesite,  # "none" requires secure=true on modern browsers
        "path": "/",
    }

def _row_to_user_public(row: Dict[str, Any]) -> UserPublic:
    return UserPublic(
        id=row["id"],
        username=row["username"],
        email=row.get("email"),
        given_name=row.get("given_name"),
        family_name=row.get("family_name"),
    )

def _get_session(session_id: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE session_id=?;", (session_id,))
    row = cur.fetchone()
    conn.close()
    return fetchone_dict(row)

def _create_session(user_id: int, ip: Optional[str], ua: Optional[str]) -> Tuple[str, str, int, int]:
    sid = new_session_id()
    csrf = new_csrf_token()
    exp, abs_exp = session_expiries()
    n = now()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO sessions(session_id, user_id, created_at, last_seen, expires_at, absolute_expires_at, ip, user_agent, csrf_token, revoked)
        VALUES(?,?,?,?,?,?,?,?,?,0)
    """, (sid, user_id, n, n, exp, abs_exp, ip or "", ua or "", csrf))
    conn.commit()
    conn.close()
    return sid, csrf, exp, abs_exp

def _touch_session(session_id: str) -> None:
    # refresh idle TTL but not beyond absolute expiry
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT expires_at, absolute_expires_at FROM sessions WHERE session_id=? AND revoked=0;", (session_id,))
    row = cur.fetchone()
    if row:
        from .settings import settings as s
        new_exp = min(now() + s.SESSION_TTL_SECONDS, row["absolute_expires_at"])
        cur.execute("UPDATE sessions SET last_seen=?, expires_at=? WHERE session_id=?;", (now(), new_exp, session_id))
        conn.commit()
    conn.close()

def _revoke_session(session_id: str, all_for_user: bool = False) -> None:
    conn = get_conn()
    cur = conn.cursor()
    if all_for_user:
        cur.execute("SELECT user_id FROM sessions WHERE session_id=?;", (session_id,))
        r = cur.fetchone()
        if r:
            user_id = r["user_id"]
            cur.execute("UPDATE sessions SET revoked=1 WHERE user_id=?;", (user_id,))
    else:
        cur.execute("UPDATE sessions SET revoked=1 WHERE session_id=?;", (session_id,))
    conn.commit()
    conn.close()

def _get_cookie_session_id(request: Request) -> Optional[str]:
    return request.cookies.get(settings.COOKIE_NAME)

@app.get("/healthz")
def healthz():
    return {"ok": True}

# -------- DEV ONLY: create user quickly to test --------
@app.post("/dev/create-user")
def dev_create_user(payload: Dict[str, Any]):
    if not settings.DEV_MODE or not settings.DEV_LOCAL_USERS:
        raise HTTPException(status_code=403, detail="dev endpoint disabled")
    required = {"username", "password"}
    if not required.issubset(payload):
        raise HTTPException(status_code=400, detail="username/password required")
    user = create_user_dev(
        username=payload["username"],
        password=payload["password"],
        email=payload.get("email"),
        given_name=payload.get("given_name"),
        family_name=payload.get("family_name"),
        is_admin=int(bool(payload.get("is_admin", False)))
    )
    return {"user": _row_to_user_public(user).model_dump()}

# --------------------- AuthN core ----------------------

@app.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, request: Request, response: Response):
    # 1) Look up user (dev-local for M0)
    user = get_user_by_username(payload.username)
    if not user:
        raise HTTPException(status_code=401, detail="invalid_credentials")

    # optional: account lock / backoff could go here

    # 2) Verify password
    if not verify_user_password(user, payload.password):
        # optional: increment failed_attempts here
        raise HTTPException(status_code=401, detail="invalid_credentials")

    # 3) Create session
    sid, csrf, exp, abs_exp = _create_session(
        user_id=user["id"],
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
    )

    # 4) Set HttpOnly session cookie
    cookie_params = _cookie_params()
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=sid,
        **cookie_params,
        max_age=settings.SESSION_ABSOLUTE_SECONDS,
    )

    # 5) Return public user info + CSRF token
    return LoginResponse(user=_row_to_user_public(user), csrf_token=csrf)

@app.get("/session/me", response_model=SessionMeResponse)
def session_me(request: Request):
    sid = _get_cookie_session_id(request)
    if not sid:
        raise HTTPException(status_code=401, detail="no_session")

    sess = _get_session(sid)
    if not sess or sess["revoked"] == 1:
        raise HTTPException(status_code=401, detail="invalid_session")

    if sess["expires_at"] <= now() or sess["absolute_expires_at"] <= now():
        raise HTTPException(status_code=401, detail="session_expired")

    # Refresh idle TTL (sliding window) without exceeding absolute expiry
    _touch_session(sid)

    # Fetch user record for public fields
    user = get_user_by_username_by_id(sess["user_id"])
    if user is None:
        # if user deleted, invalidate session
        _revoke_session(sid, all_for_user=False)
        raise HTTPException(status_code=401, detail="user_not_found")

    return SessionMeResponse(
        session_id=sid,
        user=_row_to_user_public(user),
        expires_at=sess["expires_at"],
        absolute_expires_at=sess["absolute_expires_at"],
    )

def get_user_by_username_by_id(uid: int) -> Dict[str, Any] | None:
    # dev-local path only
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=?;", (uid,))
    row = cur.fetchone()
    conn.close()
    return fetchone_dict(row)

@app.post("/logout")
def logout(payload: LogoutRequest, request: Request, response: Response):
    sid = _get_cookie_session_id(request)
    if not sid:
        raise HTTPException(status_code=401, detail="no_session")

    # CSRF: require header matching session's csrf token
    csrf_hdr = request.headers.get("X-CSRF")
    sess = _get_session(sid)
    if not sess or sess["revoked"] == 1:
        raise HTTPException(status_code=401, detail="invalid_session")
    if not csrf_hdr or csrf_hdr != sess["csrf_token"]:
        raise HTTPException(status_code=403, detail="csrf_invalid")

    _revoke_session(sid, all_for_user=payload.all_devices)

    # Clear cookie
    response.delete_cookie(settings.COOKIE_NAME, path="/")

    return {"ok": True}
