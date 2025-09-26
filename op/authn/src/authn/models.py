# models.py
from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str

class UserPublic(BaseModel):
    id: int
    username: str
    email: str | None = None
    given_name: str | None = None
    family_name: str | None = None

class LoginResponse(BaseModel):
    user: UserPublic
    csrf_token: str   # return CSRF for subsequent state-changing calls

class SessionMeResponse(BaseModel):
    session_id: str
    user: UserPublic
    expires_at: int
    absolute_expires_at: int

class LogoutRequest(BaseModel):
    all_devices: bool = False
