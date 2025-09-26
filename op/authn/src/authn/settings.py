# settings.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "authn"
    HOST: str = "127.0.0.1"
    PORT: int = 7000

    DB_PATH: str = "./authn.db"

    COOKIE_NAME: str = "op_sid"
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"  # "lax" | "strict" | "none"

    SESSION_TTL_SECONDS: int = 8 * 60 * 60      # 8h
    SESSION_ABSOLUTE_SECONDS: int = 30 * 24 * 60 * 60  # 30d

    DEV_MODE: bool = True
    DEV_LOCAL_USERS: bool = True
    USERS_BASE_URL: str | None = None  # for future external Users service

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
