# security.py
import bcrypt

def hash_password(plain: str) -> str:
    # Truncate password to 72 bytes to avoid bcrypt limit
    password_bytes = plain.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12)).decode('utf-8')
    return hashed

def verify_password(plain: str, hashed: str) -> bool:
    # Truncate password to 72 bytes to match hashing
    password_bytes = plain.encode('utf-8')
    hashed_bytes = hashed.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)
