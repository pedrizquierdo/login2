from bcrypt import hashpw, gensalt, checkpw
import re

def hash_password(password: str) -> str:
    """Hash a password using bcrypt and return as string."""
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password) -> bool:
    """Verify a hashed password against a plain password."""
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return checkpw(plain_password.encode('utf-8'), hashed_password)

def is_strong_password(password: str) -> bool:
    """Check if password meets strength requirements"""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True