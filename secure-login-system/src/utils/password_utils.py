from bcrypt import hashpw, gensalt, checkpw

def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt."""
    return hashpw(password.encode('utf-8'), gensalt())

def verify_password(plain_password: str, hashed_password) -> bool:
    """Verify a hashed password against a plain password."""
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return checkpw(plain_password.encode('utf-8'), hashed_password)