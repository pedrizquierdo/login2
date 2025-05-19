from sqlalchemy.orm import Session
from models.user import User
from utils.password_utils import hash_password, verify_password

def create_user(db: Session, username: str, email: str, password: str, role: str):
    hashed_password = hash_password(password)
    new_user = User(username=username, email=email, password=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def validate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if user and verify_password(password, user.password):
        return user
    return None

def get_all_users(db: Session):
    return db.query(User).all()