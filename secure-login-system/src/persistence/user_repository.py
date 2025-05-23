from sqlalchemy.orm import Session
from models.user import User
from utils.password_utils import hash_password, verify_password

def create_user(db: Session, username: str, email: str, password: str, role: str):
    
    new_user = User(username=username, email=email, password=password, role=role)
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

def delete_user_by_id(db: Session, user_id: int):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        db.delete(user)
        db.commit()
        return True
    return False


def update_user(db: Session, user_id: int, username: str = None, email: str = None, role: str = None):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False
    
    if username:
        user.username = username
    if email:
        user.email = email
    if role:
        user.role = role
    
    db.commit()
    db.refresh(user)
    return True

def change_password(db: Session, user_id: int, new_password: str):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False
    
    hashed_password = hash_password(new_password)
    user.password = hashed_password
    db.commit()
    return True