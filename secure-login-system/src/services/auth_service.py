from sqlalchemy.orm import Session
from models.user import User
from utils.password_utils import hash_password, verify_password

def register_user(db: Session, username: str, email: str, password: str, role: str):
    hashed_password = hash_password(password)
    new_user = User(username=username, email=email, password=hashed_password, role=role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def validate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if user and verify_password(password, user.password):
        return user
    return None

def get_user_role(user: User):
    return user.role

def is_admin(user: User):
    return user.role == 'Administrador'