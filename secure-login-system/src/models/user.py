from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy.orm import declarative_base
from sqlalchemy.ext.declarative import declared_attr

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    role = Column(Enum('Collaborator', 'Administrator', name='user_role'), nullable=False)

    
    def __init__(self, username, email, password, role='Collaborator'):
        self.username = username
        self.email = email
        self.password = password
        self.role = role