from sqlalchemy import Column, Integer, String, ForeignKey, Enum
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'Usuarios'
    id = Column(Integer, primary_key=True)
    nombre_usuario = Column(String(50), nullable=False)
    correo = Column(String(100), unique=True, nullable=False)
    contraseña = Column(String(100), nullable=False)
    rol = Enum('Colaborador', 'Administrador', name='rol_usuario', nullable=False)

    