from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from models.user import User

# Configuración de la conexión (ajusta según tu entorno)
CONNECTION = 'mysql+pymysql://root:administrador@localhost/login'

# Crear el motor de la base de datos
engine = create_engine(CONNECTION, echo=True)

# Crear sesión local
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    # Crear todas las tablas en la base de datos
    User.metadata.create_all(bind=engine)