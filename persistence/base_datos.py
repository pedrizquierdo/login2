from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Configuración de la conexión (ajusta según tu entorno)
CONNECTION = 'mysql+pymysql://root:Admin@localhost/login'

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
    from entitie.usuario import Usuario
