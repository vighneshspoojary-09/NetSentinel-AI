"""Database setup: connects SQLAlchemy to the SQLite file."""
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()  # reads settings from the .env file

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/netsentinel.db")

# Make sure the data/ folder exists so SQLite can create its file there.
os.makedirs("data", exist_ok=True)

# check_same_thread=False is needed because FastAPI may use several threads.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)


@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    """SQLite ignores foreign keys unless we switch them on for every connection."""
    if dbapi_connection.__class__.__module__.startswith("sqlite3"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    """FastAPI dependency: gives each request its own database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
