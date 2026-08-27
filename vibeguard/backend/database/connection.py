"""
Database connection management for VibeGuard.

Reads DATABASE_URL from the environment (never hardcoded) and exposes
a SQLAlchemy engine + session factory. All credential-bearing strings
are kept out of logs and error messages returned to clients.
"""

import logging
import os
from contextlib import contextmanager
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError, ArgumentError
from sqlalchemy.orm import sessionmaker, Session, declarative_base

load_dotenv()

logger = logging.getLogger("vibeguard.database")

DATABASE_URL = os.getenv("DATABASE_URL")

Base = declarative_base()

_engine = None
_SessionLocal = None


class DatabaseConfigError(Exception):
    """Raised when DATABASE_URL is missing or malformed."""


class DatabaseConnectionError(Exception):
    """Raised when PostgreSQL cannot be reached. Message is safe to show to users."""


def _build_engine():
    global _engine, _SessionLocal

    if not DATABASE_URL:
        raise DatabaseConfigError(
            "DATABASE_URL is not set. Create a .env file based on .env.example "
            "and set DATABASE_URL to your PostgreSQL connection string."
        )

    if not DATABASE_URL.startswith("postgresql://") and not DATABASE_URL.startswith(
        "postgresql+psycopg2://"
    ):
        raise DatabaseConfigError(
            "DATABASE_URL must be a PostgreSQL connection string "
            "(postgresql://user:password@host:port/dbname). SQLite and other "
            "database backends are not supported."
        )

    try:
        engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            future=True,
        )
    except ArgumentError as exc:
        # Never echo the raw connection string, it may contain a password.
        raise DatabaseConfigError(
            "Invalid DATABASE_URL. Check the format and try again."
        ) from exc

    _engine = engine
    _SessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=_engine, future=True
    )
    return _engine


def get_engine():
    if _engine is None:
        return _build_engine()
    return _engine


def get_session_factory():
    if _SessionLocal is None:
        get_engine()
    return _SessionLocal


def check_connection() -> bool:
    """
    Returns True if PostgreSQL is reachable, False otherwise.
    Never raises — callers (e.g. /api/health) should treat this as a boolean signal.
    """
    try:
        engine = get_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except (DatabaseConfigError, OperationalError, ProgrammingError, Exception) as exc:
        logger.warning("Database connectivity check failed: %s", type(exc).__name__)
        return False


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context-manager style session, for use outside of FastAPI's Depends().
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency. Yields a SQLAlchemy session and guarantees cleanup.
    Raises DatabaseConnectionError (safe message) if the engine cannot be built.
    """
    try:
        factory = get_session_factory()
    except DatabaseConfigError as exc:
        raise DatabaseConnectionError(str(exc)) from exc

    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
