"""
Idempotent database initialization.

Creates missing tables. Never drops, truncates, or overwrites existing data.
Safe to run multiple times.

Usage:
    python -m backend.database.init_db
"""

import logging
import sys

from backend.database.connection import (
    get_engine,
    DatabaseConfigError,
    check_connection,
)
from backend.database import models  # noqa: F401  (registers models on Base.metadata)
from backend.database.connection import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vibeguard.init_db")


def init_db() -> bool:
    try:
        engine = get_engine()
    except DatabaseConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return False

    if not check_connection():
        logger.error(
            "Unable to connect to PostgreSQL. Check that PostgreSQL is running "
            "and DATABASE_URL contains the correct credentials and database name."
        )
        return False

    # create_all only creates tables that do not already exist; it never
    # drops or truncates existing tables/data.
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema is up to date (reports, findings, scan_metadata).")
    return True


if __name__ == "__main__":
    success = init_db()
    sys.exit(0 if success else 1)
