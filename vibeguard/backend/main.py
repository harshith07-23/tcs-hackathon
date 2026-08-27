import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.api import health, scans, reports
from backend.database.connection import (
    get_engine,
    check_connection,
    DatabaseConfigError,
    DatabaseConnectionError,
)
from backend.database import models  # noqa: F401  registers models on Base.metadata
from backend.database.connection import Base

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vibeguard.main")

app = FastAPI(
    title="VibeGuard API",
    description="AI-generated code security scanner — deterministic analysis + Gemini reasoning.",
    version="0.1.0",
)

# CORS: explicit allowlist rather than a wildcard, configurable via env for deployment.
_allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _allowed_origins if o.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    """
    Automatically create missing tables on startup. Never drops or resets
    existing data (see backend/database/init_db.py for the equivalent
    standalone script).
    """
    try:
        engine = get_engine()
        if check_connection():
            Base.metadata.create_all(bind=engine)
            logger.info("Connected to PostgreSQL and verified schema.")
        else:
            logger.warning(
                "Could not connect to PostgreSQL at startup. The API will start, "
                "but database-backed endpoints will report a degraded status "
                "until connectivity is restored."
            )
    except DatabaseConfigError as exc:
        logger.warning("Database not configured: %s", exc)


@app.exception_handler(DatabaseConnectionError)
async def db_connection_error_handler(request: Request, exc: DatabaseConnectionError):
    return JSONResponse(
        status_code=503,
        content={"detail": str(exc)},
    )


app.include_router(health.router)
app.include_router(scans.router)
app.include_router(reports.router)


@app.get("/")
def root():
    return {
        "service": "VibeGuard API",
        "docs": "/docs",
        "health": "/api/health",
    }
