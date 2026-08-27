from fastapi import APIRouter

from backend.database.connection import check_connection
from backend.services import gemini_service

router = APIRouter(tags=["health"])


@router.get("/api/health")
def health_check():
    db_ok = check_connection()
    gemini_ok = gemini_service.is_configured()

    status = "healthy" if db_ok else "degraded"

    return {
        "status": status,
        "database": "connected" if db_ok else "disconnected",
        "ml_model": "loaded" if gemini_ok else "unavailable",
    }
