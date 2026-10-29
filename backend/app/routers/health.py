from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database import get_db
from app.ml.model import model_manager
from app.config import settings

router = APIRouter(prefix="/health", tags=["Health"])

@router.get("")
def health_check(db: Session = Depends(get_db)):
    # Check DB connectivity
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    # Check ML model
    model_ok = model_manager.is_loaded()
    if not model_ok:
        try:
            model_manager.load_or_train()
            model_ok = model_manager.is_loaded()
        except Exception:
            model_ok = False

    overall_status = "healthy" if (db_ok and model_ok) else "degraded"

    return {
        "status": overall_status,
        "database": "connected" if db_ok else "unreachable",
        "model": "loaded" if model_ok else "unavailable",
        "model_version": model_manager.model_version,
        "app_version": settings.VERSION,
        "environment": "development"
    }
