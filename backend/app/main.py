import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import engine, Base
from app.models import DnsAnalysis, ThreatAlert, SystemSetting, MonitoringSession
from app.ml.model import model_manager
from app.routers import (
    health,
    dashboard,
    analysis,
    alerts,
    monitoring,
    model_info,
    settings as settings_router
)

# Ensure tables are created immediately upon module load
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize Database Tables
    Base.metadata.create_all(bind=engine)
    
    # 2. Load or Train ML Model
    try:
        model_manager.load_or_train()
        print(f"[*] DNS Shield ML Model ready: {model_manager.model_version}")
    except Exception as e:
        print(f"[!] Warning: ML model initialization encountered error: {e}")

    yield

    # Clean shutdown of streaming engine
    from app.services.stream_manager import stream_engine
    stream_engine.stop()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="DNS Shield AI — Enterprise DNS Tunneling Detection & Threat Monitoring System",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include Routers under /api
app.include_router(health.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(monitoring.router, prefix="/api")
app.include_router(model_info.router, prefix="/api")
app.include_router(settings_router.router, prefix="/api")

@app.get("/")
def root():
    return {
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "docs": "/docs",
        "api_endpoints": {
            "health": "/api/health",
            "dashboard": "/api/dashboard/summary",
            "analysis": "/api/analysis/single",
            "batch_analysis": "/api/analysis/batch",
            "threat_alerts": "/api/alerts",
            "live_monitoring": "/api/monitoring/status",
            "model_insights": "/api/model/info",
            "settings": "/api/settings"
        }
    }
