from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timezone, timedelta
import json

from app.database import get_db
from app.models import DnsAnalysis, ThreatAlert
from app.ml.model import model_manager
from app.services.stream_manager import stream_engine

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    total_queries = db.query(func.count(DnsAnalysis.id)).scalar() or 0
    suspicious_queries = db.query(func.count(DnsAnalysis.id)).filter(DnsAnalysis.is_suspicious == True).scalar() or 0
    high_risk_queries = db.query(func.count(DnsAnalysis.id)).filter(DnsAnalysis.severity == "HIGH").scalar() or 0
    critical_queries = db.query(func.count(DnsAnalysis.id)).filter(DnsAnalysis.severity == "CRITICAL").scalar() or 0
    
    detection_rate_pct = round((suspicious_queries / total_queries * 100.0), 2) if total_queries > 0 else 0.0
    open_alerts_count = db.query(func.count(ThreatAlert.id)).filter(ThreatAlert.status == "OPEN").scalar() or 0

    # Risk distribution (User requested bands: 0-24 Low, 25-49 Moderate, 50-74 High, 75-100 Critical)
    low_count = db.query(func.count(DnsAnalysis.id)).filter(DnsAnalysis.severity == "LOW").scalar() or 0
    med_count = db.query(func.count(DnsAnalysis.id)).filter(DnsAnalysis.severity.in_(["MODERATE", "MEDIUM"])).scalar() or 0
    high_count = high_risk_queries
    crit_count = critical_queries

    # Top 5 suspicious domains
    top_domains_query = (
        db.query(
            DnsAnalysis.hostname,
            func.count(DnsAnalysis.id).label("count"),
            func.max(DnsAnalysis.risk_score).label("max_risk"),
            func.max(DnsAnalysis.timestamp).label("last_seen"),
            DnsAnalysis.severity
        )
        .filter(DnsAnalysis.is_suspicious == True)
        .group_by(DnsAnalysis.hostname)
        .order_by(desc("count"), desc("max_risk"))
        .limit(5)
        .all()
    )

    top_domains = [
        {
            "hostname": d.hostname,
            "count": d.count,
            "max_risk_score": d.max_risk,
            "severity": d.severity,
            "last_detected": d.last_seen.isoformat() if hasattr(d.last_seen, "isoformat") else str(d.last_seen)
        }
        for d in top_domains_query
    ]

    # Activity over time (last 12 time buckets)
    now = datetime.now(timezone.utc)
    activity_buckets = []
    for i in range(11, -1, -1):
        bucket_start = now - timedelta(hours=i + 1)
        bucket_end = now - timedelta(hours=i)
        
        t_count = db.query(func.count(DnsAnalysis.id)).filter(
            DnsAnalysis.timestamp >= bucket_start,
            DnsAnalysis.timestamp < bucket_end
        ).scalar() or 0

        s_count = db.query(func.count(DnsAnalysis.id)).filter(
            DnsAnalysis.timestamp >= bucket_start,
            DnsAnalysis.timestamp < bucket_end,
            DnsAnalysis.is_suspicious == True
        ).scalar() or 0

        label = bucket_start.strftime("%H:%M")
        activity_buckets.append({
            "time_label": label,
            "total": t_count,
            "suspicious": s_count
        })

    # Recent Alerts (last 5)
    recent_alerts_query = (
        db.query(ThreatAlert)
        .order_by(desc(ThreatAlert.timestamp))
        .limit(5)
        .all()
    )
    recent_alerts = [
        {
            "id": a.id,
            "alert_uid": a.alert_uid,
            "hostname": a.hostname,
            "risk_score": a.risk_score,
            "severity": a.severity,
            "status": a.status,
            "source": a.source,
            "timestamp": a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp)
        }
        for a in recent_alerts_query
    ]

    return {
        "stats": {
            "total_queries": total_queries,
            "suspicious_queries": suspicious_queries,
            "high_risk_queries": high_risk_queries,
            "critical_queries": critical_queries,
            "detection_rate_pct": detection_rate_pct,
            "open_alerts_count": open_alerts_count,
            "monitoring_status": stream_engine.status,
            "model_status": "ONLINE" if model_manager.is_loaded() else "OFFLINE",
            "database_status": "CONNECTED"
        },
        "risk_distribution": {
            "low": low_count,
            "medium": med_count,
            "high": high_count,
            "critical": crit_count
        },
        "activity_timeline": activity_buckets,
        "top_suspicious_domains": top_domains,
        "recent_alerts": recent_alerts
    }
