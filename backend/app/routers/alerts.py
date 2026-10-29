import io
import csv
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import ThreatAlert
from app.schemas import AlertStatusUpdate, AlertNotesUpdate

router = APIRouter(prefix="/alerts", tags=["Threat Alerts"])

@router.get("")
def list_threat_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ThreatAlert)

    if status:
        query = query.filter(ThreatAlert.status == status.upper())
    if severity:
        query = query.filter(ThreatAlert.severity == severity.upper())
    if search:
        query = query.filter(ThreatAlert.hostname.ilike(f"%{search.strip()}%"))
    if source:
        query = query.filter(ThreatAlert.source == source.upper())

    total = query.count()
    offset = (page - 1) * page_size
    alerts = query.order_by(desc(ThreatAlert.timestamp)).offset(offset).limit(page_size).all()

    items = []
    for a in alerts:
        reasons = json.loads(a.reasons_json) if a.reasons_json else []
        items.append({
            "id": a.id,
            "alert_uid": a.alert_uid,
            "analysis_id": a.analysis_id,
            "hostname": a.hostname,
            "risk_score": a.risk_score,
            "severity": a.severity,
            "status": a.status,
            "source": a.source,
            "reasons": reasons,
            "notes": a.notes,
            "timestamp": a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp),
            "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None
        })

    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size if total > 0 else 1,
        "items": items
    }

@router.get("/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    reasons = json.loads(alert.reasons_json) if alert.reasons_json else []
    return {
        "id": alert.id,
        "alert_uid": alert.alert_uid,
        "analysis_id": alert.analysis_id,
        "hostname": alert.hostname,
        "risk_score": alert.risk_score,
        "severity": alert.severity,
        "status": alert.status,
        "source": alert.source,
        "reasons": reasons,
        "notes": alert.notes,
        "timestamp": alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp),
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None
    }

@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db)
):
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    now = datetime.now(timezone.utc)
    new_status = payload.status.upper()
    alert.status = new_status

    if new_status == "ACKNOWLEDGED":
        alert.acknowledged_at = now
    elif new_status == "RESOLVED":
        alert.resolved_at = now
    elif new_status == "OPEN":
        # Reopening alert
        alert.resolved_at = None

    if payload.notes:
        if alert.notes:
            alert.notes += f"\n[{now.strftime('%Y-%m-%d %H:%M')}] Status changed to {new_status}: {payload.notes}"
        else:
            alert.notes = f"[{now.strftime('%Y-%m-%d %H:%M')}] Status changed to {new_status}: {payload.notes}"

    db.commit()
    db.refresh(alert)
    return {
        "id": alert.id,
        "alert_uid": alert.alert_uid,
        "status": alert.status,
        "notes": alert.notes,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None
    }

@router.patch("/{alert_id}/notes")
def update_alert_notes(
    alert_id: int,
    payload: AlertNotesUpdate,
    db: Session = Depends(get_db)
):
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.notes = payload.notes
    db.commit()
    db.refresh(alert)
    return {"id": alert.id, "alert_uid": alert.alert_uid, "notes": alert.notes}

@router.get("/export/csv")
def export_alerts_csv(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ThreatAlert)
    if status:
        query = query.filter(ThreatAlert.status == status.upper())
    if severity:
        query = query.filter(ThreatAlert.severity == severity.upper())

    alerts = query.order_by(desc(ThreatAlert.timestamp)).limit(2000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Alert UID", "Hostname", "Risk Score", "Severity", "Status",
        "Source", "Timestamp", "Acknowledged At", "Resolved At", "Notes"
    ])

    for a in alerts:
        writer.writerow([
            a.alert_uid,
            a.hostname,
            a.risk_score,
            a.severity,
            a.status,
            a.source,
            a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp),
            a.acknowledged_at.isoformat() if a.acknowledged_at else "",
            a.resolved_at.isoformat() if a.resolved_at else "",
            a.notes or ""
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dns_shield_alerts.csv"}
    )
