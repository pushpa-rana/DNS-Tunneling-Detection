import io
import csv
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import DnsAnalysis, ThreatAlert
from app.config import settings
from app.services.stream_manager import stream_engine
from app.services.analyzer import analyze_and_record
from app.schemas import ExternalEventPayload, ExternalBatchEventPayload

router = APIRouter(prefix="/monitoring", tags=["Live Monitoring"])

class DemoStartRequest(BaseModel):
    speed_ms: Optional[int] = Field(default=1500, ge=200, le=10000)

class ControlRequest(BaseModel):
    action: str = Field(..., pattern="^(pause|resume|stop)$")

class ResetDemoRequest(BaseModel):
    confirm: bool = Field(..., description="Must be true to confirm removal of demo telemetry records.")

@router.get("/status")
def get_monitoring_status():
    return stream_engine.get_status()

@router.post("/demo/start")
def start_demo_stream(payload: DemoStartRequest):
    return stream_engine.start_demo_stream(speed_ms=payload.speed_ms)

@router.post("/control")
def control_monitoring(payload: ControlRequest):
    if payload.action == "pause":
        return stream_engine.pause()
    elif payload.action == "resume":
        return stream_engine.resume()
    elif payload.action == "stop":
        return stream_engine.stop()

@router.post("/demo/reset")
def reset_demo_data(payload: ResetDemoRequest, db: Session = Depends(get_db)):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required to delete demo records.")
    
    stream_engine.stop()
    stream_engine.total_streamed = 0
    stream_engine.suspicious_streamed = 0
    stream_engine.recent_events.clear()

    # Delete records with source DEMO_STREAM or CSV_REPLAY
    del_analyses = db.query(DnsAnalysis).filter(DnsAnalysis.source.in_(["DEMO_STREAM", "CSV_REPLAY"])).delete(synchronize_session=False)
    del_alerts = db.query(ThreatAlert).filter(ThreatAlert.source.in_(["DEMO_STREAM", "CSV_REPLAY"])).delete(synchronize_session=False)
    db.commit()

    return {
        "status": "SUCCESS",
        "message": f"Purged {del_analyses} demo analyses and {del_alerts} associated demo alerts."
    }

@router.post("/replay/upload")
async def upload_and_start_replay(
    file: UploadFile = File(...),
    speed_ms: int = Query(1500, ge=200, le=10000)
):
    if not (file.filename.endswith(".csv") or file.content_type in ("text/csv", "application/vnd.ms-excel")):
        raise HTTPException(status_code=400, detail="Only .csv files are supported for replay.")

    contents = await file.read()
    if len(contents) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Replay dataset exceeds 5MB limit.")

    try:
        text = contents.decode("utf-8-sig", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode CSV.")

    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        raise HTTPException(status_code=400, detail="Replay file is empty.")

    header = [h.strip().lower() for h in rows[0]]
    col_idx = 0
    start_row = 0
    candidate_names = ["hostname", "domain", "fqdn", "query"]
    for i, h in enumerate(header):
        if h in candidate_names:
            col_idx = i
            start_row = 1
            break

    hostnames = []
    for r in rows[start_row:]:
        if r and col_idx < len(r) and r[col_idx].strip():
            h = r[col_idx].strip()
            if len(h) <= 253 and "." in h:
                hostnames.append(h)

    if not hostnames:
        raise HTTPException(status_code=400, detail="No valid hostnames found in CSV for replay.")

    return stream_engine.start_csv_replay(hostnames=hostnames, speed_ms=speed_ms)

@router.get("/events")
def get_live_events(limit: int = Query(25, ge=1, le=100)):
    return {
        "status": stream_engine.status,
        "mode": stream_engine.mode,
        "events": stream_engine.get_recent_events(limit=limit)
    }

from app.services.zeek_parser import ZeekDnsParser

# Mode C: External Event Ingestion
@router.post("/ingest")
def ingest_external_dns_events(
    payload: ExternalBatchEventPayload,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    # Authenticate API Key
    if not x_api_key or x_api_key != settings.DEFAULT_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-API-Key header. Provide authorized ingest key."
        )

    if not payload.events:
        raise HTTPException(status_code=400, detail="No events provided in payload.")

    if len(payload.events) > 500:
        raise HTTPException(status_code=400, detail="Batch ingestion limit is 500 events per request.")

    processed = 0
    suspicious = 0
    results = []

    for ev in payload.events:
        try:
            res = analyze_and_record(
                db=db,
                hostname=ev.hostname,
                enable_enrichment=False,
                query_type=ev.query_type or "A",
                source="API_INGESTION",
                client_ip=ev.client_ip or "external-collector"
            )
            processed += 1
            if res["is_suspicious"]:
                suspicious += 1

            target_h = res.get("submitted_hostname") or res.get("hostname") or ev.hostname
            results.append({
                "hostname": target_h,
                "risk_score": res["risk_score"],
                "severity": res["severity"],
                "is_suspicious": res["is_suspicious"],
                "status": "PROCESSED"
            })
        except Exception as e:
            results.append({
                "hostname": ev.hostname[:50],
                "error": str(e),
                "status": "ERROR"
            })

    return {
        "status": "SUCCESS",
        "total_received": len(payload.events),
        "total_processed": processed,
        "suspicious_detected": suspicious,
        "items": results
    }

# Mode D: Real Zeek / JSONL / TSV DNS Log Ingestion
@router.post("/zeek/upload")
async def upload_zeek_dns_log(
    file: UploadFile = File(...),
    store_records: bool = Query(True, description="Whether to persist analyses into database"),
    db: Session = Depends(get_db)
):
    """
    Ingests authorized Zeek DNS logs (JSON, JSONL, or TSV format).
    Extracts timestamps, client IPs, queries, response codes, and computes
    real flow features (fanout rate, NXDOMAIN ratio, TXT frequency).
    Detections clearly distinguish ML inferences from flow rules.
    """
    contents = await file.read()
    if len(contents) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Log file exceeds maximum allowed limit of {settings.MAX_UPLOAD_SIZE_BYTES // (1024*1024)}MB."
        )

    try:
        text = contents.decode("utf-8-sig", errors="replace")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to decode log file: {str(e)}")

    events, errors, fields_observed = ZeekDnsParser.parse_log_text(text)
    if not events:
        raise HTTPException(
            status_code=400,
            detail=f"No valid DNS query events could be parsed. Observed errors: {'; '.join(errors[:3]) if errors else 'Empty file'}"
        )

    analysis_summary = ZeekDnsParser.process_and_analyze(
        events=events,
        db=db,
        store_records=store_records
    )
    analysis_summary["filename"] = file.filename
    analysis_summary["fields_observed"] = fields_observed
    analysis_summary["parse_errors"] = errors[:10]
    return analysis_summary
