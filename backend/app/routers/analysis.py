import io
import csv
import json
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Response, Form
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from app.database import get_db
from app.models import DnsAnalysis
from app.schemas import (
    DnsAnalysisRequest,
    DnsAnalysisResponse,
    BatchAnalysisResponse,
    BatchAnalysisItemResult
)
from app.services.analyzer import analyze_and_record

router = APIRouter(prefix="/analysis", tags=["DNS Analysis"])

@router.post("/single", response_model=DnsAnalysisResponse)
def analyze_single_hostname(
    payload: DnsAnalysisRequest,
    db: Session = Depends(get_db)
):
    try:
        result = analyze_and_record(
            db=db,
            hostname=payload.hostname,
            enable_enrichment=payload.enable_enrichment,
            query_type=payload.query_type or "A",
            source=payload.source or "MANUAL",
            client_ip=payload.client_ip or "127.0.0.1"
        )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis engine error: {str(e)}")

@router.post("/batch", response_model=BatchAnalysisResponse)
async def analyze_batch_csv(
    file: UploadFile = File(...),
    hostname_column: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    # Validate file type
    if not (file.filename.endswith(".csv") or file.content_type in ("text/csv", "application/vnd.ms-excel")):
        raise HTTPException(status_code=400, detail="Only standard .csv files are supported for batch ingestion.")

    # Max size 10MB
    contents = await file.read()
    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum allowed 10MB limit.")

    try:
        text = contents.decode("utf-8-sig", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to decode file as UTF-8.")

    csv_reader = csv.reader(io.StringIO(text))
    rows = list(csv_reader)
    if not rows:
        raise HTTPException(status_code=400, detail="Uploaded CSV file is completely empty.")

    # Flexible column selection / auto-detection
    header = [h.strip().lower() for h in rows[0]]
    col_idx = 0
    start_row = 1
    detected_col_name = "auto-column-0"

    candidate_names = ["hostname", "domain", "fqdn", "query", "url", "domain_name", "target", "host"]

    if hostname_column and hostname_column.strip().lower() in header:
        col_idx = header.index(hostname_column.strip().lower())
        detected_col_name = header[col_idx]
        start_row = 1
    else:
        found = False
        for i, h in enumerate(header):
            if h in candidate_names:
                col_idx = i
                detected_col_name = header[i]
                start_row = 1
                found = True
                break
        if not found:
            # Check if first row contains a domain instead of headers
            if "." in rows[0][0] and not any(cand in rows[0][0].lower() for cand in candidate_names):
                start_row = 0
                detected_col_name = "Column 1 (Data)"
            else:
                detected_col_name = header[0] if header else "Column 1"

    total_processed = 0
    valid_count = 0
    invalid_count = 0
    suspicious_count = 0
    high_risk_count = 0
    results: List[BatchAnalysisItemResult] = []

    # Limit to 2000 rows per request
    max_items = 2000
    data_rows = rows[start_row:start_row + max_items]

    for row_num, row in enumerate(data_rows, start=start_row + 1):
        if not row or col_idx >= len(row) or not row[col_idx].strip():
            continue

        raw_domain = row[col_idx].strip()
        total_processed += 1

        try:
            # Validate input syntax
            res = analyze_and_record(
                db=db,
                hostname=raw_domain,
                enable_enrichment=False,
                source="BATCH",
                client_ip="batch-import"
            )
            valid_count += 1
            if res["is_suspicious"]:
                suspicious_count += 1
            if res["severity"] in ("HIGH", "CRITICAL"):
                high_risk_count += 1

            results.append(BatchAnalysisItemResult(
                row_number=row_num,
                submitted_hostname=res["submitted_hostname"],
                normalized_hostname=res["normalized_hostname"],
                is_suspicious=res["is_suspicious"],
                risk_score=res["risk_score"],
                severity=res["severity"],
                classification=res["classification"],
                confidence_display=res["confidence_display"],
                status="SUCCESS"
            ))
        except Exception as ex:
            invalid_count += 1
            results.append(BatchAnalysisItemResult(
                row_number=row_num,
                submitted_hostname=raw_domain[:70],
                normalized_hostname=raw_domain[:70],
                is_suspicious=False,
                risk_score=0.0,
                severity="LOW",
                classification="Invalid input",
                confidence_display="N/A",
                status="SKIPPED",
                error=str(ex)
            ))

    return BatchAnalysisResponse(
        total_processed=total_processed,
        valid_count=valid_count,
        invalid_count=invalid_count,
        suspicious_count=suspicious_count,
        high_risk_count=high_risk_count,
        detected_column=detected_col_name,
        results=results
    )

@router.get("/sample-csv")
def download_sample_csv():
    sample_content = (
        "hostname,expected_category,notes\n"
        "api.github.com,benign,Standard Developer API\n"
        "mail.google.com,benign,Corporate Email Service\n"
        "static-assets.cloudflare.net,benign,Edge CDN Subdomain\n"
        "a8f92k7m3x9q2m10v8z.tunnel.evilcorp.org,tunneling_iodine,Iodine Base32 Payload\n"
        "dnscat.01823947bca8921df87.c2.targetdomain.net,tunneling_dnscat2,DNScat2 Hex C2 Beacon\n"
        "dGhpcy1pcy1hLXNlY3JldA.data.exfil-dns.io,tunneling_base64,Base64 Chunk Exfiltration\n"
        "accounts.google.com,benign,Authentication Portal\n"
        "portal.azure.com,benign,Cloud Management Portal\n"
        "9f82kd0281b37492cfa77192.beacon.covertc2.biz,tunneling_beacon,Covert DNS Channel\n"
    )
    return Response(
        content=sample_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dns_shield_sample.csv"}
    )

@router.get("/history")
def get_analysis_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    search: Optional[str] = None,
    severity: Optional[str] = None,
    is_suspicious: Optional[bool] = None,
    source: Optional[str] = None,
    sort_by: str = Query("timestamp", pattern="^(timestamp|risk_score|hostname)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db)
):
    query = db.query(DnsAnalysis)

    if search:
        query = query.filter(DnsAnalysis.hostname.ilike(f"%{search.strip()}%"))
    if severity:
        query = query.filter(DnsAnalysis.severity == severity.upper())
    if is_suspicious is not None:
        query = query.filter(DnsAnalysis.is_suspicious == is_suspicious)
    if source:
        query = query.filter(DnsAnalysis.source == source.upper())

    total = query.count()

    order_col = getattr(DnsAnalysis, sort_by)
    if sort_order == "desc":
        query = query.order_by(desc(order_col))
    else:
        query = query.order_by(asc(order_col))

    offset = (page - 1) * page_size
    records = query.offset(offset).limit(page_size).all()

    items = []
    for r in records:
        features = json.loads(r.features_json) if r.features_json else {}
        reasons = json.loads(r.reasons_json) if r.reasons_json else []
        enrichment = json.loads(r.enrichment_json) if r.enrichment_json else None
        
        # Classification description
        if r.risk_score >= 75.0:
            classification = "Critical risk"
        elif r.risk_score >= 50.0:
            classification = "Suspicious / High-risk"
        elif r.risk_score >= 25.0:
            classification = "Moderate risk"
        else:
            classification = "No strong suspicious indicators detected"

        items.append({
            "id": r.id,
            "submitted_hostname": r.hostname,
            "normalized_hostname": r.hostname.strip().lower().rstrip("."),
            "is_suspicious": r.is_suspicious,
            "risk_score": r.risk_score,
            "severity": r.severity,
            "classification": classification,
            "confidence": r.confidence,
            "confidence_display": f"{round(r.confidence * 100, 1)}%",
            "uncertainty_status": "CALIBRATED_CONFIDENT",
            "features": features,
            "reasons": reasons,
            "enrichment": enrichment,
            "source": r.source,
            "query_type": r.query_type,
            "client_ip": r.client_ip,
            "timestamp": r.timestamp.isoformat() if hasattr(r.timestamp, "isoformat") else str(r.timestamp)
        })

    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size if total > 0 else 1,
        "items": items
    }

@router.get("/export/csv")
def export_analyses_csv(
    search: Optional[str] = None,
    severity: Optional[str] = None,
    is_suspicious: Optional[bool] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(DnsAnalysis)
    if search:
        query = query.filter(DnsAnalysis.hostname.ilike(f"%{search.strip()}%"))
    if severity:
        query = query.filter(DnsAnalysis.severity == severity.upper())
    if is_suspicious is not None:
        query = query.filter(DnsAnalysis.is_suspicious == is_suspicious)
    if source:
        query = query.filter(DnsAnalysis.source == source.upper())

    records = query.order_by(desc(DnsAnalysis.timestamp)).limit(3000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Submitted Hostname", "Is Suspicious", "Risk Score", "Severity",
        "Confidence", "Shannon Entropy", "Hostname Length", "Max Label Length",
        "Source", "Client IP", "Timestamp"
    ])

    for r in records:
        features = json.loads(r.features_json) if r.features_json else {}
        writer.writerow([
            r.id,
            r.hostname,
            r.is_suspicious,
            r.risk_score,
            r.severity,
            r.confidence,
            features.get("shannon_entropy", ""),
            features.get("hostname_length", ""),
            features.get("max_label_length", ""),
            r.source,
            r.client_ip,
            r.timestamp.isoformat() if hasattr(r.timestamp, "isoformat") else str(r.timestamp)
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=dns_shield_analyses.csv"}
    )
