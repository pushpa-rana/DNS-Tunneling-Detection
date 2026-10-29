import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models import DnsAnalysis
from app.ml.model import model_manager
from app.services.alert_service import maybe_create_alert

def extract_apex_domain(hostname: str) -> str:
    """Extracts the approximate apex/root domain (e.g. a.b.evil.com -> evil.com)."""
    cleaned = hostname.strip().lower().rstrip(".")
    parts = cleaned.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return cleaned

class ZeekDnsParser:
    """
    Parses authorized Zeek JSON/JSONL and TSV DNS logs.
    Computes real traffic flow features and executes hybrid detection
    (Calibrated ML Lexical + Documented Traffic Flow Rules).
    """

    MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024 # 15 MB limit
    MAX_RECORDS = 5000 # Max events processed per upload to maintain responsiveness

    @classmethod
    def parse_log_text(cls, content: str) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
        """
        Parses text content into structured DNS event records.
        Returns (parsed_events, skipped_errors, detected_fields).
        """
        events: List[Dict[str, Any]] = []
        errors: List[str] = []
        fields_observed = set()

        lines = content.splitlines()
        if not lines:
            return events, ["Log file is empty."], []

        # Determine if JSONL or TSV
        first_content_line = next((l.strip() for l in lines if l.strip() and not l.startswith("#")), "")
        is_json = first_content_line.startswith("{")

        if is_json:
            for line_idx, line in enumerate(lines, start=1):
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                try:
                    obj = json.loads(raw)
                    record = cls._normalize_json_record(obj)
                    if record:
                        events.append(record)
                        fields_observed.update(record.keys())
                    if len(events) >= cls.MAX_RECORDS:
                        break
                except Exception as e:
                    if len(errors) < 15:
                        errors.append(f"Line {line_idx}: Invalid JSON syntax ({str(e)})")
        else:
            # TSV / Zeek standard tab-delimited
            header: Optional[List[str]] = None
            for line_idx, line in enumerate(lines, start=1):
                raw = line.strip()
                if not raw:
                    continue
                if raw.startswith("#fields"):
                    header = [h.strip() for h in raw.replace("#fields", "").strip().split("\t")]
                    continue
                if raw.startswith("#"):
                    continue
                
                parts = raw.split("\t")
                if header and len(parts) == len(header):
                    record = cls._normalize_tsv_record(dict(zip(header, parts)))
                    if record:
                        events.append(record)
                        fields_observed.update(record.keys())
                    if len(events) >= cls.MAX_RECORDS:
                        break
                elif len(parts) >= 2:
                    # Fallback generic comma or space/tab
                    q = parts[-1].strip()
                    if "." in q:
                        events.append({
                            "timestamp": datetime.now(timezone.utc),
                            "client_ip": parts[0].strip() if len(parts) > 1 else "unknown-client",
                            "hostname": q,
                            "query_type": "A",
                            "rcode": "NOERROR",
                            "raw_source": "GENERIC_LOG"
                        })

        return events, errors, sorted(list(fields_observed))

    @classmethod
    def _normalize_json_record(cls, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        query = obj.get("query") or obj.get("qname") or obj.get("hostname") or obj.get("domain")
        if not query or not isinstance(query, str) or "." not in query:
            return None

        # Timestamp conversion
        ts_val = obj.get("ts") or obj.get("timestamp") or obj.get("time")
        event_time = datetime.now(timezone.utc)
        if isinstance(ts_val, (int, float)):
            try:
                event_time = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
            except Exception:
                pass
        elif isinstance(ts_val, str):
            try:
                event_time = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception:
                pass

        client_ip = (
            obj.get("id.orig_h") or
            obj.get("orig_h") or
            obj.get("client_ip") or
            obj.get("src_ip") or
            "unknown-client"
        )
        server_ip = (
            obj.get("id.resp_h") or
            obj.get("resp_h") or
            obj.get("resolver_ip") or
            obj.get("dst_ip") or
            "unknown-resolver"
        )
        qtype = (
            obj.get("qtype_name") or
            obj.get("qtype") or
            "A"
        )
        rcode = (
            obj.get("rcode_name") or
            obj.get("rcode") or
            "NOERROR"
        )
        answers = obj.get("answers") or []
        if isinstance(answers, str):
            answers = [answers]

        return {
            "timestamp": event_time,
            "client_ip": str(client_ip),
            "server_ip": str(server_ip),
            "hostname": query.strip().rstrip(".").lower(),
            "query_type": str(qtype).upper(),
            "rcode": str(rcode).upper(),
            "answers": answers,
            "trans_id": obj.get("trans_id")
        }

    @classmethod
    def _normalize_tsv_record(cls, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        query = row.get("query")
        if not query or query == "-" or "." not in query:
            return None

        event_time = datetime.now(timezone.utc)
        ts_str = row.get("ts", "")
        if ts_str and ts_str != "-":
            try:
                event_time = datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
            except Exception:
                pass

        client_ip = row.get("id.orig_h", "unknown-client")
        server_ip = row.get("id.resp_h", "unknown-resolver")
        qtype = row.get("qtype_name", row.get("qtype", "A"))
        rcode = row.get("rcode_name", row.get("rcode", "NOERROR"))
        answers_raw = row.get("answers", "")
        answers = answers_raw.split(",") if answers_raw and answers_raw != "-" else []

        return {
            "timestamp": event_time,
            "client_ip": client_ip if client_ip != "-" else "unknown-client",
            "server_ip": server_ip if server_ip != "-" else "unknown-resolver",
            "hostname": query.strip().rstrip(".").lower(),
            "query_type": qtype if qtype != "-" else "A",
            "rcode": rcode if rcode != "-" else "NOERROR",
            "answers": answers,
            "trans_id": row.get("trans_id")
        }

    @classmethod
    def process_and_analyze(
        cls,
        events: List[Dict[str, Any]],
        db: Session,
        store_records: bool = True
    ) -> Dict[str, Any]:
        """
        Executes traffic-based flow aggregation and hybrid detection:
        1. Aggregates flow features per (client_ip, apex_domain).
        2. Evaluates documented Flow Rules (DGA fanout, NXDOMAIN ratio, TXT tunnel).
        3. Evaluates Platt-calibrated ML Lexical Model on unique domains.
        4. Distinguishes findings clearly (ML vs Rule).
        5. Persists authorized analyses with source 'HISTORICAL_ZEEK_IMPORT'.
        """
        if not events:
            return {
                "status": "EMPTY",
                "total_events": 0,
                "message": "No valid DNS events to analyze."
            }

        # 1. Group by (client_ip, apex_domain) for flow traffic analysis
        clusters: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        client_ips = set()
        unique_hostnames = set()

        for ev in events:
            h = ev["hostname"]
            client = ev["client_ip"]
            apex = extract_apex_domain(h)
            key = (client, apex)
            if key not in clusters:
                clusters[key] = []
            clusters[key].append(ev)
            client_ips.add(client)
            unique_hostnames.add(h)

        # 2. Run Hybrid Analysis on each cluster
        cluster_summaries: List[Dict[str, Any]] = []
        flagged_events: List[Dict[str, Any]] = []
        stored_count = 0

        # Model cache to avoid recomputing identical hostnames in a batch
        ml_cache: Dict[str, Dict[str, Any]] = {}

        for (client, apex), cluster_evs in clusters.items():
            total_queries = len(cluster_evs)
            distinct_subdomains = list({e["hostname"] for e in cluster_evs})
            unique_sub_count = len(distinct_subdomains)
            nxdomain_count = sum(1 for e in cluster_evs if e["rcode"] == "NXDOMAIN")
            txt_query_count = sum(1 for e in cluster_evs if e["query_type"] == "TXT")

            # Time span in cluster
            timestamps = [e["timestamp"] for e in cluster_evs]
            start_ts = min(timestamps)
            end_ts = max(timestamps)
            duration_sec = max(1.0, (end_ts - start_ts).total_seconds())
            queries_per_min = round((total_queries / duration_sec) * 60.0, 2)
            nxdomain_pct = round((nxdomain_count / total_queries) * 100.0, 1)

            flow_features = {
                "client_ip": client,
                "apex_domain": apex,
                "total_queries": total_queries,
                "unique_subdomain_count": unique_sub_count,
                "nxdomain_count": nxdomain_count,
                "nxdomain_percentage": nxdomain_pct,
                "txt_query_count": txt_query_count,
                "duration_seconds": round(duration_sec, 2),
                "query_velocity_per_min": queries_per_min
            }

            # Flow-Based Rules (Documented Logic)
            flow_reasons: List[Dict[str, str]] = []
            flow_is_suspicious = False

            if unique_sub_count >= 10:
                flow_is_suspicious = True
                flow_reasons.append({
                    "type": "RULE_DETECTION",
                    "factor": "High Subdomain Velocity (Fanout)",
                    "description": f"Observed {unique_sub_count} unique subdomains under apex '{apex}'. Characteristic of chunked exfiltration or DGA beaconing.",
                    "weight": "HIGH"
                })

            if nxdomain_pct >= 40.0 and total_queries >= 6:
                flow_is_suspicious = True
                flow_reasons.append({
                    "type": "RULE_DETECTION",
                    "factor": "Elevated NXDOMAIN Failure Ratio",
                    "description": f"{nxdomain_pct}% of queries returned NXDOMAIN ({nxdomain_count}/{total_queries}), indicating domain scanning or rendezvous failure.",
                    "weight": "HIGH"
                })

            if txt_query_count >= 5:
                flow_reasons.append({
                    "type": "RULE_DETECTION",
                    "factor": "Frequent TXT Record Tunneling Pattern",
                    "description": f"{txt_query_count} TXT queries recorded. TXT payloads are often used for oversized C2 responses.",
                    "weight": "MEDIUM"
                })

            # Run ML analysis on each distinct hostname in cluster
            for h in distinct_subdomains:
                if h not in ml_cache:
                    ml_cache[h] = model_manager.predict(h)
                ml_pred = ml_cache[h]

                # Combine ML findings with Flow Rule findings
                combined_reasons = []
                # ML reasons tagged
                for r in ml_pred["reasons"]:
                    combined_reasons.append({
                        "type": "ML_INFERENCE",
                        "factor": f"ML Model: {r['factor']}",
                        "description": r["description"],
                        "weight": r["weight"]
                    })
                # Flow reasons tagged
                combined_reasons.extend(flow_reasons)

                # Combined risk scoring:
                # If flow rules trigger, we elevate the risk floor appropriately
                hybrid_risk = ml_pred["risk_score"]
                if flow_is_suspicious and hybrid_risk < 50.0:
                    hybrid_risk = min(85.0, hybrid_risk + 35.0)

                hybrid_is_suspicious = ml_pred["is_suspicious"] or flow_is_suspicious
                hybrid_severity = (
                    "CRITICAL" if hybrid_risk >= 75.0 else
                    "HIGH" if hybrid_risk >= 50.0 else
                    "MODERATE" if hybrid_risk >= 25.0 else
                    "LOW"
                )

                # Storing in DB if enabled
                if store_records:
                    analysis = DnsAnalysis(
                        hostname=h,
                        is_suspicious=hybrid_is_suspicious,
                        risk_score=hybrid_risk,
                        severity=hybrid_severity,
                        confidence=ml_pred["confidence"],
                        features_json=json.dumps({
                            "lexical": ml_pred["features"],
                            "flow": flow_features
                        }),
                        reasons_json=json.dumps(combined_reasons),
                        enrichment_json=None,
                        source="HISTORICAL_ZEEK_IMPORT",
                        query_type=cluster_evs[0]["query_type"],
                        client_ip=client,
                        timestamp=cluster_evs[0]["timestamp"]
                    )
                    db.add(analysis)
                    db.flush()
                    stored_count += 1

                    # Trigger alert if High or Critical
                    if hybrid_risk >= 50.0:
                        maybe_create_alert(db, analysis, combined_reasons)

                if hybrid_is_suspicious:
                    flagged_events.append({
                        "hostname": h,
                        "client_ip": client,
                        "apex_domain": apex,
                        "risk_score": hybrid_risk,
                        "severity": hybrid_severity,
                        "detection_types": [r["type"] for r in combined_reasons],
                        "reasons": combined_reasons,
                        "timestamp": cluster_evs[0]["timestamp"].isoformat()
                    })

            cluster_summaries.append({
                "client_ip": client,
                "apex_domain": apex,
                "flow_features": flow_features,
                "distinct_subdomains_count": unique_sub_count,
                "rule_triggers": [r["factor"] for r in flow_reasons]
            })

        if store_records:
            db.commit()

        # Identify missing fields in telemetry
        missing_fields = []
        if "response_bytes" not in events[0]:
            missing_fields.append("response_bytes (Response size payload variance)")
        if "rtt" not in events[0]:
            missing_fields.append("rtt (Resolver round-trip-time jitter)")

        return {
            "status": "SUCCESS",
            "telemetry_source": "HISTORICAL_ZEEK_IMPORT",
            "data_classification": "HISTORICAL_LOG_DATA",
            "total_records_processed": len(events),
            "unique_client_ips_count": len(client_ips),
            "unique_hostnames_count": len(unique_hostnames),
            "clusters_analyzed": len(clusters),
            "stored_records_count": stored_count,
            "suspicious_detections_count": len(flagged_events),
            "missing_fields": missing_fields,
            "cluster_summaries": cluster_summaries[:10],
            "flagged_detections": flagged_events[:25],
            "notice": (
                "Imported records represent historical telemetry from authorized sensor logs. "
                "Flow features were calculated from log timeframes; live streaming requires the Zeek live tailer adapter."
            )
        }
