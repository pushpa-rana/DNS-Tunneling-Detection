import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.zeek_parser import ZeekDnsParser
from app.database import SessionLocal

client = TestClient(app)

SAMPLE_ZEEK_JSONL = """
{"ts": 1698579201.12, "id.orig_h": "192.168.1.101", "id.resp_h": "8.8.8.8", "query": "api.github.com", "qtype_name": "A", "rcode_name": "NOERROR"}
{"ts": 1698579202.15, "id.orig_h": "192.168.1.101", "id.resp_h": "8.8.8.8", "query": "www.google.com", "qtype_name": "A", "rcode_name": "NOERROR"}
{"ts": 1698579203.20, "id.orig_h": "10.0.0.55", "id.resp_h": "1.1.1.1", "query": "chunk1.exfil.tunnel-exfil.xyz", "qtype_name": "TXT", "rcode_name": "NOERROR"}
{"ts": 1698579203.80, "id.orig_h": "10.0.0.55", "id.resp_h": "1.1.1.1", "query": "chunk2.exfil.tunnel-exfil.xyz", "qtype_name": "TXT", "rcode_name": "NOERROR"}
{"ts": 1698579204.10, "id.orig_h": "10.0.0.55", "id.resp_h": "1.1.1.1", "query": "chunk3.exfil.tunnel-exfil.xyz", "qtype_name": "TXT", "rcode_name": "NXDOMAIN"}
"""

SAMPLE_ZEEK_TSV = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
1698579210.00	CHhAvVGS	192.168.1.50	53211	8.8.8.8	53	udp	41231	0.012	portal.company.com	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	10.10.1.1	300.0	F
1698579211.50	CHhAvVGT	192.168.1.50	53212	8.8.8.8	53	udp	41232	0.015	a8f92k7m3x9q2m10v8z.tunnel.dnstunnel.net	1	C_INTERNET	1	A	0	NOERROR	F	F	T	T	0	192.168.1.1	300.0	F
"""

def test_zeek_jsonl_parser():
    events, errors, fields = ZeekDnsParser.parse_log_text(SAMPLE_ZEEK_JSONL)
    assert len(events) == 5
    assert len(errors) == 0
    assert "client_ip" in fields
    assert "hostname" in fields
    assert events[0]["hostname"] == "api.github.com"
    assert events[0]["client_ip"] == "192.168.1.101"
    assert events[2]["query_type"] == "TXT"

def test_zeek_tsv_parser():
    events, errors, fields = ZeekDnsParser.parse_log_text(SAMPLE_ZEEK_TSV)
    assert len(events) == 2
    assert events[0]["hostname"] == "portal.company.com"
    assert events[1]["hostname"] == "a8f92k7m3x9q2m10v8z.tunnel.dnstunnel.net"
    assert events[1]["client_ip"] == "192.168.1.50"

def test_zeek_flow_aggregation_and_hybrid_detection():
    events, _, _ = ZeekDnsParser.parse_log_text(SAMPLE_ZEEK_JSONL)
    db = SessionLocal()
    try:
        res = ZeekDnsParser.process_and_analyze(events, db=db, store_records=False)
        assert res["status"] == "SUCCESS"
        assert res["total_records_processed"] == 5
        assert res["unique_client_ips_count"] == 2
        assert len(res["cluster_summaries"]) >= 2
        
        # Verify flow features were computed
        cluster = res["cluster_summaries"][0]
        assert "flow_features" in cluster
        flow = cluster["flow_features"]
        assert "total_queries" in flow
        assert "unique_subdomain_count" in flow
        assert "query_velocity_per_min" in flow
    finally:
        db.close()

def test_zeek_upload_endpoint():
    response = client.post(
        "/api/monitoring/zeek/upload",
        files={"file": ("dns.log", SAMPLE_ZEEK_JSONL, "application/json")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["telemetry_source"] == "HISTORICAL_ZEEK_IMPORT"
    assert data["data_classification"] == "HISTORICAL_LOG_DATA"
    assert data["total_records_processed"] == 5
    assert "missing_fields" in data
