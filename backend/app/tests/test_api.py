import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert "database" in data
    assert "model" in data

def test_model_info_endpoint():
    response = client.get("/api/model/info")
    assert response.status_code == 200
    data = response.json()
    assert "model_type" in data
    assert "accuracy" in data
    assert "confusion_matrix" in data

def test_single_domain_analysis_valid_benign():
    response = client.post(
        "/api/analysis/single",
        json={"hostname": "api.github.com", "enable_enrichment": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["submitted_hostname"] == "api.github.com"
    assert data["normalized_hostname"] == "api.github.com"
    assert "risk_score" in data
    assert data["risk_score"] < 40.0
    assert data["confidence"] >= 0.50
    assert "confidence_display" in data
    assert data["flow_features_available"] is False
    assert len(data["reasons"]) > 0

def test_single_domain_analysis_unseen_hostname():
    # A completely new, previously unseen enterprise domain
    unseen = "secure-edge-gw-01.ap-south-1.telemetry-corp.io"
    response = client.post(
        "/api/analysis/single",
        json={"hostname": unseen, "enable_enrichment": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["submitted_hostname"] == unseen
    assert "severity" in data
    assert data["severity"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert "features" in data

def test_single_domain_analysis_synthetic_tunneling():
    # Synthetic random base32 encoded Iodine style tunneling
    tunnel = "a8f92k7m3x9q2m10v8z4p19k3m.tunnel.covertc2.biz"
    response = client.post(
        "/api/analysis/single",
        json={"hostname": tunnel, "enable_enrichment": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] is True
    assert data["risk_score"] >= 50.0
    assert data["severity"] in ("HIGH", "CRITICAL")
    assert data["classification"] in ("Suspicious / High-risk", "Critical risk")

def test_single_domain_analysis_invalid_empty_label():
    response = client.post(
        "/api/analysis/single",
        json={"hostname": "invalid..domain..com"}
    )
    assert response.status_code == 422
    assert "empty label" in response.text.lower()

def test_single_domain_analysis_invalid_label_too_long():
    long_label = "a" * 65 + ".example.com"
    response = client.post(
        "/api/analysis/single",
        json={"hostname": long_label}
    )
    assert response.status_code == 422
    assert "exceeds maximum rfc" in response.text.lower()

def test_dns_enrichment_nonexistent_domain():
    # Nonexistent domain should return resolver_status NXDOMAIN without failing analysis
    nonexistent = "nonexistent-subdomain-rnd-912837.google.com"
    response = client.post(
        "/api/analysis/single",
        json={"hostname": nonexistent, "enable_enrichment": True}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["enrichment"] is not None
    assert data["enrichment"]["performed"] is True
    assert data["enrichment"]["resolver_status"] in ("NXDOMAIN", "NOERROR", "TIMEOUT", "SERVFAIL", "RESOLVER_ERROR")
    # Lookup failure does not automatically label domain as malicious
    assert "disclaimer" in data["enrichment"]

def test_batch_csv_analysis_flexible_columns():
    csv_data = "target_domain,notes\napi.github.com,Benign developer API\na8f92k7m3x9q2m10v8z.tunnel.evilcorp.org,Tunneling sample\n"
    response = client.post(
        "/api/analysis/batch",
        files={"file": ("test.csv", csv_data, "text/csv")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_processed"] == 2
    assert data["valid_count"] == 2
    assert len(data["results"]) == 2
    assert data["results"][0]["status"] == "SUCCESS"

def test_batch_csv_analysis_handles_malformed_rows():
    csv_data = "domain\napi.github.com\ninvalid..hostname..com\nvalid.service.org\n"
    response = client.post(
        "/api/analysis/batch",
        files={"file": ("test.csv", csv_data, "text/csv")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_processed"] == 3
    assert data["valid_count"] == 2
    assert data["invalid_count"] == 1
    # Skipped row is reported with error
    assert data["results"][1]["status"] == "SKIPPED"
    assert data["results"][1]["error"] is not None

def test_alert_workflow():
    tunnel_domain = "01823947bca8921df87349120aef1.c2.iodine-exfil.xyz"
    res1 = client.post("/api/analysis/single", json={"hostname": tunnel_domain})
    assert res1.status_code == 200

    alerts_res = client.get("/api/alerts?search=iodine-exfil")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()
    assert alerts_data["total"] >= 1
    alert_id = alerts_data["items"][0]["id"]

    ack_res = client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": "ACKNOWLEDGED", "notes": "Analyst inspecting packet records."}
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "ACKNOWLEDGED"

    res_res = client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": "RESOLVED", "notes": "Investigated and closed."}
    )
    assert res_res.status_code == 200
    assert res_res.json()["status"] == "RESOLVED"

def test_external_ingest_authentication():
    bad_res = client.post(
        "/api/monitoring/ingest",
        json={"events": [{"hostname": "test.com"}]}
    )
    assert bad_res.status_code == 401

    good_res = client.post(
        "/api/monitoring/ingest",
        headers={"X-API-Key": settings.DEFAULT_API_KEY},
        json={"events": [{"hostname": "legit-telemetry.org"}]}
    )
    assert good_res.status_code == 200
    data = good_res.json()
    assert data["status"] == "SUCCESS"
    assert data["total_processed"] == 1
