import os
import pytest
from app.ml.model import model_manager
from app.ml.dataset import generate_dataset

def test_dataset_generation():
    domains, labels = generate_dataset(num_samples=100, random_state=42)
    assert len(domains) == 100
    assert len(labels) == 100
    assert labels.count(0) == 50
    assert labels.count(1) == 50

def test_model_training_and_metrics():
    metrics = model_manager.train_and_save(num_samples=400)
    assert model_manager.is_loaded()
    assert "accuracy" in metrics
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "confusion_matrix" in metrics
    assert "feature_importance" in metrics
    assert metrics["accuracy"] > 0.80

def test_model_prediction_benign():
    result = model_manager.predict("www.google.com")
    assert result["submitted_hostname"] == "www.google.com"
    assert result["normalized_hostname"] == "www.google.com"
    assert "risk_score" in result
    assert "severity" in result
    assert "classification" in result
    assert "features" in result
    assert "reasons" in result
    assert result["risk_score"] < 40.0
    # Calibrated confidence must be certainty of predicted class >= 0.50, NOT 0%
    assert result["confidence"] >= 0.50
    assert "confidence_display" in result
    assert "%" in result["confidence_display"]

def test_model_prediction_tunneling():
    # Tunneling domain with long random hex payload
    result = model_manager.predict("dnscat.01823947bca8921df87349120.c2.targetdomain.net")
    assert result["risk_score"] >= 50.0
    assert result["severity"] in ("HIGH", "CRITICAL")
    assert result["classification"] in ("Suspicious / High-risk", "Critical risk")
    assert len(result["reasons"]) > 0

def test_out_of_distribution_handling():
    # Single word hostname without public TLD
    result = model_manager.predict("internalhostonly")
    assert result["uncertainty_status"] == "OUT_OF_DISTRIBUTION"
    assert "Confidence unavailable" in result["confidence_display"]
    assert result["classification"] == "Insufficient evidence"

def test_google_and_github_predictions():
    # Requirement 9: test google.com and github.com
    for domain in ["google.com", "github.com"]:
        res = model_manager.predict(domain)
        assert res["severity"] == "LOW"
        assert res["risk_score"] < 25.0
        assert res["confidence"] >= 0.50
        assert "High Certainty" in res["confidence_display"] or "Moderate Certainty" in res["confidence_display"]

def test_synthetic_subdomain_under_example_com_not_critical():
    # Requirement 9: Synthetic random-looking hostnames under example.com must NOT be falsely marked critical
    for domain in ["test-a8f92k.example.com", "random-token-8921.example.com"]:
        res = model_manager.predict(domain)
        assert res["severity"] in ("LOW", "MODERATE")
        assert res["risk_score"] < 50.0

def test_structured_recommendation_contains_five_parts():
    # Requirement 6: Dynamic actionable recommendation must explain:
    # 1. What was detected
    # 2. Why it matters
    # 3. What to investigate next
    # 4. Which evidence supports that action
    # 5. What information is missing
    res = model_manager.predict("a8f92k7m3x9q2m10v8z.tunnel.dnstunnel.net")
    assert "structured_recommendation" in res
    rec = res["structured_recommendation"]
    assert "summary" in rec
    assert "detected" in rec
    assert "significance" in rec
    assert "next_steps" in rec
    assert "supporting_evidence" in rec
    assert "missing_information" in rec
    assert "Never automatically block" in rec["next_steps"]

def test_label_lengths_field_in_features():
    # Requirement 5: Display individual DNS label lengths
    res = model_manager.predict("api.service.example.com")
    features = res["features"]
    assert "label_lengths" in features
    assert features["label_lengths"] == [3, 7, 7, 3]

