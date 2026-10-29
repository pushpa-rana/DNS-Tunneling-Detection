import pytest
from app.ml.features import (
    extract_features,
    calculate_shannon_entropy,
    feature_dict_to_vector,
    FEATURE_NAMES
)

def test_shannon_entropy_calculation():
    # Empty string entropy should be 0.0
    assert calculate_shannon_entropy("") == 0.0
    # Repeating string has low entropy
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0
    # High randomness has higher entropy
    h_entropy = calculate_shannon_entropy("a8f92k7m3x9q2m10v8z4")
    assert h_entropy > 3.5

def test_feature_extraction_structure():
    domain = "api.internal.example.com"
    feats = extract_features(domain)

    assert "hostname_length" in feats
    assert feats["hostname_length"] == len(domain)
    assert feats["num_labels"] == 4
    assert feats["subdomain_depth"] == 2
    assert feats["has_known_tld"] is True
    assert feats["max_label_length"] == len("internal")
    assert 0.0 <= feats["digit_ratio"] <= 1.0

def test_feature_vector_conversion():
    domain = "dnscat.01823947bca8921df87.c2.targetdomain.net"
    feats = extract_features(domain)
    vec = feature_dict_to_vector(feats)

    assert len(vec) == len(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in vec)
