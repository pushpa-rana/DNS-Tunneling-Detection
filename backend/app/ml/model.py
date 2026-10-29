import os
import json
import idna
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List
import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)

from app.config import settings
from app.ml.features import (
    extract_features,
    feature_dict_to_vector,
    FEATURE_NAMES
)
from app.ml.dataset import generate_dataset

class DnsModelManager:
    def __init__(self):
        self.model: Optional[Any] = None
        self.metrics: Optional[Dict[str, Any]] = None
        self.model_version: str = "GradientBoosting-v2.0-FlowLexical"

    def is_loaded(self) -> bool:
        return self.model is not None

    def normalize_hostname(self, hostname: str) -> str:
        """Normalizes hostname for consistent analysis and IDN Punycode decoding."""
        raw = hostname.strip().rstrip(".")
        try:
            return idna.encode(raw.lower()).decode("ascii")
        except Exception:
            return raw.lower()

    def train_and_save(self, num_samples: int = 5000) -> Dict[str, Any]:
        """
        Trains the Gradient-Boosted Classifier using reproducible stratified
        Train (70%), Validation (15%), and Test (15%) splits with zero data leakage.
        Applies Platt Sigmoid Calibration on the validation split.
        """
        os.makedirs(os.path.dirname(settings.MODEL_PATH), exist_ok=True)
        
        domains, labels = generate_dataset(num_samples=num_samples, random_state=42)
        X = [feature_dict_to_vector(extract_features(d)) for d in domains]
        y = np.array(labels)

        # 1. First Split: Train (70%) and Temp (30%)
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.30, random_state=42, stratify=y
        )

        # 2. Second Split: Validation (15%) and Test (15%)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
        )

        # Gradient Boosted Flow-Lexical Classifier
        clf = GradientBoostingClassifier(
            n_estimators=120,
            learning_rate=0.10,
            max_depth=6,
            min_samples_split=6,
            min_samples_leaf=3,
            subsample=0.85,
            random_state=42
        )
        clf.fit(X_train, y_train)

        # Platt scaling probability calibration using held-out validation set
        calibrated_clf = CalibratedClassifierCV(estimator=clf, method='sigmoid', cv='prefit')
        calibrated_clf.fit(X_val, y_val)

        # Evaluate strictly on held-out test split
        y_pred = calibrated_clf.predict(X_test)
        y_prob = calibrated_clf.predict_proba(X_test)[:, 1]

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        auc = float(roc_auc_score(y_test, y_prob))

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

        importances = dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in clf.feature_importances_]))
        sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

        metrics_data = {
            "model_type": "Gradient-Boosted Flow-Lexical Classifier (Platt Calibrated)",
            "model_version": self.model_version,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "dataset_source": "Stratified Synthetic & Simulated DNS Tunneling Vectors (Iodine, DNScat2, Base64/Hex exfiltration vs Alexa/Enterprise CDN subdomains)",
            "total_samples": len(domains),
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
            "legitimate_samples": int(sum(1 for lbl in labels if lbl == 0)),
            "tunneling_samples": int(sum(1 for lbl in labels if lbl == 1)),
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(auc, 4),
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp
            },
            "feature_importance": sorted_importances,
            "disclaimer": "Metrics are evaluated strictly on held-out test splits. Static lexical analysis alone cannot conclusively establish malicious intent; correlation with network telemetry, query frequency, and threat intelligence is advised."
        }

        # Persist model and metrics
        joblib.dump(calibrated_clf, settings.MODEL_PATH)
        with open(settings.METRICS_PATH, "w", encoding="utf-8") as f:
            json.dump(metrics_data, f, indent=2)

        self.model = calibrated_clf
        self.metrics = metrics_data
        return metrics_data

    def load_or_train(self) -> None:
        """Loads model from disk or trains if missing."""
        if os.path.exists(settings.MODEL_PATH) and os.path.exists(settings.METRICS_PATH):
            try:
                self.model = joblib.load(settings.MODEL_PATH)
                with open(settings.METRICS_PATH, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
                return
            except Exception:
                pass
        
        self.train_and_save()

    def predict(self, raw_hostname: str) -> Dict[str, Any]:
        """
        Runs feature extraction, Gradient-Boosted inference, calibrated certainty,
        risk band assignment (0-24 Low, 25-49 Moderate, 50-74 High, 75-100 Critical),
        and explainability.
        """
        if not self.is_loaded():
            self.load_or_train()

        normalized = self.normalize_hostname(raw_hostname)
        features = extract_features(normalized)
        vector = feature_dict_to_vector(features)

        # Check for Out-Of-Distribution (OOD) or Insufficient Evidence
        # e.g. Single label with no TLD (e.g. 'localhost'), or extreme length > 250 without valid syntax
        is_ood = False
        ood_reason = None
        if features["num_labels"] < 2 and not features["has_known_tld"]:
            is_ood = True
            ood_reason = "Single-label hostname without public top-level domain."

        # Model Probabilities: [P(benign), P(tunneling)]
        probs = self.model.predict_proba([vector])[0]
        prob_benign = float(probs[0])
        prob_tunnel = float(probs[1])

        # True Classification Confidence = certainty of the predicted class: max(P0, P1)
        predicted_class = 1 if prob_tunnel >= 0.5 else 0
        raw_confidence = max(prob_benign, prob_tunnel)

        # Calibrated Confidence Status
        if is_ood:
            uncertainty_status = "OUT_OF_DISTRIBUTION"
            confidence_display = "Confidence unavailable (Out-of-distribution input)"
        elif raw_confidence >= 0.85:
            uncertainty_status = "CALIBRATED_CONFIDENT"
            confidence_display = f"{round(raw_confidence * 100, 1)}% (High Certainty)"
        elif raw_confidence >= 0.65:
            uncertainty_status = "MODERATE_UNCERTAINTY"
            confidence_display = f"{round(raw_confidence * 100, 1)}% (Moderate Certainty)"
        else:
            uncertainty_status = "HIGH_UNCERTAINTY"
            confidence_display = f"{round(raw_confidence * 100, 1)}% (Near Decision Boundary)"

        # Calibrated Risk Scoring Formula (0 to 100)
        # Directly derived from the Platt-calibrated tunneling probability:
        # P(tunneling | x) * 100 with strict risk bands:
        # 0–24: Low
        # 25–49: Moderate
        # 50–74: High
        # 75–100: Critical
        if is_ood:
            risk_score = 0.0
            severity = "LOW"
            classification = "Insufficient evidence"
            is_suspicious = False
        else:
            risk_score = round(max(0.0, min(100.0, prob_tunnel * 100.0)), 1)
            if risk_score >= 75.0:
                severity = "CRITICAL"
                classification = "Critical risk"
                is_suspicious = True
            elif risk_score >= 50.0:
                severity = "HIGH"
                classification = "Suspicious / High-risk"
                is_suspicious = True
            elif risk_score >= 25.0:
                severity = "MODERATE"
                classification = "Moderate risk"
                is_suspicious = False
            else:
                severity = "LOW"
                classification = "No strong suspicious indicators detected"
                is_suspicious = False

        # Explainable reasons
        reasons = []
        if features["shannon_entropy"] >= 3.9:
            reasons.append({
                "factor": "High Shannon Entropy",
                "description": f"Entropy of {features['shannon_entropy']} bits/char indicates compressed, encrypted, or Base32 payload encoding.",
                "weight": "HIGH"
            })
        if features["max_label_length"] >= 30:
            reasons.append({
                "factor": "Subdomain Label Length Anomaly",
                "description": f"Longest label contains {features['max_label_length']} characters, characteristic of chunked DNS data exfiltration.",
                "weight": "HIGH"
            })
        if features["hostname_length"] >= 50:
            reasons.append({
                "factor": "Extended FQDN Length",
                "description": f"Total length of {features['hostname_length']} characters exceeds typical benign query profiles.",
                "weight": "MEDIUM"
            })
        if features["hex_ratio"] >= 0.55:
            reasons.append({
                "factor": "Elevated Hexadecimal Density",
                "description": f"{round(features['hex_ratio']*100, 1)}% hexadecimal characters, consistent with DNScat2 or binary dumps.",
                "weight": "HIGH"
            })
        if features["digit_ratio"] >= 0.25:
            reasons.append({
                "factor": "Elevated Numeric Ratio",
                "description": f"{round(features['digit_ratio']*100, 1)}% numeric characters, atypical for natural language domain names.",
                "weight": "MEDIUM"
            })
        if features["subdomain_depth"] >= 3:
            reasons.append({
                "factor": "Deep Subdomain Hierarchy",
                "description": f"{features['subdomain_depth']} nested subdomain levels observed.",
                "weight": "LOW"
            })
        if features["consecutive_consonant_max"] >= 6:
            reasons.append({
                "factor": "Pronounceability Anomaly",
                "description": f"Streak of {features['consecutive_consonant_max']} consecutive consonants indicates non-dictionary algorithmic generation.",
                "weight": "MEDIUM"
            })

        if not reasons:
            reasons.append({
                "factor": "Standard Lexical Baseline",
                "description": "Domain conforms to standard lexical naming baselines, balanced vowel/consonant distribution, and natural entropy.",
                "weight": "LOW"
            })

        # Dynamic 5-part Actionable Advisory Recommendation
        structured_rec = self.generate_structured_recommendation(
            hostname=raw_hostname,
            severity=severity,
            risk_score=risk_score,
            confidence_display=confidence_display,
            features=features,
            reasons=reasons,
            is_ood=is_ood
        )

        return {
            "submitted_hostname": raw_hostname,
            "normalized_hostname": normalized,
            "is_suspicious": is_suspicious,
            "risk_score": risk_score,
            "severity": severity,
            "classification": classification,
            "confidence": round(raw_confidence, 4),
            "confidence_display": confidence_display,
            "uncertainty_status": uncertainty_status,
            "features": features,
            "reasons": reasons,
            "recommendation": structured_rec["summary"],
            "structured_recommendation": structured_rec,
            "model_version": self.model_version
        }

    def generate_structured_recommendation(
        self,
        hostname: str,
        severity: str,
        risk_score: float,
        confidence_display: str,
        features: Dict[str, Any],
        reasons: List[Dict[str, str]],
        is_ood: bool
    ) -> Dict[str, str]:
        """Generates dynamic 5-part actionable security recommendations with explicit limitations."""
        if is_ood:
            return {
                "summary": "Analysis limited: target is a single-label or internal hostname without a public top-level domain. Routine monitoring recommended.",
                "detected": f"Input '{hostname}' does not conform to public FQDN syntax (no public TLD observed).",
                "significance": "Classification model is trained on public domain namespace syntax. Local hostnames cannot be reliably scored with public lexical baselines.",
                "next_steps": "Verify internal DNS resolver logs and local DHCP bindings for this host if internal anomaly is suspected. Do not apply automated perimeter blocking.",
                "supporting_evidence": f"Total length: {features['hostname_length']} chars, Labels: {features['num_labels']}, Public TLD: No.",
                "missing_information": "Public DNS resolution and authoritative SOA/NS records are not available for non-public domains."
            }

        if severity == "CRITICAL":
            detected_factors = ", ".join([r["factor"] for r in reasons[:3]])
            return {
                "summary": "Critical risk: High-density lexical anomaly consistent with DNS tunneling. Prompt incident-response investigation advised (Advisory only).",
                "detected": f"High tunneling probability detected on '{hostname}' (Risk Score: {risk_score}/100, Band: CRITICAL). Key factors: {detected_factors}.",
                "significance": "DNS tunneling can allow adversaries to bypass egress firewalls and exfiltrate confidential data or establish C2 channels via recursive DNS resolvers.",
                "next_steps": "Correlate client IP query history in SIEM/Zeek logs. Inspect resolver TXT/CNAME response payload sizes. Quarantine suspicious endpoints according to authorized incident response procedures. Never automatically block domains without authorization.",
                "supporting_evidence": f"Observed Shannon entropy: {features['shannon_entropy']} bits/char; Max label length: {features['max_label_length']} chars; Hex ratio: {round(features['hex_ratio']*100, 1)}%; Subdomain depth: {features['subdomain_depth']}.",
                "missing_information": "Network flow metrics (query volume/frequency, response octets, inter-arrival time jitter) require packet capture ingestion."
            }
        elif severity == "HIGH":
            detected_factors = ", ".join([r["factor"] for r in reasons[:2]])
            return {
                "summary": "High risk: Suspicious lexical pattern detected. Prioritize source host investigation and DNS query inspection.",
                "detected": f"Elevated anomalous lexical characteristics detected on '{hostname}' (Risk Score: {risk_score}/100, Band: HIGH). Contributing factors: {detected_factors}.",
                "significance": "Significantly elevated entropy, deep label depth, or high hex density often indicates encoded data chunks or machine-generated C2 infrastructure.",
                "next_steps": "Investigate query volume from the originating host. Check whether the domain resolves to known dynamic DNS, bulletproof hosting, or unmanaged infrastructure. Consult authorized security team prior to firewall changes.",
                "supporting_evidence": f"Observed entropy: {features['shannon_entropy']} bits/char; Max label: {features['max_label_length']} chars; Digit ratio: {round(features['digit_ratio']*100, 1)}%.",
                "missing_information": "Absence of real-time query rate and payload variance data means static analysis cannot definitively confirm active transmission."
            }
        elif severity == "MODERATE":
            return {
                "summary": "Moderate risk: Unusual domain structure observed. Review query logs to verify whether this is an enterprise CDN, security scanner, or cloud token.",
                "detected": f"Moderate structural variations detected on '{hostname}' (Risk Score: {risk_score}/100, Band: MODERATE).",
                "significance": "Cloud CDNs, analytics providers, and git build previews frequently utilize hash tokens or random IDs in subdomains which resemble encoded payloads.",
                "next_steps": "Correlate with known organizational software-as-a-service providers and CDN registries. If the domain is recognized business software, consider whitelisting.",
                "supporting_evidence": f"Hostname length: {features['hostname_length']} chars; Entropy: {features['shannon_entropy']} bits/char; Label count: {features['num_labels']}.",
                "missing_information": "Traffic frequency, NXDOMAIN ratio, and client application process context are required to distinguish benign CDN tokens from covert channels."
            }
        else: # LOW
            return {
                "summary": "Low risk: Domain conforms to standard naming conventions. No strong suspicious indicators detected. Continue routine monitoring.",
                "detected": f"Standard lexical structure detected on '{hostname}' (Risk Score: {risk_score}/100, Band: LOW).",
                "significance": "Lexical metrics align with standard natural language, brand, and well-formed enterprise hostnames.",
                "next_steps": "Maintain routine continuous DNS monitoring and telemetry collection. No containment or remediation actions required.",
                "supporting_evidence": f"Entropy: {features['shannon_entropy']} bits/char (normal range); Max label: {features['max_label_length']} chars; TLD present: {features['has_known_tld']}.",
                "missing_information": "Static analysis checks lexical properties only. Sophisticated slow-drip dictionary attacks require flow-rate monitoring."
            }

model_manager = DnsModelManager()
