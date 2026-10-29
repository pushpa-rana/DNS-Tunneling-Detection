import math
import re
from typing import Dict, Any, List

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ai",
    "info", "biz", "me", "dev", "app", "cloud", "security", "tech", "online",
    "xyz", "top", "site", "live", "store", "ru", "cn", "de", "uk", "nl", "eu"
}

VOWELS = set("aeiou")
HEX_CHARS = set("0123456789abcdef")

FEATURE_NAMES = [
    "hostname_length",
    "num_labels",
    "subdomain_depth",
    "max_label_length",
    "avg_label_length",
    "shannon_entropy",
    "digit_ratio",
    "hex_ratio",
    "vowel_ratio",
    "consonant_ratio",
    "consecutive_consonant_max",
    "hyphen_count",
    "underscore_count",
    "repeated_char_ratio",
    "has_known_tld"
]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_features(hostname: str) -> Dict[str, Any]:
    """
    Extracts lexical DNS features from a normalized hostname string.
    Feature extraction is deterministic and identical between training and inference.
    """
    cleaned = hostname.strip().lower()
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]

    labels = cleaned.split(".")
    total_len = len(cleaned)
    num_labels = len(labels)
    
    # Subdomain depth: e.g. a.b.example.com -> labels: 4, depth = 2 (subdomains: 'a', 'b')
    subdomain_depth = max(0, num_labels - 2) if num_labels >= 2 else 0

    label_lengths = [len(label) for label in labels if label]
    max_label_length = max(label_lengths) if label_lengths else 0
    avg_label_length = round(sum(label_lengths) / len(label_lengths), 2) if label_lengths else 0.0

    # Entropy of full hostname without dots
    text_no_dots = "".join(labels)
    text_len = len(text_no_dots) if text_no_dots else 1

    shannon_entropy = calculate_shannon_entropy(cleaned)

    # Character counts
    digit_count = sum(1 for c in text_no_dots if c.isdigit())
    hex_count = sum(1 for c in text_no_dots if c in HEX_CHARS)
    vowel_count = sum(1 for c in text_no_dots if c in VOWELS)
    alpha_count = sum(1 for c in text_no_dots if c.isalpha())
    consonant_count = alpha_count - vowel_count

    digit_ratio = round(digit_count / text_len, 4)
    hex_ratio = round(hex_count / text_len, 4)
    vowel_ratio = round(vowel_count / text_len, 4)
    consonant_ratio = round(consonant_count / text_len, 4)

    # Max consecutive consonants in any label
    consecutive_consonant_max = 0
    for label in labels:
        matches = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", label)
        for m in matches:
            if len(m) > consecutive_consonant_max:
                consecutive_consonant_max = len(m)

    hyphen_count = cleaned.count("-")
    underscore_count = cleaned.count("_")

    # Ratio of unique characters to length (lower = more repeats)
    unique_chars = len(set(text_no_dots))
    repeated_char_ratio = round(1.0 - (unique_chars / text_len), 4)

    # Known TLD check
    tld = labels[-1] if labels else ""
    has_known_tld = 1 if tld in COMMON_TLDS else 0

    return {
        "hostname_length": total_len,
        "num_labels": num_labels,
        "subdomain_depth": subdomain_depth,
        "label_lengths": label_lengths,
        "max_label_length": max_label_length,
        "avg_label_length": avg_label_length,
        "shannon_entropy": shannon_entropy,
        "digit_ratio": digit_ratio,
        "hex_ratio": hex_ratio,
        "vowel_ratio": vowel_ratio,
        "consonant_ratio": consonant_ratio,
        "consecutive_consonant_max": consecutive_consonant_max,
        "hyphen_count": hyphen_count,
        "underscore_count": underscore_count,
        "repeated_char_ratio": repeated_char_ratio,
        "has_known_tld": bool(has_known_tld)
    }

def feature_dict_to_vector(features: Dict[str, Any]) -> List[float]:
    """Converts a feature dict into an ordered float list matching FEATURE_NAMES."""
    return [
        float(features["hostname_length"]),
        float(features["num_labels"]),
        float(features["subdomain_depth"]),
        float(features["max_label_length"]),
        float(features["avg_label_length"]),
        float(features["shannon_entropy"]),
        float(features["digit_ratio"]),
        float(features["hex_ratio"]),
        float(features["vowel_ratio"]),
        float(features["consonant_ratio"]),
        float(features["consecutive_consonant_max"]),
        float(features["hyphen_count"]),
        float(features["underscore_count"]),
        float(features["repeated_char_ratio"]),
        1.0 if features["has_known_tld"] else 0.0
    ]
