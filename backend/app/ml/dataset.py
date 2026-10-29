import random
import string
import base64
from typing import List, Tuple

LEGIT_BASES = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "github.com", "cloudflare.com", "wikipedia.org", "linkedin.com", "zoom.us",
    "spotify.com", "slack.com", "salesforce.com", "adobe.com", "atlassian.net",
    "gitlab.com", "shopify.com", "dropbox.com", "paypal.com", "stripe.com",
    "stackoverflow.com", "medium.com", "nytimes.com", "bbc.co.uk", "cnn.com",
    "reddit.com", "quora.com", "pinterest.com", "twitter.com", "instagram.com",
    "example.com", "example.net", "example.org"
]

LEGIT_PREFIXES = [
    "www", "api", "mail", "cdn", "static", "auth", "dev", "staging", "test",
    "portal", "app", "dashboard", "gateway", "service", "login", "sso",
    "accounts", "cloud", "us-east-1", "eu-central-1", "prod", "internal",
    "assets", "media", "secure", "dns", "ns1", "ns2", "smtp", "vpn"
]

# Benign short hashes / commit tokens (e.g. assets-a8f92k.github.com, commit-39a8bc1.gitlab.io)
BENIGN_TOKENS = [
    "commit-8f92ab1", "assets-a8f92k", "release-v2-4a8f9", "build-8921bca",
    "pkg-7f8910", "bundle-49ab12", "cache-a921fe", "node-7a91bf", "v1-a8f92k"
]

TUNNEL_BASES = [
    "dnstunnel.net", "tunnel-exfil.xyz", "covert-channel.biz", "c2-relay.org",
    "iodine-dns.info", "beacon-stage.cc", "data-drop.top", "stealth-exfil.site",
    "ns-c2-tunnel.online", "command-ctrl.tech"
]

def generate_base32_chunk(length: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    return "".join(random.choices(alphabet, k=length))

def generate_hex_chunk(length: int) -> str:
    alphabet = "0123456789abcdef"
    return "".join(random.choices(alphabet, k=length))

def generate_base64_chunk(length: int) -> str:
    raw = "".join(random.choices(string.ascii_letters + string.digits, k=length)).encode("utf-8")
    encoded = base64.b64encode(raw).decode("utf-8").lower().replace("=", "").replace("+", "-").replace("/", "_")
    return encoded[:length]

def generate_dataset(num_samples: int = 5000, random_state: int = 42) -> Tuple[List[str], List[int]]:
    """
    Generates a realistic labeled dataset for training and testing DNS tunneling detection.
    Label 0 = Benign/Legitimate (including CDN tokens, git hashes, and standard example.com subdomains)
    Label 1 = DNS Tunneling / Exfiltration (Iodine, DNScat2, Base64 exfil, deep multi-label chunks)
    """
    random.seed(random_state)
    half = num_samples // 2
    domains: List[str] = []
    labels: List[int] = []

    # 1. Generate Legitimate Samples (Label 0)
    for _ in range(half):
        choice = random.random()
        base = random.choice(LEGIT_BASES)
        
        if choice < 0.15:
            # Simple root domain (e.g. google.com, example.com)
            domain = base
        elif choice < 0.40:
            # Single standard prefix (e.g. api.stripe.com, test.example.com)
            prefix = random.choice(LEGIT_PREFIXES)
            domain = f"{prefix}.{base}"
        elif choice < 0.70:
            # Multi-level legit enterprise subdomain (e.g. prod.us-east-1.k8s.service.internal.amazon.com)
            p1 = random.choice(LEGIT_PREFIXES)
            p2 = random.choice(LEGIT_PREFIXES)
            p3 = random.choice(LEGIT_PREFIXES)
            domain = f"{p1}.{p2}.{p3}.{base}"
        elif choice < 0.82:
            # Long descriptive enterprise service cluster (e.g. customer-billing-service-v2-prod-cluster.atlassian.net)
            svc = random.choice(["analytics-pipeline", "customer-billing", "identity-sso-gateway", "telemetry-collector", "order-processing"])
            env = random.choice(["production-primary", "staging-cluster-01", "us-east-datacenter"])
            domain = f"{svc}-{env}.{base}"
        elif choice < 0.90:
            # Complex enterprise CDN, S3, or asset hash (e.g. static-98afc210d4.cloudfront.net, s3-9a8f21.amazon.com)
            hex_token = generate_hex_chunk(random.randint(12, 28))
            p = random.choice(["cdn", "assets", "static", "pkg", "cache", "edge", "build"])
            domain = f"{p}-{hex_token}.{base}"
        elif choice < 0.96:
            # Synthetic random test hostnames under example.com or common test domains
            rand_token = "".join(random.choices("abcdef0123456789", k=random.randint(8, 16)))
            domain = f"test-{rand_token}.example.com"
        else:
            # Hyphenated legit service (e.g. static-assets-cache.cloudflare.com)
            p1 = random.choice(LEGIT_PREFIXES)
            p2 = random.choice(LEGIT_PREFIXES)
            domain = f"{p1}-{p2}.{base}"
            
        domains.append(domain)
        labels.append(0)

    # 2. Generate Tunneling Samples (Label 1)
    for _ in range(half):
        mode = random.choice(["iodine_base32", "dnscat_hex", "base64_exfil", "deep_subdomain_chunks", "stealth_short_chunk"])
        base = random.choice(TUNNEL_BASES)
        
        if mode == "iodine_base32":
            # Iodine style: 28-56 character base32 chunk
            payload_len = random.randint(28, 56)
            payload = generate_base32_chunk(payload_len)
            domain = f"{payload}.{base}"
        elif mode == "dnscat_hex":
            # DNScat2 style: hex packet prefix + hex payload chunk
            session_id = generate_hex_chunk(8)
            seq = generate_hex_chunk(4)
            payload = generate_hex_chunk(random.randint(26, 50))
            domain = f"dnscat.{session_id}.{seq}.{payload}.{base}"
        elif mode == "base64_exfil":
            # Encoded file exfiltration chunk
            chunk = generate_base64_chunk(random.randint(28, 52))
            domain = f"{chunk}.exfil.{base}"
        elif mode == "stealth_short_chunk":
            # Stealthy slow-drip exfiltration using shorter hex/base32 chunks (16-24 chars)
            chunk = generate_hex_chunk(random.randint(16, 24))
            domain = f"v1.{chunk}.{base}"
        else:
            # Multi-label deep chunk tunneling
            c1 = generate_hex_chunk(random.randint(16, 26))
            c2 = generate_base32_chunk(random.randint(16, 26))
            c3 = generate_hex_chunk(random.randint(10, 20))
            domain = f"{c1}.{c2}.{c3}.tunnel.{base}"

        domains.append(domain)
        labels.append(1)

    # Shuffle synchronously
    combined = list(zip(domains, labels))
    random.shuffle(combined)
    domains, labels = zip(*combined)
    return list(domains), list(labels)
