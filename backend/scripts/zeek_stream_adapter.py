#!/usr/bin/env python3
"""
DNS Shield AI — Zeek DNS Stream Ingestion Adapter
-------------------------------------------------
Authorized lightweight agent to tail live Zeek dns.log files (JSON or TSV)
and stream real-time events to the DNS Shield AI API server.

Usage:
    python zeek_stream_adapter.py --api-url http://localhost:8001 --api-key shield-sec-dev-api-key-2026 --log-file /opt/zeek/logs/current/dns.log
"""

import sys
import os
import time
import json
import argparse
import urllib.request
import urllib.error

def send_batch(api_url: str, api_key: str, events: list):
    if not events:
        return
    url = f"{api_url.rstrip('/')}/api/monitoring/ingest"
    payload = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "DNSShield-ZeekAdapter/1.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Ingested {len(events)} events | Suspicious: {res_data.get('suspicious_detected', 0)}")
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: {e.read().decode('utf-8')}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Network error sending batch: {e}", file=sys.stderr)

def tail_file(file_path: str):
    """Generator that yields new lines appended to a file."""
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' does not exist.", file=sys.stderr)
        return

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        # Seek to the end of the file to tail only new events
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def main():
    parser = argparse.ArgumentParser(description="DNS Shield AI — Zeek DNS Log Stream Adapter")
    parser.add_argument("--api-url", default="http://127.0.0.1:8001", help="DNS Shield API URL")
    parser.add_argument("--api-key", default="shield-sec-dev-api-key-2026", help="Ingestion API Key")
    parser.add_argument("--log-file", required=True, help="Path to Zeek dns.log file")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size before POSTing")
    parser.add_argument("--batch-timeout", type=float, default=2.0, help="Max seconds to buffer events")

    args = parser.parse_args()

    print(f"[*] Starting DNS Shield Zeek Adapter...")
    print(f"[*] Target API: {args.api_url}")
    print(f"[*] Tailing: {args.log_file}")

    batch = []
    last_send = time.time()

    try:
        for line in tail_file(args.log_file):
            if not line or line.startswith("#"):
                continue

            event = None
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    q = obj.get("query")
                    if q and "." in q:
                        event = {
                            "hostname": q,
                            "client_ip": obj.get("id.orig_h", "unknown"),
                            "query_type": obj.get("qtype_name", "A"),
                            "source": "ZEEK_STREAM"
                        }
                except Exception:
                    pass
            else:
                parts = line.split("\t")
                if len(parts) >= 10:
                    q = parts[9].strip()
                    if "." in q and q != "-":
                        event = {
                            "hostname": q,
                            "client_ip": parts[2].strip() if len(parts) > 2 else "unknown",
                            "query_type": parts[13].strip() if len(parts) > 13 else "A",
                            "source": "ZEEK_STREAM"
                        }

            if event:
                batch.append(event)

            if len(batch) >= args.batch_size or (batch and time.time() - last_send >= args.batch_timeout):
                send_batch(args.api_url, args.api_key, batch)
                batch = []
                last_send = time.time()

    except KeyboardInterrupt:
        print("\n[*] Adapter stopped by operator.")
        if batch:
            send_batch(args.api_url, args.api_key, batch)

if __name__ == "__main__":
    main()
