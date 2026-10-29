import asyncio
import threading
import time
import random
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from collections import deque

from app.database import SessionLocal
from app.services.analyzer import analyze_and_record
from app.ml.dataset import LEGIT_BASES, LEGIT_PREFIXES, TUNNEL_BASES, generate_base32_chunk, generate_hex_chunk

class MonitoringStreamEngine:
    def __init__(self):
        self.mode: str = "IDLE" # IDLE, DEMO_STREAM, CSV_REPLAY
        self.status: str = "STOPPED" # STOPPED, RUNNING, PAUSED
        self.speed_ms: int = 1500
        self.total_streamed: int = 0
        self.suspicious_streamed: int = 0
        self.recent_events = deque(maxlen=100) # Ring buffer for live display
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set() # Unpaused initially

        # CSV Replay state
        self.replay_queue: List[str] = []
        self.replay_index: int = 0

    def get_status(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "status": self.status,
            "speed_ms": self.speed_ms,
            "total_streamed": self.total_streamed,
            "suspicious_streamed": self.suspicious_streamed,
            "replay_progress": {
                "current": self.replay_index,
                "total": len(self.replay_queue)
            } if self.mode == "CSV_REPLAY" else None
        }

    def start_demo_stream(self, speed_ms: int = 1500) -> Dict[str, Any]:
        self.stop()
        self.mode = "DEMO_STREAM"
        self.speed_ms = max(200, min(10000, speed_ms))
        self.status = "RUNNING"
        self._stop_event.clear()
        self._pause_event.set()

        self._thread = threading.Thread(target=self._run_demo_loop, daemon=True)
        self._thread.start()
        return self.get_status()

    def start_csv_replay(self, hostnames: List[str], speed_ms: int = 1500) -> Dict[str, Any]:
        self.stop()
        self.mode = "CSV_REPLAY"
        self.speed_ms = max(200, min(10000, speed_ms))
        self.replay_queue = hostnames
        self.replay_index = 0
        self.status = "RUNNING"
        self._stop_event.clear()
        self._pause_event.set()

        self._thread = threading.Thread(target=self._run_replay_loop, daemon=True)
        self._thread.start()
        return self.get_status()

    def pause(self) -> Dict[str, Any]:
        if self.status == "RUNNING":
            self.status = "PAUSED"
            self._pause_event.clear()
        return self.get_status()

    def resume(self) -> Dict[str, Any]:
        if self.status == "PAUSED":
            self.status = "RUNNING"
            self._pause_event.set()
        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        self.status = "STOPPED"
        self.mode = "IDLE"
        self._stop_event.set()
        self._pause_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        self._thread = None
        return self.get_status()

    def get_recent_events(self, limit: int = 25) -> List[Dict[str, Any]]:
        events = list(self.recent_events)
        return events[-limit:]

    def _generate_demo_domain(self) -> str:
        # 75% legit, 25% tunneling to mimic realistic network telemetry
        if random.random() < 0.75:
            base = random.choice(LEGIT_BASES)
            p = random.choice(LEGIT_PREFIXES)
            if random.random() < 0.3:
                return f"{p}.{random.choice(LEGIT_PREFIXES)}.{base}"
            return f"{p}.{base}"
        else:
            base = random.choice(TUNNEL_BASES)
            if random.random() < 0.5:
                # Iodine style
                payload = generate_base32_chunk(random.randint(30, 48))
                return f"{payload}.tunnel.{base}"
            else:
                # DNScat2 style
                sess = generate_hex_chunk(8)
                payload = generate_hex_chunk(random.randint(24, 40))
                return f"dnscat.{sess}.{payload}.{base}"

    def _run_demo_loop(self):
        while not self._stop_event.is_set():
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            domain = self._generate_demo_domain()
            db = SessionLocal()
            try:
                res = analyze_and_record(
                    db=db,
                    hostname=domain,
                    enable_enrichment=False,
                    source="DEMO_STREAM",
                    client_ip=f"192.168.1.{random.randint(10, 220)}"
                )
                self.total_streamed += 1
                if res["is_suspicious"]:
                    self.suspicious_streamed += 1

                event_item = {
                    "id": res["id"],
                    "hostname": res["hostname"],
                    "is_suspicious": res["is_suspicious"],
                    "risk_score": res["risk_score"],
                    "severity": res["severity"],
                    "source": "DEMO_STREAM",
                    "client_ip": res["client_ip"],
                    "timestamp": res["timestamp"].isoformat() if hasattr(res["timestamp"], "isoformat") else str(res["timestamp"])
                }
                self.recent_events.append(event_item)
            except Exception as e:
                pass
            finally:
                db.close()

            time.sleep(self.speed_ms / 1000.0)

    def _run_replay_loop(self):
        while not self._stop_event.is_set() and self.replay_index < len(self.replay_queue):
            self._pause_event.wait()
            if self._stop_event.is_set():
                break

            domain = self.replay_queue[self.replay_index]
            self.replay_index += 1

            db = SessionLocal()
            try:
                res = analyze_and_record(
                    db=db,
                    hostname=domain,
                    enable_enrichment=False,
                    source="CSV_REPLAY",
                    client_ip=f"10.20.0.{random.randint(5, 150)}"
                )
                self.total_streamed += 1
                if res["is_suspicious"]:
                    self.suspicious_streamed += 1

                event_item = {
                    "id": res["id"],
                    "hostname": res["hostname"],
                    "is_suspicious": res["is_suspicious"],
                    "risk_score": res["risk_score"],
                    "severity": res["severity"],
                    "source": "CSV_REPLAY",
                    "client_ip": res["client_ip"],
                    "timestamp": res["timestamp"].isoformat() if hasattr(res["timestamp"], "isoformat") else str(res["timestamp"])
                }
                self.recent_events.append(event_item)
            except Exception:
                pass
            finally:
                db.close()

            time.sleep(self.speed_ms / 1000.0)

        if self.replay_index >= len(self.replay_queue):
            self.status = "STOPPED"
            self.mode = "IDLE"

stream_engine = MonitoringStreamEngine()
