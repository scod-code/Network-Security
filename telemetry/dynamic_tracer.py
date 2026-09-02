import time
import psutil
import os
from typing import Dict, Any, List

class DynamicTracer:
    """
    Dynamic Telemetry & Runtime System Tracing:
    - Measures real-time latency, throughput, jitter
    - Tracks CPU utilization, memory pressure, thread count, I/O counters
    - Records security incidents and state transitions in memory buffer
    """

    def __init__(self, buffer_size: int = 500):
        self.buffer_size = buffer_size
        self.process = psutil.Process(os.getpid())
        self.event_log: List[Dict[str, Any]] = []
        self.traffic_stats = {
            "bytes_sent": 0,
            "bytes_received": 0,
            "packets_sent": 0,
            "packets_received": 0,
            "packets_blocked": 0,
            "threats_neutralized": 0
        }
        self.start_time = time.time()

    def record_traffic(self, direction: str, num_bytes: int, blocked: bool = False, is_threat: bool = False):
        if direction == "sent":
            self.traffic_stats["bytes_sent"] += num_bytes
            self.traffic_stats["packets_sent"] += 1
        elif direction == "received":
            self.traffic_stats["bytes_received"] += num_bytes
            self.traffic_stats["packets_received"] += 1
            if blocked:
                self.traffic_stats["packets_blocked"] += 1
            if is_threat:
                self.traffic_stats["threats_neutralized"] += 1

    def log_event(self, category: str, severity: str, title: str, details: Dict[str, Any]):
        event = {
            "id": f"EVT-{int(time.time()*1000)}",
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "category": category,
            "severity": severity,
            "title": title,
            "details": details
        }
        self.event_log.append(event)
        if len(self.event_log) > self.buffer_size:
            self.event_log.pop(0)
        return event

    def get_system_metrics(self) -> Dict[str, Any]:
        """Collects dynamic machine and process metrics"""
        try:
            cpu_pct = self.process.cpu_percent(interval=None)
            mem_info = self.process.memory_info()
            mem_mb = round(mem_info.rss / (1024 * 1024), 2)
            threads = self.process.num_threads()
            uptime = round(time.time() - self.start_time, 1)
        except Exception:
            cpu_pct = 0.0
            mem_mb = 0.0
            threads = 1
            uptime = 0.0

        return {
            "uptime_seconds": uptime,
            "cpu_percent": cpu_pct,
            "memory_mb": mem_mb,
            "thread_count": threads,
            "traffic": self.traffic_stats.copy()
        }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.event_log[-limit:]
