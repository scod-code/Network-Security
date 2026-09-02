from typing import Dict, Any, List
from telemetry.static_analyzer import StaticAnalyzer
from telemetry.dynamic_tracer import DynamicTracer

class TelemetryEngine:
    """
    Central Telemetry Engine uniting Static Analysis and Dynamic Tracing
    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.static_analyzer = StaticAnalyzer()
        self.dynamic_tracer = DynamicTracer()

    def analyze_static(self, data: bytes) -> Dict[str, Any]:
        return self.static_analyzer.analyze(data)

    def log_incident(self, category: str, severity: str, title: str, details: Dict[str, Any]):
        return self.dynamic_tracer.log_event(category, severity, title, details)

    def record_traffic(self, direction: str, num_bytes: int, blocked: bool = False, is_threat: bool = False):
        self.dynamic_tracer.record_traffic(direction, num_bytes, blocked, is_threat)

    def get_full_telemetry_snapshot(self) -> Dict[str, Any]:
        return {
            "metrics": self.dynamic_tracer.get_system_metrics(),
            "recent_events": self.dynamic_tracer.get_recent_events(30)
        }
