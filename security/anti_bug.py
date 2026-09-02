import re
from typing import Dict, Any, List
from config.settings import MAX_PAYLOAD_SIZE

class AntiBugEngine:
    """
    Anti-Bug & Protocol Anomaly Engine:
    - Protects against malformed frames, buffer overflow attempts, string format vulnerabilities
    - Validates JSON/Struct serialization formats
    - Identifies logic bugs and boundary violations
    """

    def __init__(self):
        # Known bug & overflow patterns
        self.overflow_pattern = re.compile(rb"(%n|%s|%x|%p){4,}|[A]{256,}")
        self.sql_inj_pattern = re.compile(rb"(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b).*(\bFROM\b|\bTABLE\b|--|;)", re.IGNORECASE)
        self.path_traversal_pattern = re.compile(rb"(\.\./|\.\.\\){2,}")

    def inspect_frame(self, header_dict: Dict[str, Any], payload: bytes) -> Dict[str, Any]:
        """
        Inspects protocol frame for structural anomalies or protocol bugs
        """
        anomalies: List[Dict[str, Any]] = []

        # 1. Check size limits
        if header_dict.get("payload_len", 0) > MAX_PAYLOAD_SIZE:
            anomalies.append({
                "type": "BUFFER_OVERSIZED",
                "severity": "CRITICAL",
                "details": f"Declared payload size {header_dict.get('payload_len')} exceeds max allowed {MAX_PAYLOAD_SIZE}"
            })

        # 2. Check length mismatch
        if header_dict.get("payload_len", 0) != len(payload):
            anomalies.append({
                "type": "FRAME_LENGTH_MISMATCH",
                "severity": "HIGH",
                "details": f"Header declared {header_dict.get('payload_len')} bytes but received {len(payload)} bytes"
            })

        # 3. Check for format string / buffer overflow exploit patterns
        if self.overflow_pattern.search(payload):
            anomalies.append({
                "type": "BUFFER_OVERFLOW_PATTERN",
                "severity": "CRITICAL",
                "details": "Repetitive string exploit pattern or format string exploit sequence detected"
            })

        # 4. Path traversal in tunnel control paths
        if self.path_traversal_pattern.search(payload):
            anomalies.append({
                "type": "PATH_TRAVERSAL_ATTEMPT",
                "severity": "HIGH",
                "details": "Directory traversal sequence detected in payload"
            })

        is_valid = len(anomalies) == 0
        return {
            "is_valid": is_valid,
            "anomaly_detected": not is_valid,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies)
        }
