import os
import json
import math
import re
from typing import Dict, Any, List, Optional
from config.settings import SIGNATURE_FILE, MAX_ENTROPY_THRESHOLD

class AntivirusEngine:
    """
    Antivirus & Payload Scanner:
    - Signature-based pattern matching (from signatures DB)
    - Shannon Entropy heuristic for packed malware/encrypted payload detection
    - Suspicious binary headers / shellcode heuristics
    - Malicious keyword detection
    """

    def __init__(self, sig_file_path: Optional[str] = None):
        self.sig_file = sig_file_path or str(SIGNATURE_FILE)
        self.signatures = []
        self.load_signatures()

    def load_signatures(self):
        """Loads signature database from disk"""
        if os.path.exists(self.sig_file):
            try:
                with open(self.sig_file, "r", encoding="utf-8") as f:
                    self.signatures = json.load(f)
            except Exception as e:
                print(f"[AV] Error loading signatures: {e}")
                self.signatures = []

    def calculate_entropy(self, data: bytes) -> float:
        """Calculates Shannon Entropy of payload (0.0 to 8.0)"""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freqs = {}
        for b in data:
            freqs[b] = freqs.get(b, 0) + 1
        for count in freqs.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def scan(self, data: bytes) -> Dict[str, Any]:
        """
        Scans byte payload for threats.
        Returns detailed report: is_clean, detections, entropy, severity, details.
        """
        detections = []
        highest_severity = "LOW"
        entropy = self.calculate_entropy(data)

        # 1. Signature Scanning
        for sig in self.signatures:
            try:
                pat_bytes = bytes.fromhex(sig["pattern_hex"])
                if pat_bytes in data:
                    detections.append({
                        "id": sig["id"],
                        "name": sig["name"],
                        "severity": sig["severity"],
                        "description": sig["description"],
                        "category": sig["category"],
                        "match_type": "EXACT_SIGNATURE"
                    })
            except Exception:
                continue

        # 2. Heuristic: High Shannon Entropy Scan (Packed/Encrypted Malware)
        if entropy >= MAX_ENTROPY_THRESHOLD and len(data) > 64:
            detections.append({
                "id": "HEUR-ENTROPY-001",
                "name": "Suspicious High Entropy Payload",
                "severity": "MEDIUM",
                "description": f"Entropy of {entropy} exceeds safety threshold ({MAX_ENTROPY_THRESHOLD}). Potential packed/obfuscated malware.",
                "category": "Heuristic/Obfuscation",
                "match_type": "ENTROPY_ANALYSIS"
            })

        # 3. Heuristic: Suspicious Executable Magic in unexpected streams
        if data.startswith(b"MZ") or data.startswith(b"\x7fELF") or b"WScript.Shell" in data:
            detections.append({
                "id": "HEUR-EXEC-002",
                "name": "Executable Binary Header Embedded",
                "severity": "HIGH",
                "description": "Raw Windows/Linux executable or ActiveX object found in tunnel payload stream.",
                "category": "Heuristic/ExecutableDelivery",
                "match_type": "MAGIC_HEADER"
            })

        # Determine overall severity
        severities = [d["severity"] for d in detections]
        if "CRITICAL" in severities:
            highest_severity = "CRITICAL"
        elif "HIGH" in severities:
            highest_severity = "HIGH"
        elif "MEDIUM" in severities:
            highest_severity = "MEDIUM"
        elif "LOW" in severities:
            highest_severity = "LOW"

        is_clean = len(detections) == 0

        return {
            "is_clean": is_clean,
            "threat_detected": not is_clean,
            "threat_count": len(detections),
            "severity": highest_severity if not is_clean else "CLEAN",
            "entropy": entropy,
            "detections": detections,
            "payload_size": len(data)
        }
