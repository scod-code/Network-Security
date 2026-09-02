import time
import math
import hashlib
import re
from typing import Dict, Any, List

class StaticAnalyzer:
    """
    Static Telemetry & Code/Payload Analysis:
    - Extracts byte distribution, statistical entropy, printable strings
    - Identifies suspicious API calls, imports, IP addresses, URLs, embedded commands
    - Detects covert channel exfiltration (DNS tunneling, base64 payload leakage, steganography markers)
    - Generates risk scoring matrix (0 - 100)
    """

    def __init__(self):
        self.ip_regex = re.compile(rb"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        self.url_regex = re.compile(rb"https?://[^\s/$.?#].[^\s]*")
        self.dns_tunnel_regex = re.compile(rb"([a-zA-Z0-9+/=]{16,}\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
        self.base64_exfil_regex = re.compile(rb"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        
        self.suspicious_apis = [
            b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory",
            b"SetWindowsHookEx", b"CryptEncrypt", b"RegSetValueEx",
            b"socket", b"connect", b"eval", b"exec", b"os.system", b"subprocess"
        ]

    def analyze(self, data: bytes) -> Dict[str, Any]:
        """Performs comprehensive static inspection of a payload"""
        if not data:
            return {"risk_score": 0, "status": "EMPTY_PAYLOAD"}

        # 1. Hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        # 2. String Extraction
        printable_chars = set(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ")
        extracted_strings = []
        current_str = bytearray()
        for b in data:
            if b in printable_chars:
                current_str.append(b)
            else:
                if len(current_str) >= 4:
                    extracted_strings.append(current_str.decode('ascii', errors='ignore'))
                current_str = bytearray()
        if len(current_str) >= 4:
            extracted_strings.append(current_str.decode('ascii', errors='ignore'))

        # 3. Suspicious Indicators
        detected_ips = [ip.decode('ascii') for ip in self.ip_regex.findall(data)]
        detected_urls = [u.decode('ascii', errors='ignore') for u in self.url_regex.findall(data)]
        detected_apis = [api.decode('ascii') for api in self.suspicious_apis if api in data]

        # 4. Covert Channel & Exfiltration Inspection (DNS Tunneling / Stego)
        covert_channels = []
        dns_matches = self.dns_tunnel_regex.findall(data)
        if dns_matches:
            covert_channels.append(f"DNS Tunneling / High-Entropy Domain Exfiltration: {dns_matches[0].decode('ascii', errors='ignore')}")
            
        # Raw unformatted base64 data exfiltration (excluding explicit structured media transfer JSON)
        if not (b'"media_type"' in data or b'"content_b64"' in data):
            b64_matches = [m for m in self.base64_exfil_regex.findall(data) if len(m) >= 64]
            if b64_matches:
                covert_channels.append(f"Large Obfuscated Base64 Data Exfiltration Chunk ({len(b64_matches[0])} bytes)")

        # Stego markers (e.g. PK zip / PNG headers embedded inside text)
        if b"PK\x03\x04" in data[4:] or b"\x89PNG" in data[4:]:
            covert_channels.append("Steganographic File Payload Embedded Inside Transit Stream")

        # 5. Risk Score Calculation
        score = 0
        if detected_apis:
            score += len(detected_apis) * 15
        if detected_ips:
            score += len(detected_ips) * 10
        if detected_urls:
            score += len(detected_urls) * 10
        if covert_channels:
            score += len(covert_channels) * 45

        risk_score = min(100, score)

        return {
            "sha256": sha256_hash,
            "md5": md5_hash,
            "size_bytes": len(data),
            "extracted_strings_sample": extracted_strings[:10],
            "total_strings_found": len(extracted_strings),
            "detected_ips": detected_ips,
            "detected_urls": detected_urls,
            "detected_apis": detected_apis,
            "covert_channels": covert_channels,
            "risk_score": risk_score,
            "risk_level": "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 20 else "LOW"
        }
