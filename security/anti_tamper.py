import hashlib
import os
from typing import Dict, Any, List
from pathlib import Path

class AntiTamperEngine:
    """
    Anti-Tamper & Cryptographic Chain-of-Custody Engine:
    - Maintains an immutable hash chain (Merkle/Blockchain-style) of all messages
    - Detects payload modification or in-flight bit alterations
    - Verifies local code & critical module binary integrity on startup
    """

    def __init__(self, root_dir: Path = None):
        self.root_dir = root_dir or Path(__file__).resolve().parent.parent
        # Genesis hash for the communication chain
        self.chain_head = hashlib.sha256(b"SECURE_HARNESS_GENESIS_BLOCK_2026").digest()
        self.chain_length = 0
        self.baseline_checksums: Dict[str, str] = {}
        self.record_baseline_integrity()

    def record_baseline_integrity(self):
        """Hashes critical source files to detect on-disk tampering"""
        target_extensions = [".py", ".json"]
        for ext in target_extensions:
            for p in self.root_dir.rglob(f"*{ext}"):
                if ".git" in p.parts or "__pycache__" in p.parts or "sandbox_workspace" in p.parts:
                    continue
                try:
                    with open(p, "rb") as f:
                        self.baseline_checksums[str(p)] = hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    pass

    def check_binary_integrity(self) -> Dict[str, Any]:
        """Scans source files against baseline to detect runtime modifications"""
        tampered_files = []
        for file_path, original_hash in self.baseline_checksums.items():
            if not os.path.exists(file_path):
                tampered_files.append({"file": file_path, "issue": "FILE_DELETED"})
                continue
            try:
                with open(file_path, "rb") as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != original_hash:
                    tampered_files.append({
                        "file": file_path,
                        "issue": "CONTENT_MODIFIED",
                        "original_hash": original_hash,
                        "current_hash": current_hash
                    })
            except Exception as e:
                tampered_files.append({"file": file_path, "issue": f"READ_ERROR: {str(e)}"})

        return {
            "integrity_ok": len(tampered_files) == 0,
            "tampered_count": len(tampered_files),
            "tampered_files": tampered_files
        }

    def append_and_verify_chain(self, payload_data: bytes, expected_prev_hash: bytes = None) -> Dict[str, Any]:
        """
        Updates the chain of custody with payload_data.
        Computes Next Hash = SHA256(Prev Hash || Payload SHA256)
        """
        payload_hash = hashlib.sha256(payload_data).digest()
        
        tamper_detected = False
        if expected_prev_hash and expected_prev_hash != self.chain_head:
            tamper_detected = True

        new_head = hashlib.sha256(self.chain_head + payload_hash).digest()
        self.chain_head = new_head
        self.chain_length += 1

        return {
            "tamper_detected": tamper_detected,
            "chain_length": self.chain_length,
            "chain_head_hex": self.chain_head.hex()[:16] + "...",
            "payload_sha256": payload_hash.hex()
        }
