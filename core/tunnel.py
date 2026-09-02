import asyncio
import time
import json
import hashlib
from typing import Optional, Callable, Dict, Any

from core.crypto import CryptoEngine
from core.protocol import (
    Packet, HEADER_SIZE, TYPE_HANDSHAKE, TYPE_DATA,
    TYPE_HEARTBEAT, TYPE_TELEMETRY, TYPE_ALERT, TYPE_CLOSE,
    MIN_PROTOCOL_VERSION
)
from security.antivirus import AntivirusEngine
from security.anti_bug import AntiBugEngine
from security.anti_interference import AntiInterferenceEngine
from security.anti_tamper import AntiTamperEngine
from security.anti_traffic_analysis import AntiTrafficAnalysis
from core.sandbox import ProcessSandbox
from telemetry.engine import TelemetryEngine
from config.settings import MAX_RISK_SCORE_THRESHOLD

class SecureTunnelHarness:
    """
    SecureHarness Tunnel Core:
    Integrates Crypto (AES-256-GCM + X25519 + Ed25519), TRANSEC (Anti-Traffic Analysis Padding),
    AV, Anti-Bug, Anti-Interference, Anti-Tamper, Sandbox & Telemetry over arbitrary network streams.
    """

    def __init__(self, is_server: bool = True, psk: bytes = None, expected_peer_fingerprint: str = None):
        self.is_server = is_server
        self.crypto = CryptoEngine(psk)
        self.av = AntivirusEngine()
        self.anti_bug = AntiBugEngine()
        self.anti_interference = AntiInterferenceEngine()
        self.anti_tamper = AntiTamperEngine()
        self.sandbox = ProcessSandbox()
        self.telemetry = TelemetryEngine.get_instance()

        self.seq_counter = 0
        self.peer_connected = False
        self.peer_fingerprint = None
        self.peer_signing_pubkey = None
        self.expected_peer_fingerprint = expected_peer_fingerprint
        self.rekey_interval = 1000 # rekey every 1000 packets for perfect forward secrecy

        # Generate ephemeral keypair
        self.private_key, self.public_bytes = CryptoEngine.generate_keypair()

    async def perform_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        """
        Executes authenticated ECDH Key Exchange + Ed25519 Identity Exchange with Peer Fingerprinting
        Handshake Payload: [32B X25519 PubKey] + [32B Ed25519 Signing PubKey] = 64 Bytes
        """
        try:
            my_handshake_bytes = self.public_bytes + self.crypto.signing_public_bytes

            if self.is_server:
                # 1. Server sends its keys
                writer.write(my_handshake_bytes)
                await writer.drain()

                # 2. Server receives client's keys
                client_handshake = await reader.readexactly(64)
                client_ecdh_pub = client_handshake[:32]
                self.peer_signing_pubkey = client_handshake[32:64]
                self.crypto.derive_session_key(self.private_key, client_ecdh_pub)
                self.peer_fingerprint = hashlib.sha256(self.peer_signing_pubkey).hexdigest()[:16]
            else:
                # 1. Client receives server's keys
                server_handshake = await reader.readexactly(64)
                server_ecdh_pub = server_handshake[:32]
                self.peer_signing_pubkey = server_handshake[32:64]
                self.crypto.derive_session_key(self.private_key, server_ecdh_pub)
                self.peer_fingerprint = hashlib.sha256(self.peer_signing_pubkey).hexdigest()[:16]

                # 2. Client sends its keys
                writer.write(my_handshake_bytes)
                await writer.drain()

            # Peer Pinning Check (Masquerade / MITM defense)
            if self.expected_peer_fingerprint and self.peer_fingerprint != self.expected_peer_fingerprint:
                self.telemetry.log_incident(
                    category="PEER_MASQUERADE",
                    severity="CRITICAL",
                    title="Peer Fingerprint Mismatch (Potential MITM / Masquerade)",
                    details={"expected": self.expected_peer_fingerprint, "received": self.peer_fingerprint}
                )
                return False

            self.peer_connected = True
            self.telemetry.log_incident(
                category="TUNNEL_CRYPTO",
                severity="LOW",
                title="Secure Handshake & Identity Established",
                details={
                    "role": "SERVER" if self.is_server else "CLIENT",
                    "cipher": "AES-256-GCM + X25519 + Ed25519",
                    "peer_fingerprint": self.peer_fingerprint
                }
            )
            return True
        except Exception as e:
            self.telemetry.log_incident(
                category="TUNNEL_CRYPTO",
                severity="CRITICAL",
                title="Handshake Failed",
                details={"error": str(e)}
            )
            return False

    def wrap_payload(self, raw_data: bytes, msg_type: int = TYPE_DATA) -> bytes:
        """
        Prepares, signs (Ed25519 Non-Repudiation), pads (TRANSEC Traffic Analysis Defense),
        encrypts (AES-256-GCM), and frames with HMAC-SHA256.
        """
        self.seq_counter += 1
        seq = self.seq_counter
        timestamp = time.time()

        # Automatic Rekeying Ratchet (Forward Secrecy hardening)
        if self.seq_counter % self.rekey_interval == 0:
            self.crypto.rekey()
            self.telemetry.log_incident("KEY_ROTATION", "LOW", "Session Key Automatically Ratcheted (PFS)", {"seq": seq})

        # 1. Non-Repudiation: Ed25519 Digital Signature over raw payload
        # Inner Frame: [64-byte Ed25519 Signature] + [Raw Payload]
        sig = self.crypto.sign_payload(raw_data)
        signed_frame = sig + raw_data

        # 2. TRANSEC: Pad payload to 512-byte blocks to prevent traffic analysis
        padded_frame = AntiTrafficAnalysis.pad_payload(signed_frame, block_size=512)

        # 3. Encrypt padded frame with AES-256-GCM
        encrypted_payload = self.crypto.encrypt(padded_frame)

        # 4. Compute HMAC of (Seq + Timestamp + Encrypted Payload)
        data_to_sign = str(seq).encode() + str(timestamp).encode() + encrypted_payload
        auth_tag = self.crypto.compute_hmac(data_to_sign)

        # 5. Form packet
        packet = Packet(
            msg_type=msg_type,
            seq_num=seq,
            payload=encrypted_payload,
            timestamp=timestamp,
            auth_tag=auth_tag
        )

        serialized = packet.serialize(auth_tag)
        self.telemetry.record_traffic("sent", len(serialized))
        return serialized

    def process_incoming_frame(self, header_bytes: bytes, raw_payload: bytes) -> Dict[str, Any]:
        """
        Full 10-Stage Defensive Security Pipeline:
        1. Protocol Version & Downgrade Prevention
        2. Anti-Bug Wire Frame Inspection
        3. Anti-Interference (Replay, Timing, Truncation & Sequence Gap)
        4. HMAC-SHA256 Authenticated Tag Verification
        5. AES-256-GCM Decryption
        6. TRANSEC Padding Removal
        7. Ed25519 Non-Repudiation Digital Signature Verification
        8. Anti-Bug Deep Content Plaintext Inspection
        9. Antivirus & Shannon Entropy Deep Scan
        10. Static Telemetry, Covert Channel Inspection & Risk Policy Enforcement
        11. Merkle Chain-of-Custody Update
        """
        # Step 1: Parse Header & Protocol Version Check (Downgrade Defense)
        try:
            hdr = Packet.parse_header(header_bytes)
        except Exception as e:
            self.telemetry.log_incident("PROTOCOL_BUG", "CRITICAL", "Corrupt Packet Header or Protocol Downgrade", {"error": str(e)})
            return {"accepted": False, "reason": f"Malformed Header / Downgrade Attempt: {str(e)}"}

        # Step 2: Anti-Bug Engine (Wire Frame Geometry)
        bug_res = self.anti_bug.inspect_frame(hdr, raw_payload)
        if not bug_res["is_valid"]:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("ANTI_BUG", "CRITICAL", "Protocol Bug / Buffer Overflow Attempt Blocked", bug_res)
            return {"accepted": False, "reason": "Anti-Bug Inspection Failed", "anomalies": bug_res["anomalies"]}

        # Step 3: Anti-Interference Engine (Replay, Timing, Seq Gap, Truncation)
        interf_res = self.anti_interference.verify_packet(hdr["seq_num"], hdr["timestamp"], hdr["auth_tag"], hdr["msg_type"])
        if not interf_res["passed"]:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("ANTI_INTERFERENCE", "CRITICAL", "Interference / Replay Attack Blocked", interf_res)
            return {"accepted": False, "reason": "Interference Check Failed", "interferences": interf_res["interferences"]}

        # Step 4: Cryptographic HMAC Verification
        data_to_verify = str(hdr["seq_num"]).encode() + str(hdr["timestamp"]).encode() + raw_payload
        if not self.crypto.verify_hmac(data_to_verify, hdr["auth_tag"]):
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("ANTI_TAMPER", "CRITICAL", "HMAC Tamper Violation", {"seq": hdr["seq_num"]})
            return {"accepted": False, "reason": "Cryptographic Integrity Check Failed (Tampered Payload)"}

        # Step 5: Decrypt Payload (AES-256-GCM)
        try:
            decrypted_padded = self.crypto.decrypt(raw_payload)
        except Exception as e:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("CRYPTO_FAIL", "CRITICAL", "AES-GCM Decryption / Tag Verification Failed", {"error": str(e)})
            return {"accepted": False, "reason": "Decryption Failed"}

        # Step 6: TRANSEC Padding Removal
        try:
            signed_frame = AntiTrafficAnalysis.strip_padding(decrypted_padded)
        except Exception as e:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("TRANSEC_ERROR", "HIGH", "Corrupt TRANSEC Padding Header", {"error": str(e)})
            return {"accepted": False, "reason": f"Padding Error: {str(e)}"}

        # Step 7: Ed25519 Non-Repudiation Verification
        # Format: [64-byte Sig] + [Plaintext]
        if len(signed_frame) < 64:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            return {"accepted": False, "reason": "Payload too short for Ed25519 Non-Repudiation Signature"}

        sig = signed_frame[:64]
        decrypted_plaintext = signed_frame[64:]

        # Verify signature if peer signing key is available
        if self.peer_signing_pubkey:
            sig_valid = CryptoEngine.verify_signature(decrypted_plaintext, sig, self.peer_signing_pubkey)
            if not sig_valid:
                self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
                self.telemetry.log_incident("NON_REPUDIATION", "CRITICAL", "Forged / Invalid Ed25519 Digital Signature", {"seq": hdr["seq_num"]})
                return {"accepted": False, "reason": "Non-Repudiation Signature Verification Failed (Forged Identity)"}

        # Step 8: Anti-Bug Deep Content Inspection (Post-Decryption)
        content_bug_res = self.anti_bug.inspect_frame(
            {"payload_len": len(decrypted_plaintext)},
            decrypted_plaintext
        )
        if not content_bug_res["is_valid"]:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("ANTI_BUG", "CRITICAL", "Exploit Pattern Detected in Decrypted Content", content_bug_res)
            sb_path = self.sandbox.write_payload_to_sandbox("quarantined_exploit.bin", decrypted_plaintext)
            return {
                "accepted": False,
                "reason": "Anti-Bug Deep Content Inspection Failed (Exploit Pattern in Plaintext)",
                "anomalies": content_bug_res["anomalies"],
                "quarantine_path": str(sb_path)
            }

        # Step 9: Antivirus & Heuristic Scanning
        av_res = self.av.scan(decrypted_plaintext)
        if av_res["threat_detected"]:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("ANTIVIRUS", av_res["severity"], "Malicious Payload Quarantined", av_res)
            
            sb_path = self.sandbox.write_payload_to_sandbox("quarantined_threat.bin", decrypted_plaintext)
            return {
                "accepted": False,
                "reason": "Antivirus Signature/Heuristic Match",
                "threat": av_res,
                "quarantine_path": str(sb_path)
            }

        # Step 10: Static Telemetry, Covert Channel Inspection & Risk Policy Enforcement
        static_telemetry = self.telemetry.analyze_static(decrypted_plaintext)
        if static_telemetry.get("risk_score", 0) >= MAX_RISK_SCORE_THRESHOLD:
            self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=True, is_threat=True)
            self.telemetry.log_incident("STATIC_TELEMETRY", static_telemetry["risk_level"], "High Risk Payload Quarantined by Telemetry Policy", static_telemetry)
            sb_path = self.sandbox.write_payload_to_sandbox("quarantined_risky_payload.bin", decrypted_plaintext)
            return {
                "accepted": False,
                "reason": f"Static Telemetry Risk Policy Blocked ({static_telemetry['risk_score']}/100 {static_telemetry['risk_level']} - suspicious APIs/C2/Covert Exfil)",
                "static_telemetry": static_telemetry,
                "quarantine_path": str(sb_path)
            }

        # Step 11: Chain of Custody (Anti-Tamper)
        chain_res = self.anti_tamper.append_and_verify_chain(decrypted_plaintext)

        self.telemetry.record_traffic("received", len(header_bytes) + len(raw_payload), blocked=False, is_threat=False)
        self.telemetry.log_incident("PAYLOAD_CLEARED", "LOW", "Packet Verified & Cleared by Hardened Harness", {
            "seq": hdr["seq_num"],
            "size": len(decrypted_plaintext),
            "chain_length": chain_res["chain_length"]
        })

        return {
            "accepted": True,
            "seq_num": hdr["seq_num"],
            "msg_type": hdr["msg_type"],
            "plaintext": decrypted_plaintext,
            "static_telemetry": static_telemetry,
            "chain_info": chain_res
        }
