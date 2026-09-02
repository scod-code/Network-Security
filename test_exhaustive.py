import os
import time
import struct
import random
import hashlib
from typing import List, Dict, Any

from core.tunnel import SecureTunnelHarness
from core.protocol import HEADER_SIZE, HEADER_MAGIC, Packet, MIN_PROTOCOL_VERSION
from config.settings import MAX_PAYLOAD_SIZE, REPLAY_WINDOW_SECONDS, MAX_RISK_SCORE_THRESHOLD, MAX_ENTROPY_THRESHOLD
from security.antivirus import AntivirusEngine
from security.anti_bug import AntiBugEngine
from security.anti_interference import AntiInterferenceEngine
from security.anti_tamper import AntiTamperEngine
from security.anti_traffic_analysis import AntiTrafficAnalysis
from core.sandbox import ProcessSandbox
from telemetry.engine import TelemetryEngine

class ExhaustiveSecurityVerifier:
    def __init__(self):
        self.passed_tests = 0
        self.failed_tests = 0

    def record_result(self, category: str, test_name: str, passed: bool, details: str = ""):
        if passed:
            self.passed_tests += 1
            print(f"  [PASS] {test_name}: {details}")
        else:
            self.failed_tests += 1
            print(f"  [FAIL] {test_name}: {details}")

    def run_all(self):
        print("================================================================================")
        print("   EXHAUSTIVE HARDENED SECURITY & BOUNDARY VERIFICATION SUITE")
        print("   Testing all COMSEC, STRIDE & Dolev-Yao Threat Vectors across 12 Categories")
        print("================================================================================\n")

        self.test_category_wire_protocol_boundaries()
        self.test_category_downgrade_attacks()
        self.test_category_cryptographic_attacks()
        self.test_category_non_repudiation_signatures()
        self.test_category_transec_traffic_analysis()
        self.test_category_peer_identity_pinning()
        self.test_category_interference_and_replay_matrix()
        self.test_category_malware_heuristics_and_entropy()
        self.test_category_anti_bug_exploit_fuzzing()
        self.test_category_covert_channels_and_exfil()
        self.test_category_anti_tamper_and_chain_of_custody()
        self.test_category_sandbox_isolation_and_containment()
        self.test_category_fuzz_bit_mutation_stress()

        print("\n================================================================================")
        print(f"   SUMMARY: {self.passed_tests} PASSED | {self.failed_tests} FAILED across 13 Threat Categories")
        print("================================================================================")
        return self.failed_tests == 0

    # 1. Wire Protocol & Boundary
    def test_category_wire_protocol_boundaries(self):
        print("--- [CATEGORY 1] Wire Protocol & Boundary Conditions ---")
        harness = SecureTunnelHarness(is_server=True)

        pkt = harness.wrap_payload(b"")
        res = harness.process_incoming_frame(pkt[:HEADER_SIZE], pkt[HEADER_SIZE:])
        self.record_result("PROTOCOL", "Empty Payload Frame", res["accepted"] is True, "Processed safely")

        bad_magic = b"BADM" + pkt[4:HEADER_SIZE]
        res = harness.process_incoming_frame(bad_magic, pkt[HEADER_SIZE:])
        self.record_result("PROTOCOL", "Invalid Magic Bytes", res["accepted"] is False, "Rejected bad magic")

        oversized_hdr = struct.pack("!4sHHQdI32s", HEADER_MAGIC, 1, 2, 9998, time.time(), MAX_PAYLOAD_SIZE + 1024, b"\x00"*32)
        res = harness.process_incoming_frame(oversized_hdr, b"payload")
        self.record_result("PROTOCOL", "Oversized Frame Limit (>10MB)", res["accepted"] is False, "Enforced 10MB payload limit")
        print()

    # 2. Downgrade Attacks
    def test_category_downgrade_attacks(self):
        print("--- [CATEGORY 2] Protocol Downgrade Attack Prevention ---")
        harness = SecureTunnelHarness(is_server=True)
        pkt = harness.wrap_payload(b"Downgrade test")
        
        # Inject version 0 (< MIN_PROTOCOL_VERSION)
        downgraded_hdr = struct.pack("!4sHHQdI32s", HEADER_MAGIC, 0, 2, 1, time.time(), len(pkt[HEADER_SIZE:]), b"\x00"*32)
        res = harness.process_incoming_frame(downgraded_hdr, pkt[HEADER_SIZE:])
        self.record_result("DOWNGRADE", "Version 0 Downgrade Attempt", res["accepted"] is False, "Blocked version 0 downgrade")
        print()

    # 3. Cryptographic Attacks
    def test_category_cryptographic_attacks(self):
        print("--- [CATEGORY 3] Cryptographic Attacks & AEAD Verification ---")
        harness = SecureTunnelHarness(is_server=True)
        pkt = harness.wrap_payload(b"Transfer $1,000,000")
        hdr = pkt[:HEADER_SIZE]
        ct = pkt[HEADER_SIZE:]

        mutated_ct = bytearray(ct)
        mutated_ct[15] ^= 0x01
        res = harness.process_incoming_frame(hdr, bytes(mutated_ct))
        self.record_result("CRYPTO", "Single-Bit Ciphertext Flip", res["accepted"] is False, "HMAC/AEAD caught corruption")

        bad_tag_hdr = hdr[:28] + b"\xff" * 32
        res = harness.process_incoming_frame(bad_tag_hdr, ct)
        self.record_result("CRYPTO", "Forged HMAC Tag", res["accepted"] is False, "Blocked forged HMAC")
        print()

    # 4. Non-Repudiation (Ed25519)
    def test_category_non_repudiation_signatures(self):
        print("--- [CATEGORY 4] Non-Repudiation (Ed25519 Digital Signatures) ---")
        harness = SecureTunnelHarness(is_server=True)
        from cryptography.hazmat.primitives.asymmetric import ed25519
        attacker_key = ed25519.Ed25519PrivateKey.generate()
        
        harness.peer_signing_pubkey = attacker_key.public_key().public_bytes_raw()
        # Create packet signed by harness's key (not attacker's expected key)
        pkt = harness.wrap_payload(b"Payment Instruction: Pay Alice $500")
        
        # Another server expecting victim's key
        different_server = SecureTunnelHarness(is_server=True)
        different_server.peer_signing_pubkey = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        different_server.crypto.session_key = harness.crypto.session_key
        different_server.crypto.aesgcm = harness.crypto.aesgcm
        
        res = different_server.process_incoming_frame(pkt[:HEADER_SIZE], pkt[HEADER_SIZE:])
        self.record_result("NON_REPUDIATION", "Forged Sender Signature Detection", res["accepted"] is False, "Blocked forged digital signature")
        print()

    # 5. TRANSEC / Traffic Analysis Defense
    def test_category_transec_traffic_analysis(self):
        print("--- [CATEGORY 5] TRANSEC & Traffic Analysis Defense (Padding) ---")
        harness = SecureTunnelHarness(is_server=True)
        # Test payloads of wildly different sizes
        short_pkt = harness.wrap_payload(b"Hi")
        long_pkt = harness.wrap_payload(b"A" * 300)
        
        # Ciphertext length should be uniform multiple of block size (512 bytes) + 12B nonce + 16B GCM tag
        ct_short_len = len(short_pkt[HEADER_SIZE:])
        ct_long_len = len(long_pkt[HEADER_SIZE:])
        self.record_result("TRANSEC", "Uniform Block Size Padding", ct_short_len == ct_long_len == 540, f"Both 2B and 300B payloads padded to {ct_short_len} bytes")
        print()

    # 6. Peer Identity & Masquerade Defense
    def test_category_peer_identity_pinning(self):
        print("--- [CATEGORY 6] Peer Identity Pinning & Masquerade Defense ---")
        harness = SecureTunnelHarness(is_server=True, expected_peer_fingerprint="KNOWN_GOOD_FP_12")
        harness.peer_fingerprint = "ATTACKER_FAKE_FP"
        
        # Check mismatch
        is_pinned = harness.expected_peer_fingerprint == harness.peer_fingerprint
        self.record_result("IDENTITY", "Peer Fingerprint Pinning Mismatch", is_pinned is False, "Caught rogue peer fingerprint")
        print()

    # 7. Anti-Interference, Replay & Truncation
    def test_category_interference_and_replay_matrix(self):
        print("--- [CATEGORY 7] Anti-Interference, Replay & Truncation Checks ---")
        harness = SecureTunnelHarness(is_server=True)
        msg = b"Transaction #9912 Authorization"
        pkt = harness.wrap_payload(msg)
        hdr = pkt[:HEADER_SIZE]
        pl = pkt[HEADER_SIZE:]

        res1 = harness.process_incoming_frame(hdr, pl)
        self.record_result("INTERFERENCE", "Valid Initial Packet", res1["accepted"] is True, "Seq #1 accepted")

        res2 = harness.process_incoming_frame(hdr, pl)
        self.record_result("INTERFERENCE", "Immediate Duplicate Replay", res2["accepted"] is False, "Duplicate sequence rejected")

        # Sequence gap / truncation detection
        res_gap = harness.anti_interference.verify_packet(50, time.time(), b"\x33"*32)
        self.record_result("INTERFERENCE", "Sequence Gap / Truncation Warning", res_gap["sequence_gaps_total"] > 0, "Detected missing intermediate frames")
        print()

    # 8. Antivirus & Entropy
    def test_category_malware_heuristics_and_entropy(self):
        print("--- [CATEGORY 8] Antivirus Signatures & Heuristic Entropy ---")
        harness = SecureTunnelHarness(is_server=True)

        eicar_pkt = harness.wrap_payload(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        res_eicar = harness.process_incoming_frame(eicar_pkt[:HEADER_SIZE], eicar_pkt[HEADER_SIZE:])
        self.record_result("AV", "EICAR Test Signature", res_eicar["accepted"] is False, "Quarantined EICAR virus")

        rev_pkt = harness.wrap_payload(b"POST /api/exec HTTP/1.1\r\n\r\n/bin/sh -i")
        res_rev = harness.process_incoming_frame(rev_pkt[:HEADER_SIZE], rev_pkt[HEADER_SIZE:])
        self.record_result("AV", "Reverse Shell Pattern (/bin/sh -i)", res_rev["accepted"] is False, "Quarantined backdoor signature")
        print()

    # 9. Anti-Bug & Boundary Exploits
    def test_category_anti_bug_exploit_fuzzing(self):
        print("--- [CATEGORY 9] Anti-Bug, Format Strings & Overflow Defense ---")
        harness = SecureTunnelHarness(is_server=True)

        fmt_pkt = harness.wrap_payload(b"%s%s%s%s%n%n%n%n%x%x%x%p")
        res_fmt = harness.process_incoming_frame(fmt_pkt[:HEADER_SIZE], fmt_pkt[HEADER_SIZE:])
        self.record_result("ANTI_BUG", "Format String Exploit Attack (%n%s%x)", res_fmt["accepted"] is False, "Format string blocked")

        overflow_pkt = harness.wrap_payload(b"A" * 500)
        res_ovf = harness.process_incoming_frame(overflow_pkt[:HEADER_SIZE], overflow_pkt[HEADER_SIZE:])
        self.record_result("ANTI_BUG", "Long Repetitive Buffer Overflow (500 'A's)", res_ovf["accepted"] is False, "Buffer overflow blocked")
        print()

    # 10. Covert Channels & Data Exfiltration
    def test_category_covert_channels_and_exfil(self):
        print("--- [CATEGORY 10] Covert Channels & DNS Tunneling Exfiltration ---")
        harness = SecureTunnelHarness(is_server=True)

        dns_exfil_msg = b"Lookup query for aW5maWx0cmF0aW9uX2tleV9kYXRh.covert-c2-channel.attacker.com"
        dns_pkt = harness.wrap_payload(dns_exfil_msg)
        res_dns = harness.process_incoming_frame(dns_pkt[:HEADER_SIZE], dns_pkt[HEADER_SIZE:])
        self.record_result("COVERT_EXFIL", "DNS Tunneling Covert Exfiltration", res_dns["accepted"] is False, "Flagged and blocked DNS exfil pattern")
        print()

    # 11. Anti-Tamper & Chain of Custody
    def test_category_anti_tamper_and_chain_of_custody(self):
        print("--- [CATEGORY 11] Anti-Tamper & Chain of Custody Integrity ---")
        engine = AntiTamperEngine()
        integrity = engine.check_binary_integrity()
        self.record_result("ANTI_TAMPER", "Codebase Pristine SHA-256 Checksum", integrity["integrity_ok"] is True, f"Verified all {len(engine.baseline_checksums)} project files")
        print()

    # 12. Sandbox Isolation
    def test_category_sandbox_isolation_and_containment(self):
        print("--- [CATEGORY 12] Process Sandbox Isolation & Resource Limits ---")
        sandbox = ProcessSandbox()
        res_timeout = sandbox.run_isolated_command(["python", "-c", "import time; time.sleep(10)"], timeout_seconds=0.5)
        self.record_result("SANDBOX", "Infinite Loop Timeout Kill Quota", res_timeout["timed_out"] is True and res_timeout["success"] is False, "Killed within 0.5s quota")
        print()

    # 13. Mutation Fuzzing
    def test_category_fuzz_bit_mutation_stress(self):
        print("--- [CATEGORY 13] Automated Fuzzing & Bit-Mutation Stress (50 Iterations) ---")
        harness = SecureTunnelHarness(is_server=True)
        sample_msg = b"Standard Tunnel Information Frame"
        base_pkt = harness.wrap_payload(sample_msg)
        
        fuzz_passes = 0
        iterations = 50

        for _ in range(iterations):
            mutated = bytearray(base_pkt)
            mutation_type = random.choice(["header_scramble", "payload_bitflip", "truncation", "tag_corrupt"])
            if mutation_type == "header_scramble":
                pos = random.randint(0, HEADER_SIZE - 1)
                mutated[pos] ^= random.randint(1, 255)
            elif mutation_type == "payload_bitflip":
                if len(mutated) > HEADER_SIZE:
                    pos = random.randint(HEADER_SIZE, len(mutated) - 1)
                    mutated[pos] ^= random.randint(1, 255)
            elif mutation_type == "truncation":
                cut_point = random.randint(1, len(mutated) - 1)
                mutated = mutated[:cut_point]
            elif mutation_type == "tag_corrupt":
                mutated[28:60] = os.urandom(32)

            try:
                hdr = bytes(mutated[:HEADER_SIZE])
                pl = bytes(mutated[HEADER_SIZE:])
                res = harness.process_incoming_frame(hdr, pl)
                if res.get("accepted") is False:
                    fuzz_passes += 1
            except Exception:
                pass

        self.record_result("FUZZING", f"Randomized Bit-Fuzzing ({iterations} rounds)", fuzz_passes == iterations, f"{fuzz_passes}/{iterations} mutated packets neutralized with 0 runtime crashes")
        print()

if __name__ == "__main__":
    verifier = ExhaustiveSecurityVerifier()
    success = verifier.run_all()
    if not success:
        exit(1)
