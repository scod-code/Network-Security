import time
from typing import Dict, Any, Set, List
from config.settings import REPLAY_WINDOW_SECONDS

class AntiInterferenceEngine:
    """
    Anti-Interference, Network Anomaly & Truncation Defense:
    - Protects against Packet Replay Attacks (via Sliding Sequence Window + Nonce caching)
    - Detects Timing Skew / Man-In-The-Middle network interference
    - Detects Session Truncation, Sequence Gaps, and Monotonicity Violations
    - Detects Flood / DoS interference and duplicate frames
    - Enforces Graceful Termination (blocks post-close frame injection)
    """

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.last_seq_num = 0
        self.seen_seq_nums: Set[int] = set()
        self.seen_signatures: Set[bytes] = set()
        self.packet_rate_history: List[float] = []
        self.max_packets_per_sec = 250
        self.session_closed = False
        self.sequence_gaps_detected = 0

    def verify_packet(self, seq_num: int, timestamp: float, auth_tag: bytes, msg_type: int = 2) -> Dict[str, Any]:
        """
        Validates timing, sequence order, replay immunity, truncation, and interference patterns
        """
        now = time.time()
        interferences = []

        # 0. Session Termination Check (Post-Close Injection Defense)
        if self.session_closed:
            interferences.append({
                "type": "POST_TERMINATION_INJECTION",
                "severity": "CRITICAL",
                "details": "Packet received after session was gracefully closed and terminated."
            })

        # 1. Timestamp freshness (Replay Window)
        time_diff = abs(now - timestamp)
        if time_diff > REPLAY_WINDOW_SECONDS:
            interferences.append({
                "type": "TIMESTAMP_EXPIRED_OR_DRIFT",
                "severity": "HIGH",
                "details": f"Packet timestamp drift: {time_diff:.2f}s exceeds window ({REPLAY_WINDOW_SECONDS}s). Potential replay or spoofing."
            })

        # 2. Sequence Number Replay & Monotonicity Check
        if seq_num in self.seen_seq_nums:
            interferences.append({
                "type": "REPLAY_ATTACK_DETECTED",
                "severity": "CRITICAL",
                "details": f"Duplicate sequence number #{seq_num} detected. Replay attack blocked."
            })
        elif seq_num < self.last_seq_num - self.window_size:
            interferences.append({
                "type": "SEQUENCE_OUT_OF_WINDOW",
                "severity": "MEDIUM",
                "details": f"Sequence #{seq_num} is outside sliding window from #{self.last_seq_num}"
            })

        # 2b. Sequence Gap / Truncation Detection
        if self.last_seq_num > 0 and seq_num > self.last_seq_num + 1:
            missing_count = seq_num - (self.last_seq_num + 1)
            self.sequence_gaps_detected += missing_count
            # Recorded as interference warning (adversary dropping frames on the path)
            interferences.append({
                "type": "SEQUENCE_GAP_TRUNCATION",
                "severity": "HIGH",
                "details": f"Detected missing/dropped sequence numbers between #{self.last_seq_num} and #{seq_num} (gap of {missing_count} frames)."
            })

        # 3. Duplicate HMAC / Tag Check (Bit-for-bit replay)
        if auth_tag in self.seen_signatures and auth_tag != b"\x00" * 32:
            interferences.append({
                "type": "DUPLICATE_AUTH_TAG_REPLAY",
                "severity": "CRITICAL",
                "details": "Identical cryptographic auth tag already processed in current session."
            })

        # 4. DoS / Flood Interference Detection
        self.packet_rate_history.append(now)
        self.packet_rate_history = [t for t in self.packet_rate_history if now - t <= 1.0]
        if len(self.packet_rate_history) > self.max_packets_per_sec:
            interferences.append({
                "type": "TRAFFIC_FLOOD_INTERFERENCE",
                "severity": "HIGH",
                "details": f"Packet rate {len(self.packet_rate_history)}/sec exceeds safety cap {self.max_packets_per_sec}/sec."
            })

        # Check for Close Frame (TYPE_CLOSE = 6)
        if msg_type == 6:
            self.session_closed = True

        # If clean, commit sequence
        if not interferences or (len(interferences) == 1 and interferences[0]["type"] == "SEQUENCE_GAP_TRUNCATION"):
            self.seen_seq_nums.add(seq_num)
            if auth_tag != b"\x00" * 32:
                self.seen_signatures.add(auth_tag)
            if seq_num > self.last_seq_num:
                self.last_seq_num = seq_num

            # Trim history to prevent unbounded memory growth
            if len(self.seen_seq_nums) > self.window_size * 2:
                self.seen_seq_nums = {s for s in self.seen_seq_nums if s > self.last_seq_num - self.window_size}
            if len(self.seen_signatures) > self.window_size * 2:
                self.seen_signatures.clear()

        # A sequence gap is flagged for telemetry, but critical blocking errors are replay/timing/flood/post-close
        fatal_interferences = [i for i in interferences if i["type"] != "SEQUENCE_GAP_TRUNCATION"]
        passed = len(fatal_interferences) == 0

        return {
            "passed": passed,
            "interference_detected": len(interferences) > 0,
            "interferences": interferences,
            "current_rate_pps": len(self.packet_rate_history),
            "sequence_gaps_total": self.sequence_gaps_detected,
            "session_closed": self.session_closed
        }
