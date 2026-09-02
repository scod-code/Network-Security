import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Network Tunnel Settings
DEFAULT_HOST = "127.0.0.1"
DEFAULT_TUNNEL_PORT = 9443
DEFAULT_DASHBOARD_PORT = 8080
WS_HEARTBEAT_INTERVAL = 5 # seconds

# Security & Crypto Settings
ARGON2_SALT = b"SecureHarnessDynamicSalt2026SecureTunnel"
NONCE_LENGTH = 12 # 96 bits for AES-GCM
HMAC_DIGEST_LEN = 32 # SHA256

# Antivirus & Heuristic Thresholds
MAX_ENTROPY_THRESHOLD = 7.2 # Payloads above this are flagged as packed/encrypted malware or suspicious
MAX_PAYLOAD_SIZE = 10 * 1024 * 1024 # 10 MB maximum packet size
REPLAY_WINDOW_SECONDS = 30.0 # Messages older or far in the future are rejected
MAX_RISK_SCORE_THRESHOLD = 40 # Payloads scoring >= 40 (HIGH or CRITICAL) are blocked by telemetry policy

# Sandbox directory
SANDBOX_ROOT = BASE_DIR / "sandbox_workspace"
SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)

# Telemetry DB & Storage
SIGNATURE_FILE = BASE_DIR / "signatures" / "virus_sigs.json"
