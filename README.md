# SecureHarness: Secure Network Information Sharing Tunnel

An advanced, sandboxed, tamper-proof, antivirus and anti-interference network tunnel engineered for secure real-time information sharing across any network transport.

---

## Key Features

1. **AES-256-GCM + X25519 ECDH Tunnel Core**: Forward-secret authenticated encryption framing wrapping all communication.
2. **Antivirus & Heuristic Engine**: Real-time signature matching, Shannon entropy analysis for obfuscated/packed payloads, and malicious shellcode inspection.
3. **Anti-Bug & Protocol Anomaly Engine**: Detects malformed headers, buffer overflow sequences, format string attacks, and boundary violations.
4. **Anti-Interference & Replay Shield**: Sliding sequence window, timestamp expiration checking, and duplicate tag detection to defeat replay attacks and network interference.
5. **Anti-Tamper & Chain of Custody**: Merkle-style SHA-256 custody chain across all packets, plus startup binary file integrity baseline checks.
6. **Process Sandbox Environment**: Isolated execution directory with timeout containment and restricted environment variables.
7. **Static & Dynamic Telemetry**: Real-time risk scoring, suspicious API/IP extraction, CPU/memory pressure tracking, and live WebSocket telemetry broadcasting.
8. **Real-time SOC Dashboard**: A dark-mode cybersecurity dashboard with live metrics, threat simulation controls, and audit feeds.

---

## Installation & Setup

1. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the automated test suites:
   ```bash
   # Standard functional verification
   python test_harness.py

   # Exhaustive boundary, cryptographic attack & fuzzing suite
   python test_exhaustive.py
   ```

3. Launch the complete system (Tunnel Server + SOC Web Dashboard + Demo Client):
   ```bash
   python run.py
   ```

4. Open the Web Dashboard:
   Navigate to [http://localhost:8080](http://localhost:8080) in your browser.

---

## Directory Overview

```
Network Security/
├── core/
│   ├── crypto.py             # AES-256-GCM, ECDH X25519 & HMAC engine
│   ├── protocol.py           # Binary wire packet framing with 60-byte header
│   ├── sandbox.py            # Isolated execution sandbox
│   └── tunnel.py             # Main SecureTunnelHarness defensive pipeline
├── security/
│   ├── antivirus.py          # Signature & Shannon entropy scanner
│   ├── anti_bug.py           # Buffer overflow & protocol anomaly detector
│   ├── anti_interference.py  # Anti-replay & timing drift protection
│   └── anti_tamper.py        # Cryptographic chain of custody & file hashing
├── telemetry/
│   ├── dynamic_tracer.py     # Live system metrics (CPU, RAM, PPS, logs)
│   ├── engine.py             # Unified telemetry coordinator
│   └── static_analyzer.py    # Byte/string inspection & risk scoring
├── dashboard/
│   ├── server.py             # FastAPI SOC web server & REST API
│   ├── websocket_feed.py     # Real-time WebSocket broadcasting
│   └── static/
│       ├── index.html        # Interactive SOC dashboard UI
│       ├── styles.css        # Premium dark glassmorphism styling
│       └── app.js            # Live telemetry client & threat controls
├── agents/
│   ├── client_agent.py       # Client tunnel node
│   └── server_agent.py       # Server tunnel node
├── signatures/
│   └── virus_sigs.json       # Malware signature database
├── run.py                    # Unified system launcher
└── test_harness.py           # Automated end-to-end test suite
```
