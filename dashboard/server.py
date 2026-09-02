import os
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from telemetry.engine import TelemetryEngine
from dashboard.websocket_feed import ws_manager, telemetry_broadcast_loop
from security.antivirus import AntivirusEngine
from security.anti_tamper import AntiTamperEngine
from core.sandbox import ProcessSandbox

STATIC_DIR = Path(__file__).resolve().parent / "static"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start background telemetry pusher
    loop_task = asyncio.create_task(telemetry_broadcast_loop())
    yield
    loop_task.cancel()

app = FastAPI(title="SecureHarness Security Operations Center", lifespan=lifespan)

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

class ThreatInjectRequest(BaseModel):
    threat_type: str  # "EICAR", "REVSHELL", "REPLAY", "TAMPER_HMAC", "BUFFER_OVERFLOW", "CLEAN"
    custom_message: str = ""

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = STATIC_DIR / "index.html"
    return FileResponse(str(index_path))

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep receiving client pings if any
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

@app.get("/api/telemetry")
async def get_telemetry():
    telemetry = TelemetryEngine.get_instance()
    return telemetry.get_full_telemetry_snapshot()

@app.get("/api/integrity")
async def check_integrity():
    anti_tamper = AntiTamperEngine()
    return anti_tamper.check_binary_integrity()

@app.post("/api/simulate-threat")
async def simulate_threat(req: ThreatInjectRequest):
    """
    Endpoint for live SOC testing and demonstration:
    Injects custom test vectors through the harness pipeline and records telemetry response.
    """
    from core.tunnel import SecureTunnelHarness
    harness = SecureTunnelHarness(is_server=True)
    telemetry = TelemetryEngine.get_instance()

    payload = b""
    if req.threat_type == "EICAR":
        payload = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    elif req.threat_type == "REVSHELL":
        payload = b"GET /admin?cmd=/bin/sh%20-i HTTP/1.1\r\nHost: target\r\n\r\n"
    elif req.threat_type == "BUFFER_OVERFLOW":
        payload = b"%s%s%s%s%s%s%s%n%n%n%n" + (b"A" * 300)
    elif req.threat_type == "TAMPER_HMAC":
        # Simulate modified ciphertext
        packet = harness.wrap_payload(b"Confidential Banking Transaction: Transfer $50,000")
        # Tamper 1 bit in packet payload
        tampered_packet = packet[:-4] + b"\xff\xff\xff\xff"
        from core.protocol import HEADER_SIZE
        header = tampered_packet[:HEADER_SIZE]
        raw_pl = tampered_packet[HEADER_SIZE:]
        res = harness.process_incoming_frame(header, raw_pl)
        return {"status": "TEST_COMPLETED", "result": res}
    elif req.threat_type == "REPLAY":
        # Simulate replay
        packet = harness.wrap_payload(b"Authorized Payment Token: #9931-XYZ")
        from core.protocol import HEADER_SIZE
        header = packet[:HEADER_SIZE]
        raw_pl = packet[HEADER_SIZE:]
        # Send once
        harness.process_incoming_frame(header, raw_pl)
        # Replay duplicate
        res = harness.process_incoming_frame(header, raw_pl)
        return {"status": "TEST_COMPLETED", "result": res}
    else:
        # Clean payload
        msg = req.custom_message if req.custom_message else "SECURE_INFO_SHARE: System update payload v2.4.1 [CLEAR]"
        payload = msg.encode()

    # Wrap in tunnel & process
    packet = harness.wrap_payload(payload)
    from core.protocol import HEADER_SIZE
    header = packet[:HEADER_SIZE]
    raw_pl = packet[HEADER_SIZE:]
    res = harness.process_incoming_frame(header, raw_pl)

    return {
        "status": "TEST_COMPLETED",
        "threat_type": req.threat_type,
        "result": {
            "accepted": res.get("accepted"),
            "reason": res.get("reason"),
            "threat": res.get("threat"),
            "anomalies": res.get("anomalies"),
            "interferences": res.get("interferences"),
            "chain_info": res.get("chain_info"),
            "static_telemetry": res.get("static_telemetry")
        }
    }

class ArmorEncryptRequest(BaseModel):
    message: str

class ArmorDecryptRequest(BaseModel):
    armored_text: str

# Shared adapter instance for dashboard armor bridge
from integrations.media_adapter import SecureMediaHarness
_dashboard_armor_adapter = SecureMediaHarness(is_server=False)

@app.post("/api/armor/encrypt")
async def armor_encrypt(req: ArmorEncryptRequest):
    armored = _dashboard_armor_adapter.pack_as_ascii_armor(req.message.encode("utf-8"))
    return {"status": "SUCCESS", "armored_text": armored}

@app.post("/api/armor/decrypt")
async def armor_decrypt(req: ArmorDecryptRequest):
    # Standalone unpacker instance with matching PSK
    unpacker = SecureMediaHarness(is_server=True)
    unpacker.harness.peer_signing_pubkey = _dashboard_armor_adapter.harness.crypto.signing_public_bytes
    try:
        res = unpacker.unpack_ascii_armor(req.armored_text)
        return {
            "status": "SUCCESS",
            "accepted": res.get("accepted"),
            "plaintext": res.get("plaintext", b"").decode("utf-8", errors="replace"),
            "reason": res.get("reason"),
            "chain_info": res.get("chain_info"),
            "static_telemetry": res.get("static_telemetry")
        }
    except Exception as e:
        return {"status": "ERROR", "accepted": False, "reason": f"Corrupt Armor Format: {str(e)}"}


