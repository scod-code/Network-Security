import asyncio
import time
from core.tunnel import SecureTunnelHarness
from security.antivirus import AntivirusEngine
from security.anti_bug import AntiBugEngine
from security.anti_interference import AntiInterferenceEngine
from security.anti_tamper import AntiTamperEngine
from core.sandbox import ProcessSandbox
from telemetry.engine import TelemetryEngine
from core.protocol import HEADER_SIZE

def test_full_pipeline():
    print("=== [TEST 1] Testing Clean Payload Transmission (with Ed25519 + TRANSEC) ===")
    harness = SecureTunnelHarness(is_server=True)
    msg = b"Confidential financial statement 2026: Operating Profit +24%"
    packet = harness.wrap_payload(msg)
    
    header = packet[:HEADER_SIZE]
    payload = packet[HEADER_SIZE:]
    res = harness.process_incoming_frame(header, payload)
    assert res["accepted"] is True, f"Failed clean transmission: {res}"
    assert res["plaintext"] == msg
    print(" Clean transmission passed! Signed with Ed25519, Padded (TRANSEC), Decrypted with AES-GCM & Chain-of-Custody verified.\n")

    print("=== [TEST 2] Testing Antivirus Signature Detection (EICAR) ===")
    eicar_msg = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    packet = harness.wrap_payload(eicar_msg)
    header = packet[:HEADER_SIZE]
    payload = packet[HEADER_SIZE:]
    res = harness.process_incoming_frame(header, payload)
    assert res["accepted"] is False
    assert res["reason"] == "Antivirus Signature/Heuristic Match"
    print(f" Antivirus quarantined threat: {res['threat']['detections'][0]['name']}\n")

    print("=== [TEST 3] Testing Anti-Interference & Replay Attack Defense ===")
    clean_msg = b"Transfer Authorization Token"
    packet = harness.wrap_payload(clean_msg)
    header = packet[:HEADER_SIZE]
    payload = packet[HEADER_SIZE:]
    
    # First send -> Accept
    res1 = harness.process_incoming_frame(header, payload)
    assert res1["accepted"] is True
    
    # Second send of identical packet -> Block duplicate
    res2 = harness.process_incoming_frame(header, payload)
    assert res2["accepted"] is False
    assert "Interference" in res2["reason"] or "Replay" in str(res2)
    print(" Anti-Replay engine blocked duplicate frame.\n")

    print("=== [TEST 4] Testing Anti-Tamper In-Flight Modification ===")
    packet = harness.wrap_payload(b"Critical Configuration Command: ENABLE_FEATURE")
    # Mutate 2 bytes in payload
    tampered_payload = packet[HEADER_SIZE:-2] + b"\xde\xad"
    res = harness.process_incoming_frame(packet[:HEADER_SIZE], tampered_payload)
    assert res["accepted"] is False
    print(f" Anti-Tamper engine blocked modified packet: {res['reason']}\n")

    print("=== [TEST 5] Testing Process Sandbox Execution ===")
    sandbox = ProcessSandbox()
    sb_res = sandbox.run_isolated_command(["python", "-c", "print('Sandbox Exec OK')"])
    assert sb_res["success"] is True
    assert "Sandbox Exec OK" in sb_res["stdout"]
    print(" Process Sandbox execution verified.\n")

    print("=== [TEST 6] Testing Static Telemetry Scoring ===")
    telemetry = TelemetryEngine.get_instance()
    analysis = telemetry.analyze_static(b"powershell.exe -enc aW52b2tl... http://malicious-c2.net 192.168.1.100 VirtualAllocEx")
    assert analysis["risk_score"] > 30
    print(f" Static Telemetry Risk Score: {analysis['risk_score']} ({analysis['risk_level']}) with detected APIs & IPs.\n")

    print("=== [TEST 7] Testing High-Risk Telemetry Policy Blocking & Quarantine ===")
    risky_msg = b"Connecting to http://malware-c2.evil.net with VirtualAllocEx and CreateRemoteThread targeting 192.168.1.50 exec subprocess"
    pkt = harness.wrap_payload(risky_msg)
    res_risky = harness.process_incoming_frame(pkt[:HEADER_SIZE], pkt[HEADER_SIZE:])
    assert res_risky["accepted"] is False
    assert "Risk Policy Blocked" in res_risky["reason"]
    print(f" High-risk payload blocked by harness telemetry policy: {res_risky['reason']}\n")

    print("========================================")
    print(" ALL 7 TEST SUITES PASSED FLAWLESSLY! ")
    print("========================================")

if __name__ == "__main__":
    test_full_pipeline()
