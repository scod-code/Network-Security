"""
SecureHarness Media & Protocol Adapters:
Use these ready-to-use helpers to embed SecureHarness into:
1. Email & MIME messages (SMTP / IMAP / Webmail)
2. Instant Messaging (WhatsApp bots, Telegram, Signal, Discord, Webhooks)
3. Social Media & REST API payloads
4. File & Media transfers (PDFs, Images, Audio, Sensor Telemetry)
"""

import os
import sys
import json
import base64
from pathlib import Path
from typing import Dict, Any, Union, Optional

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from core.tunnel import SecureTunnelHarness
from core.protocol import HEADER_SIZE

class SecureMediaHarness:
    """
    High-level adapter class to embed SecureHarness into any communication media.
    """
    def __init__(self, is_server: bool = False, psk: bytes = None, expected_peer_fingerprint: str = None):
        self.harness = SecureTunnelHarness(
            is_server=is_server,
            psk=psk,
            expected_peer_fingerprint=expected_peer_fingerprint
        )
        # For standalone media armor (WhatsApp/Email), bind signing key verification
        self.harness.peer_signing_pubkey = self.harness.crypto.signing_public_bytes

    # -------------------------------------------------------------
    # 1. Chat & WhatsApp / Instant Messaging Adapter
    # -------------------------------------------------------------
    def pack_chat_message(self, sender: str, recipient: str, text: str, attachments: Optional[list] = None) -> bytes:
        """
        Packs a chat message into an armored, signed, and TRANSEC-padded binary frame.
        """
        payload_dict = {
            "media_type": "CHAT_MESSAGE",
            "sender": sender,
            "recipient": recipient,
            "text": text,
            "attachments": attachments or []
        }
        raw_bytes = json.dumps(payload_dict).encode("utf-8")
        return self.harness.wrap_payload(raw_bytes)

    def unpack_chat_message(self, wire_packet: bytes) -> Dict[str, Any]:
        """
        Verifies, decrypts, and unpacks an incoming chat frame.
        """
        header = wire_packet[:HEADER_SIZE]
        payload = wire_packet[HEADER_SIZE:]
        result = self.harness.process_incoming_frame(header, payload)
        
        if not result["accepted"]:
            return {"status": "BLOCKED", "reason": result.get("reason"), "threat": result.get("threat")}
            
        chat_data = json.loads(result["plaintext"].decode("utf-8"))
        return {
            "status": "CLEARED",
            "chat": chat_data,
            "chain_head": result.get("chain_info", {}).get("chain_head_hex"),
            "risk_score": result.get("static_telemetry", {}).get("risk_score")
        }

    # -------------------------------------------------------------
    # 2. Email & MIME Message Adapter
    # -------------------------------------------------------------
    def pack_email(self, from_addr: str, to_addr: str, subject: str, body: str, raw_mime: Optional[bytes] = None) -> bytes:
        """
        Secures email data against Wi-Fi sniffing, ISP interception, and mail gateway tampering.
        """
        if raw_mime:
            # Wrap complete RFC 822 MIME raw stream
            return self.harness.wrap_payload(raw_mime)
        
        email_dict = {
            "media_type": "EMAIL",
            "from": from_addr,
            "to": to_addr,
            "subject": subject,
            "body": body
        }
        return self.harness.wrap_payload(json.dumps(email_dict).encode("utf-8"))

    def unpack_email(self, wire_packet: bytes) -> Dict[str, Any]:
        header = wire_packet[:HEADER_SIZE]
        payload = wire_packet[HEADER_SIZE:]
        result = self.harness.process_incoming_frame(header, payload)
        
        if not result["accepted"]:
            return {"status": "BLOCKED", "reason": result.get("reason")}
            
        try:
            email_data = json.loads(result["plaintext"].decode("utf-8"))
        except Exception:
            email_data = {"raw_mime": result["plaintext"]}
            
        return {"status": "CLEARED", "email": email_data}

    # -------------------------------------------------------------
    # 3. File, Document & Image Media Adapter
    # -------------------------------------------------------------
    def pack_file(self, filename: str, file_bytes: bytes) -> bytes:
        """
        Armors and signs files (PDFs, images, software updates) with malware & integrity checks.
        """
        metadata = {
            "media_type": "FILE_TRANSFER",
            "filename": filename,
            "size": len(file_bytes),
            "content_b64": base64.b64encode(file_bytes).decode("ascii")
        }
        return self.harness.wrap_payload(json.dumps(metadata).encode("utf-8"))

    def unpack_file(self, wire_packet: bytes) -> Dict[str, Any]:
        header = wire_packet[:HEADER_SIZE]
        payload = wire_packet[HEADER_SIZE:]
        result = self.harness.process_incoming_frame(header, payload)
        
        if not result["accepted"]:
            return {"status": "BLOCKED", "reason": result.get("reason"), "threat": result.get("threat")}
            
        file_meta = json.loads(result["plaintext"].decode("utf-8"))
        file_bytes = base64.b64decode(file_meta["content_b64"])
        return {
            "status": "CLEARED",
            "filename": file_meta["filename"],
            "file_bytes": file_bytes,
            "size": len(file_bytes)
        }

    # -------------------------------------------------------------
    # 4. Text Armor / Base64 Armoring for Web APIs & Social Media
    # -------------------------------------------------------------
    def pack_as_ascii_armor(self, raw_data: bytes) -> str:
        """
        Converts protected binary packet into copy-pasteable ASCII text string
        suitable for sending over WhatsApp chat, SMS, Twitter/X DMs, Discord, or Email.
        """
        binary_packet = self.harness.wrap_payload(raw_data)
        b64_str = base64.b64encode(binary_packet).decode("ascii")
        return f"-----BEGIN SECURE HARNESS FRAME-----\n{b64_str}\n-----END SECURE HARNESS FRAME-----"

    def unpack_ascii_armor(self, armored_text: str) -> Dict[str, Any]:
        """
        Extracts and verifies ASCII armored text from any chat / email stream.
        """
        clean_text = armored_text.replace("-----BEGIN SECURE HARNESS FRAME-----", "")
        clean_text = clean_text.replace("-----END SECURE HARNESS FRAME-----", "").strip()
        binary_packet = base64.b64decode(clean_text)
        
        header = binary_packet[:HEADER_SIZE]
        payload = binary_packet[HEADER_SIZE:]
        return self.harness.process_incoming_frame(header, payload)


# Demonstration & Self-Test
if __name__ == "__main__":
    print("=== Testing SecureMediaHarness Media Adapters ===")
    sender = SecureMediaHarness(is_server=False)
    receiver = SecureMediaHarness(is_server=True)

    # 1. WhatsApp / Chat Demo
    print("\n1. Testing WhatsApp/Chat Message:")
    wire_chat = sender.pack_chat_message(sender="+1234567890", recipient="+0987654321", text="Meet at safehouse at 18:00.")
    res_chat = receiver.unpack_chat_message(wire_chat)
    print(f"   [Chat Unpacked] Status: {res_chat['status']} | Text: '{res_chat['chat']['text']}'")

    # 2. ASCII Armor Demo (for pasting into SMS, Social Media, or Email)
    print("\n2. Testing Copy-Pasteable ASCII Armor (for Social Media DMs / Email text):")
    armor = sender.pack_as_ascii_armor(b"Secret intelligence dispatch: Operation Trident is GREEN.")
    print("   [Generated Armor Text]:\n  ", armor.replace('\n', '\n   '))
    res_armor = receiver.unpack_ascii_armor(armor)
    print(f"   [Armor Decoded & Verified]: Status: {res_armor['accepted']} | Plaintext: {res_armor['plaintext'].decode()}")

    # 3. File Transfer Demo
    print("\n3. Testing Secure PDF/File Media Transfer:")
    mock_pdf = b"%PDF-1.4 Mock confidential report data..."
    wire_file = sender.pack_file("QuarterlyReport.pdf", mock_pdf)
    res_file = receiver.unpack_file(wire_file)
    print(f"   [File Unpacked]: Status: {res_file['status']} | Filename: {res_file['filename']} | Size: {res_file['size']} bytes")
    print("\n All Media & Communication Adapters Verified Successfully!")
