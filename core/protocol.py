import struct
import time
import json
from typing import Optional, Dict, Any

"""
Secure Tunnel Binary Wire Protocol:
[Magic: 4 bytes (0x53454348 = 'SECH')]
[Version: 2 bytes] (Enforces MIN_PROTOCOL_VERSION)
[Message Type: 2 bytes] (1=Handshake, 2=Data, 3=Control/Heartbeat, 4=Telemetry, 5=Alert, 6=Close/Termination)
[Sequence Number: 8 bytes (uint64)]
[Timestamp: 8 bytes (double)]
[Payload Length: 4 bytes (uint32)]
[HMAC/Auth Tag: 32 bytes (SHA256)]
[Payload: N bytes (Encrypted AES-GCM or Handshake params)]
Header size = 4 + 2 + 2 + 8 + 8 + 4 + 32 = 60 bytes
"""

HEADER_MAGIC = b"SECH"
PROTOCOL_VERSION = 1
MIN_PROTOCOL_VERSION = 1
HEADER_FORMAT = "!4sHHQdI32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

TYPE_HANDSHAKE = 1
TYPE_DATA = 2
TYPE_HEARTBEAT = 3
TYPE_TELEMETRY = 4
TYPE_ALERT = 5
TYPE_CLOSE = 6

class Packet:
    def __init__(
        self,
        msg_type: int,
        seq_num: int,
        payload: bytes,
        timestamp: Optional[float] = None,
        auth_tag: bytes = b"\x00" * 32,
        version: int = PROTOCOL_VERSION
    ):
        self.magic = HEADER_MAGIC
        self.version = version
        self.msg_type = msg_type
        self.seq_num = seq_num
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.payload = payload
        self.payload_len = len(payload)
        self.auth_tag = auth_tag

    def pack_header(self, auth_tag: bytes = None) -> bytes:
        tag = auth_tag or self.auth_tag
        return struct.pack(
            HEADER_FORMAT,
            self.magic,
            self.version,
            self.msg_type,
            self.seq_num,
            self.timestamp,
            self.payload_len,
            tag
        )

    def serialize(self, auth_tag: bytes = None) -> bytes:
        header = self.pack_header(auth_tag)
        return header + self.payload

    @classmethod
    def parse_header(cls, header_bytes: bytes) -> Dict[str, Any]:
        if len(header_bytes) != HEADER_SIZE:
            raise ValueError(f"Invalid header length: {len(header_bytes)}, expected {HEADER_SIZE}")
        magic, version, msg_type, seq_num, timestamp, payload_len, auth_tag = struct.unpack(HEADER_FORMAT, header_bytes)
        if magic != HEADER_MAGIC:
            raise ValueError(f"Invalid Protocol Magic: {magic}")
        if version < MIN_PROTOCOL_VERSION:
            raise ValueError(f"Protocol Downgrade Attack Detected: version {version} < minimum {MIN_PROTOCOL_VERSION}")
        return {
            "magic": magic,
            "version": version,
            "msg_type": msg_type,
            "seq_num": seq_num,
            "timestamp": timestamp,
            "payload_len": payload_len,
            "auth_tag": auth_tag
        }
