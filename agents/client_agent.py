import asyncio
import logging
from typing import Optional
from core.tunnel import SecureTunnelHarness
from core.protocol import HEADER_SIZE, Packet
from config.settings import DEFAULT_HOST, DEFAULT_TUNNEL_PORT

logger = logging.getLogger("SecureClientAgent")

class SecureClientAgent:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_TUNNEL_PORT, expected_peer_fingerprint: str = None):
        self.host = host
        self.port = port
        self.harness = SecureTunnelHarness(is_server=False, expected_peer_fingerprint=expected_peer_fingerprint)
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            handshake_ok = await self.harness.perform_handshake(self.reader, self.writer)
            if handshake_ok:
                self.connected = True
                logger.info(f"Client connected to secure tunnel server. Peer fingerprint: {self.harness.peer_fingerprint}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to tunnel: {e}")
            return False

    async def send_secure_payload(self, raw_data: bytes) -> Optional[dict]:
        """Signs (Ed25519), pads (TRANSEC), encrypts (AES-256-GCM), and transmits payload"""
        if not self.connected or not self.writer:
            raise ConnectionError("Tunnel is not connected.")

        packet_bytes = self.harness.wrap_payload(raw_data)
        self.writer.write(packet_bytes)
        await self.writer.drain()

        # Wait for server response frame
        try:
            header_bytes = await self.reader.readexactly(HEADER_SIZE)
            hdr = Packet.parse_header(header_bytes)
            payload_bytes = await self.reader.readexactly(hdr["payload_len"])
            result = self.harness.process_incoming_frame(header_bytes, payload_bytes)
            return result
        except Exception as e:
            logger.error(f"Error receiving response: {e}")
            return None

    async def close(self):
        self.connected = False
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
