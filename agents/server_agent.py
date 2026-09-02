import asyncio
import logging
from typing import Dict
from core.tunnel import SecureTunnelHarness
from core.protocol import HEADER_SIZE, Packet
from telemetry.engine import TelemetryEngine
from config.settings import DEFAULT_HOST, DEFAULT_TUNNEL_PORT

logger = logging.getLogger("SecureServerAgent")

class SecureServerAgent:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_TUNNEL_PORT, max_conns_per_ip: int = 10):
        self.host = host
        self.port = port
        self.max_conns_per_ip = max_conns_per_ip
        self.active_ip_counts: Dict[str, int] = {}
        self.harness = SecureTunnelHarness(is_server=True)
        self.server = None
        self.is_running = False

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info('peername')
        client_ip = client_addr[0] if client_addr else "unknown"
        
        # 1. Connection-Level DoS & Flood Limiter
        current_conns = self.active_ip_counts.get(client_ip, 0)
        if current_conns >= self.max_conns_per_ip:
            logger.warning(f"Connection flood blocked for IP {client_ip} (exceeded {self.max_conns_per_ip} concurrent connections)")
            writer.close()
            await writer.wait_closed()
            return

        self.active_ip_counts[client_ip] = current_conns + 1
        logger.info(f"Incoming connection from {client_addr} (active: {self.active_ip_counts[client_ip]})")

        try:
            # 2. Authenticate & Handshake with 5.0s Timeout (Anti-Slowloris / Handshake DoS)
            try:
                handshake_ok = await asyncio.wait_for(
                    self.harness.perform_handshake(reader, writer),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"Handshake timeout from {client_addr}. Connection closed.")
                writer.close()
                await writer.wait_closed()
                return

            if not handshake_ok:
                writer.close()
                await writer.wait_closed()
                return

            # 3. Main tunnel packet reading loop
            while self.is_running:
                header_bytes = await reader.readexactly(HEADER_SIZE)
                hdr = Packet.parse_header(header_bytes)
                payload_len = hdr["payload_len"]
                
                payload_bytes = await reader.readexactly(payload_len)
                
                # Execute full hardened security pipeline
                result = self.harness.process_incoming_frame(header_bytes, payload_bytes)
                
                if result["accepted"]:
                    resp_msg = f"ACK: Payload #{result['seq_num']} verified. Non-Repudiation Sig Valid. Custody Head: {result.get('chain_info', {}).get('chain_head_hex')}".encode()
                    resp_packet = self.harness.wrap_payload(resp_msg)
                    writer.write(resp_packet)
                    await writer.drain()
                else:
                    err_msg = f"NACK: Dropped by Hardened Harness - {result.get('reason')}".encode()
                    err_packet = self.harness.wrap_payload(err_msg)
                    writer.write(err_packet)
                    await writer.drain()
                    
        except asyncio.IncompleteReadError:
            logger.info(f"Client {client_addr} disconnected.")
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            if client_ip in self.active_ip_counts:
                self.active_ip_counts[client_ip] = max(0, self.active_ip_counts[client_ip] - 1)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.is_running = True
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info(f"Secure Tunnel Server listening on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    def stop(self):
        self.is_running = False
        if self.server:
            self.server.close()
