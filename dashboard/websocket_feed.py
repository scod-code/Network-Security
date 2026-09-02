import asyncio
import json
from typing import List, Set
from fastapi import WebSocket, WebSocketDisconnect
from telemetry.engine import TelemetryEngine

class WebSocketManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast(self, message: dict):
        dead_conns = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_conns.append(connection)
        for dead in dead_conns:
            self.active_connections.discard(dead)

ws_manager = WebSocketManager()

async def telemetry_broadcast_loop():
    """Periodically streams telemetry and health data to dashboard clients"""
    telemetry = TelemetryEngine.get_instance()
    while True:
        try:
            snapshot = telemetry.get_full_telemetry_snapshot()
            await ws_manager.broadcast({
                "type": "TELEMETRY_UPDATE",
                "data": snapshot
            })
        except Exception as e:
            pass
        await asyncio.sleep(1.0)
