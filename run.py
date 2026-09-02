import asyncio
import threading
import uvicorn
import time
import argparse
import sys

from dashboard.server import app
from agents.server_agent import SecureServerAgent
from agents.client_agent import SecureClientAgent
from config.settings import DEFAULT_HOST, DEFAULT_TUNNEL_PORT, DEFAULT_DASHBOARD_PORT

def run_dashboard(host: str, port: int):
    print(f"🚀 Starting SecureHarness SOC Web Dashboard on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")

async def run_tunnel_server(host: str, port: int):
    print(f"🔒 Starting Secure Tunnel Harness Server on {host}:{port}")
    server_agent = SecureServerAgent(host=host, port=port)
    await server_agent.start()

async def run_client_demo(host: str, port: int):
    await asyncio.sleep(2.0)
    print(f"🌐 Starting Demo Secure Client Node connecting to {host}:{port}")
    client = SecureClientAgent(host=host, port=port)
    if await client.connect():
        print(" Connected to Secure Tunnel! Sending real-time telemetry updates...")
        for i in range(3):
            await asyncio.sleep(1.5)
            payload = f"Heartbeat & Info Update #{i+1} from Client Agent [STATUS: NORMAL]".encode()
            res = await client.send_secure_payload(payload)
            print(f" [Client] Tunnel Transmit Result: {res.get('accepted')} - Seq #{res.get('seq_num')}")
        await client.close()

def main():
    parser = argparse.ArgumentParser(description="SecureHarness Anti-Virus/Bug/Tamper/Interference Tunnel")
    parser.add_argument("--dash-port", type=int, default=DEFAULT_DASHBOARD_PORT, help="Dashboard port")
    parser.add_argument("--tunnel-port", type=int, default=DEFAULT_TUNNEL_PORT, help="Tunnel port")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Host binding")
    parser.add_argument("--mode", type=str, choices=["all", "dashboard", "server", "client"], default="all")

    args = parser.parse_args()

    if args.mode == "dashboard":
        run_dashboard(args.host, args.dash_port)
    elif args.mode == "server":
        asyncio.run(run_tunnel_server(args.host, args.tunnel_port))
    elif args.mode == "client":
        asyncio.run(run_client_demo(args.host, args.tunnel_port))
    else:
        # Run dashboard in background thread, tunnel in main async loop
        t = threading.Thread(target=run_dashboard, args=(args.host, args.dash_port), daemon=True)
        t.start()

        # Run client demo as background task
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(run_client_demo(args.host, args.tunnel_port))
        
        try:
            loop.run_until_complete(run_tunnel_server(args.host, args.tunnel_port))
        except KeyboardInterrupt:
            print("\nShutting down SecureHarness.")

if __name__ == "__main__":
    main()
