"""Minimal test master; production enrollment, durable revisions and billing are separate."""
import argparse
import asyncio
import json
import ssl
import os
import hmac
from pathlib import Path
import websockets

parser = argparse.ArgumentParser()
parser.add_argument("--cert", required=True)
parser.add_argument("--key", required=True)
parser.add_argument("--config", default="examples/remote-vless.json")
parser.add_argument("--port", type=int, default=8443)
args = parser.parse_args()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args.cert, args.key)
snapshot = json.loads(Path(args.config).read_text())
seen_batches = set()
expected_token = os.environ.get("XNODE_MOCK_TOKEN")
if not expected_token:
    parser.error("set XNODE_MOCK_TOKEN to the fixture agent credential")

async def handler(socket):
    if not hmac.compare_digest(socket.request.headers.get("Authorization", ""), "Bearer " + expected_token):
        await socket.close(1008, "Authentication required")
        return
    async for raw in socket:
        message = json.loads(raw)
        if message["type"] == "state.request":
            await socket.send(json.dumps({"v": 1, "type": "state.sync", "id": "fixture-snapshot", "revision": 1, "data": snapshot}))
        elif message["type"] == "traffic.report":
            batch = message["data"]
            seen_batches.add(batch["id"])
            if len(seen_batches) > 4096:
                seen_batches.clear()  # This fixture does not implement production billing.
            await socket.send(json.dumps({"v": 1, "type": "traffic.ack", "data": {"id": batch["id"]}}))
        elif message["type"] == "firewall.pending":
            transaction = message["data"]["id"]
            await socket.send(json.dumps({"v": 1, "type": "command", "id": "confirm-" + transaction, "data": {"name": "firewall.confirm", "args": {"transaction_id": transaction}}}))

async def main():
    async with websockets.serve(handler, "127.0.0.1", args.port, ssl=context, subprotocols=["x-node.v1"]):
        await asyncio.Future()

asyncio.run(main())
