"""Single CDP screenshot of an already-open Edge page (no navigation).

    python scripts/shot2.py <out_png>
"""
from __future__ import annotations
import asyncio, base64, json, sys, urllib.request
import websockets


def ws_url() -> str:
    data = json.loads(urllib.request.urlopen("http://127.0.0.1:9222/json", timeout=5).read())
    pages = [t for t in data if t.get("type") == "page" and t.get("webSocketDebuggerUrl") and "127.0.0.1:8088" in t.get("url", "")]
    if not pages:
        pages = [t for t in data if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    return pages[0]["webSocketDebuggerUrl"]


async def main():
    out = sys.argv[1]
    async with websockets.connect(ws_url(), max_size=None, ping_interval=None, open_timeout=20) as ws:
        mid = 1
        await ws.send(json.dumps({"id": mid, "method": "Page.captureScreenshot", "params": {"format": "png", "fromSurface": True}}))
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("id") == mid:
                with open(out, "wb") as f:
                    f.write(base64.b64decode(msg["result"]["data"]))
                print("saved", out)
                return


if __name__ == "__main__":
    asyncio.run(main())
