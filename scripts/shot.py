"""Headless screenshot of the AEGIS dashboard via Edge DevTools Protocol.

Connects to an already-running Edge (--remote-debugging-port=9222), captures the
login page, then injects the session token into sessionStorage and captures the
authenticated dashboard. Usage:

    python scripts/shot.py <token> <out_dir>
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import urllib.request

import websockets


def ws_url() -> str:
    data = json.loads(urllib.request.urlopen("http://127.0.0.1:9222/json", timeout=5).read())
    pages = [t for t in data if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
    if not pages:
        raise RuntimeError("no Edge page target found")
    return pages[0]["webSocketDebuggerUrl"]


class CDP:
    def __init__(self, ws):
        self.ws = ws
        self._id = 0

    async def send(self, method, params=None):
        self._id += 1
        mid = self._id
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == mid:
                return msg.get("result", {})


async def shot(cdp: CDP, path: str):
    res = await cdp.send("Page.captureScreenshot", {"format": "png", "fromSurface": True})
    with open(path, "wb") as f:
        f.write(base64.b64decode(res["data"]))
    print("saved", path)


async def main():
    token = sys.argv[1]
    out = sys.argv[2].rstrip("\\/")
    app = "http://127.0.0.1:8088/"

    async with websockets.connect(ws_url(), max_size=None, ping_interval=None, open_timeout=20) as ws:
        cdp = CDP(ws)
        await cdp.send("Page.enable")
        await cdp.send("Runtime.enable")
        await cdp.send("Emulation.setDeviceMetricsOverride",
                       {"width": 1680, "height": 1020, "deviceScaleFactor": 1, "mobile": False})

        # 1) login page (no token)
        await cdp.send("Runtime.evaluate", {"expression": "sessionStorage.clear()"})
        await cdp.send("Page.navigate", {"url": app})
        await asyncio.sleep(4)
        await shot(cdp, f"{out}/login.png")

        # 2) authenticated dashboard — set token then reload in-page
        await cdp.send("Runtime.evaluate",
                       {"expression": f"sessionStorage.setItem('aegis_token', {json.dumps(token)}); location.reload();"})
        await asyncio.sleep(9)  # WS connect + React Flow fitView + data render
        await shot(cdp, f"{out}/dashboard.png")


if __name__ == "__main__":
    asyncio.run(main())
