#!/usr/bin/env python3
"""Screenshot a page via the Chrome DevTools Protocol.

`chromium --screenshot` captures at the load event, which is too early for a
single-page app that fetches its data afterwards -- and its
`--virtual-time-budget` never settles on a page holding an open Server-Sent
Events connection, which this UI always does. So: drive the browser directly
and capture after an explicit settle.

    python3 scripts/screenshot.py http://localhost:5173/ out.png --wait 4 --click "Agents"
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import subprocess
import time
import urllib.request

import websockets

CHROME_FLAGS = [
    "--headless", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
    "--remote-debugging-port={port}", "--window-size={width},{height}",
    "--force-device-scale-factor=1", "about:blank",
]


async def capture(url: str, out: str, wait: float, width: int, height: int,
                  click_text: str | None, steps: list[str], port: int) -> None:
    targets = json.loads(
        urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=10).read()
    )
    page = next(t for t in targets if t["type"] == "page")

    async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
        message_id = 0

        async def send(method: str, params: dict | None = None) -> dict:
            nonlocal message_id
            message_id += 1
            await ws.send(json.dumps({"id": message_id, "method": method,
                                      "params": params or {}}))
            while True:
                response = json.loads(await ws.recv())
                if response.get("id") == message_id:
                    if "error" in response:
                        raise RuntimeError(f"{method}: {response['error']}")
                    return response.get("result", {})

        await send("Page.enable")
        await send("Runtime.enable")
        await send("Emulation.setDeviceMetricsOverride",
                   {"width": width, "height": height, "deviceScaleFactor": 1,
                    "mobile": False})
        await send("Page.navigate", {"url": url})
        await asyncio.sleep(wait)

        for step in steps:
            await send("Runtime.evaluate", {"expression": step, "awaitPromise": True})
            await asyncio.sleep(wait)

        if click_text:
            # Click the first element whose trimmed text matches exactly.
            await send("Runtime.evaluate", {"expression": f"""
                (() => {{
                  const target = [...document.querySelectorAll('button')]
                    .find(el => el.textContent.trim() === {json.dumps(click_text)});
                  if (target) target.click();
                  return !!target;
                }})()
            """})
            await asyncio.sleep(wait)

        result = await send("Page.captureScreenshot",
                            {"format": "png", "captureBeyondViewport": True})
        with open(out, "wb") as handle:
            handle.write(base64.b64decode(result["data"]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("out")
    parser.add_argument("--wait", type=float, default=4.0)
    parser.add_argument("--width", type=int, default=1600)
    parser.add_argument("--height", type=int, default=1000)
    parser.add_argument("--click", default=None, help="Exact button text to click first")
    parser.add_argument("--step", action="append", default=[],
                        help="JS to evaluate, then wait. Repeatable, run in order.")
    parser.add_argument("--port", type=int, default=9222)
    parser.add_argument("--browser", default="chromium")
    args = parser.parse_args()

    flags = [flag.format(port=args.port, width=args.width, height=args.height)
             for flag in CHROME_FLAGS]
    browser = subprocess.Popen([args.browser, *flags],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{args.port}/json/version", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        asyncio.run(capture(args.url, args.out, args.wait, args.width, args.height,
                            args.click, args.step, args.port))
        print(f"wrote {args.out}")
    finally:
        browser.terminate()
        browser.wait(timeout=10)


if __name__ == "__main__":
    main()
