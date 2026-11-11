"""Operations Console end-to-end test in a real browser.

Drives headless Chrome over the DevTools Protocol (the same approach as
scripts/screenshot.py -- no new dependency) against the RUNNING system: the
console served by `vite preview`, the IAM API, the ANS, nine agent processes
and Keycloak. Nothing is mocked. It proves:

  * anonymous visitors see "sign in", never data
  * a real Keycloak login (Authorization Code + PKCE) works
  * every page renders live data as an AUDITOR with no error state
  * the overview's agent count equals the API's own count
  * a LOAN_OFFICER sees the SERVER's 403 on threat monitoring (no UI-side model)
  * a loan submitted through the UI is carried to APPROVED by the agents
  * the layout has no horizontal scroll at phone width

Screenshots land in docs/console/.

Usage:
    (cd frontend && npm run build && npx vite preview --port 5173 &)
    python3 frontend/e2e/console_e2e.py
"""
from __future__ import annotations

import asyncio
import base64
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

import websockets

BASE = "http://localhost:5173"
KEYCLOAK_TOKEN = "http://localhost:8080/realms/agentic-iam/protocol/openid-connect/token"
SHOTS = pathlib.Path(__file__).resolve().parents[2] / "docs" / "console"
USERS = {"auditor": "auditor-demo", "loan.officer": "loan-officer-demo"}
PAGES = ["overview", "workflow", "approvals", "agents", "identity", "ans", "policies",
         "jit", "a2a", "mcp", "threats", "audit", "system"]
PORT = 9333
PASS, FAIL = 0, 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    PASS += bool(ok)
    FAIL += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else f"  -- {detail}"))


def api_agent_count() -> int:
    data = urllib.parse.urlencode({"client_id": "agentic-iam-console", "grant_type": "password",
                                   "username": "auditor", "password": USERS["auditor"],
                                   "scope": "openid"}).encode()
    token = json.loads(urllib.request.urlopen(KEYCLOAK_TOKEN, data, timeout=15).read())["access_token"]
    request = urllib.request.Request("http://localhost:8000/api/v1/console/overview",
                                     headers={"Authorization": f"Bearer {token}"})
    body = json.loads(urllib.request.urlopen(request, timeout=30).read())
    return sum(body["agents"]["by_status"].values())


class Browser:
    def __init__(self, ws):
        self.ws, self.next_id = ws, 0

    async def send(self, method: str, **params):
        self.next_id += 1
        my_id = self.next_id
        await self.ws.send(json.dumps({"id": my_id, "method": method, "params": params}))
        while True:
            message = json.loads(await self.ws.recv())
            if message.get("id") == my_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    async def js(self, expression: str):
        result = await self.send("Runtime.evaluate", expression=expression,
                                 returnByValue=True, awaitPromise=True)
        return result.get("result", {}).get("value")

    async def goto(self, url: str) -> None:
        await self.send("Page.navigate", url=url)
        await self.settle()

    async def settle(self, timeout: float = 20) -> None:
        deadline = time.time() + timeout
        await asyncio.sleep(0.6)
        while time.time() < deadline:
            ready = await self.js("document.readyState === 'complete' && "
                                  "!document.querySelector('[aria-busy=true]')")
            if ready:
                break
            await asyncio.sleep(0.3)
        await asyncio.sleep(0.8)

    async def has(self, text: str) -> bool:
        return bool(await self.js(f"document.body.innerText.includes({json.dumps(text)})"))

    async def wait_for(self, text: str, timeout: float = 20) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if await self.has(text):
                return True
            await asyncio.sleep(0.5)
        return False

    async def click(self, label: str) -> bool:
        return bool(await self.js(
            "(() => { const b = [...document.querySelectorAll('button')]"
            f".find(x => x.innerText.trim() === {json.dumps(label)}); if (b) b.click(); return !!b; }})()"))

    async def viewport(self, width: int, height: int, scale: float = 1) -> None:
        await self.send("Emulation.setDeviceMetricsOverride", width=width, height=height,
                        deviceScaleFactor=scale, mobile=width < 600)

    async def shot(self, name: str) -> None:
        metrics = await self.send("Page.getLayoutMetrics")
        size = metrics["cssContentSize"]
        data = await self.send("Page.captureScreenshot", format="png", captureBeyondViewport=True,
                               clip={"x": 0, "y": 0, "width": size["width"],
                                     "height": min(size["height"], 6000), "scale": 1})
        (SHOTS / name).write_bytes(base64.b64decode(data["data"]))

    async def login(self, username: str) -> bool:
        await self.send("Network.clearBrowserCookies")
        # A full page load drops the previous user's in-memory token.
        await self.goto("about:blank")
        await self.goto(f"{BASE}/#/overview")
        if not await self.wait_for("Sign in with Keycloak →"):
            return False
        await self.click("Sign in with Keycloak →")
        deadline = time.time() + 20
        while time.time() < deadline and not await self.js("!!document.querySelector('#username')"):
            await asyncio.sleep(0.4)
        await self.js(f"document.querySelector('#username').value = {json.dumps(username)};"
                      f"document.querySelector('#password').value = {json.dumps(USERS[username])};"
                      "document.querySelector('#kc-login').click(); true")
        return await self.wait_for("Sign out", timeout=25)

    async def route(self, name: str) -> None:
        # Hash navigation keeps the in-memory token (a reload signs out, by design).
        await self.js(f"window.location.hash = '#/{name}'; true")
        await self.settle()


async def run() -> None:
    SHOTS.mkdir(parents=True, exist_ok=True)
    profile = tempfile.mkdtemp(prefix="console-e2e-")
    chrome = subprocess.Popen(
        ["google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
         f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}",
         "--window-size=1440,900", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/list", timeout=2).read())
                page = next(t for t in targets if t["type"] == "page")
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
            b = Browser(ws)
            await b.send("Page.enable")
            await b.send("Network.enable")
            await b.viewport(1440, 900)

            print("\n1. Anonymous visitor")
            await b.goto(f"{BASE}/#/overview")
            check("overview asks to sign in", await b.wait_for("Sign in required"))
            check("...and shows no data", not await b.has("Registered agents"))
            await b.shot("00-anonymous.png")

            print("\n2. Auditor: every page, live data, no error state")
            check("Keycloak login (Authorization Code + PKCE)", await b.login("auditor"))
            for index, name in enumerate(PAGES, start=1):
                await b.route(name)
                problems = [m for m in ("Request failed", "Service unreachable",
                                        "Your role may not read this", "Sign in required")
                            if await b.has(m)]
                check(f"{name}: renders without an error state", not problems, ", ".join(problems))
                await b.shot(f"{index:02d}-{name}.png")
            await b.route("overview")
            shown = await b.js("(() => { const l = [...document.querySelectorAll('div')]"
                               ".find(d => d.innerText.trim().toLowerCase() === 'registered agents');"
                               " return l ? l.nextElementSibling.innerText.trim() : null; })()")
            expected = api_agent_count()
            check("overview agent count equals the API's", str(expected) == str(shown),
                  f"console {shown}, API {expected}")

            print("\n3. Loan officer: the server's refusal is what the console shows")
            check("Keycloak login as loan.officer", await b.login("loan.officer"))
            await b.route("threats")
            check("threat monitoring shows the 403 permission state",
                  await b.wait_for("Your role may not read this"))

            print("\n4. A loan submitted in the UI is carried to APPROVED by the agents")
            await b.route("workflow")
            await b.click("Submit to the agents →")
            submitted = await b.wait_for("Submitted wf-")
            check("submission accepted by the server", submitted)
            approved = await b.wait_for("has been approved", timeout=120)
            check("the workflow reached APPROVED in the console", approved)
            for step in ("KYC verification", "Risk assessment", "Credit analysis",
                         "Document verification", "Fraud screening", "Loan decision"):
                check(f"timeline shows {step}", await b.has(step))
            await b.shot("20-workflow-approved.png")

            print("\n5. Phone width, signed in, data-heavy pages")
            await b.viewport(390, 844, 2)
            check("Keycloak login at phone width", await b.login("auditor"))
            for name in ("overview", "threats", "workflow"):
                await b.route(name)
                width = await b.js("document.documentElement.scrollWidth")
                detail = ""
                if width > 392:
                    detail = await b.js(
                        "[...document.querySelectorAll('main *')].filter(e => e.getBoundingClientRect().right > 392)"
                        ".slice(0, 4).map(e => e.tagName + '.' + String(e.className).slice(0, 50)).join(' | ')")
                check(f"{name}: no horizontal page scroll at 390 px", width <= 392, f"scrollWidth={width} {detail}")
                await b.shot(f"3{('overview', 'threats', 'workflow').index(name)}-mobile-{name}.png")
    finally:
        chrome.terminate()
        shutil.rmtree(profile, ignore_errors=True)


def main() -> int:
    asyncio.run(run())
    print(f"\n  {PASS} passed, {FAIL} failed  ·  screenshots: {SHOTS}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
