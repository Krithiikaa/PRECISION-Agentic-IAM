"""Phase 12 console integrations, in a real browser, against the RUNNING system.

Reuses the harness of console_e2e.py (headless Chrome over CDP, real Keycloak
logins, nothing mocked server-side). Covers the five additions:

  A  Audit integrity: verdict, coverage split, legacy labelling, checkpoints
  B  Workflow transition history (persisted rows, request ids, resume/recovery)
  C  Containment detail incl. approvals_cancelled for a REAL pending approval
  D  Reinstatement: separation-of-duties refusal, success with revalidation
  E  Idempotent submission: double click, lost response + retry, new submission

States: loading, error, empty and unauthorized are exercised. Where a state
cannot be produced live (an API outage, a revalidation failure in the
browser), the test INJECTS a server-shaped response in the browser's fetch and
says so in the check label -- it never claims that as live server behaviour.

Usage (stack running, console on :5173):
    cd backend && set -a && . ../.env && set +a
    python ../frontend/e2e/phase12_ui_e2e.py
"""
from __future__ import annotations

import asyncio
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "scripts"))

import websockets  # noqa: E402

import console_e2e as base  # noqa: E402
from console_e2e import BASE, KEYCLOAK_TOKEN, PORT, SHOTS, Browser  # noqa: E402

base.USERS.update({"iam.admin": "iam-admin-demo", "loan.officer.2": "loan-officer-2-demo"})
API = "http://localhost:8000"
MACHINE_ADMIN = "did:poc:administrator:identity-authority"
PASS = FAIL = 0
_tokens: dict[str, str] = {}


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    PASS += bool(ok)
    FAIL += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else f"  -- {detail}"))


def token(user: str) -> str:
    if user not in _tokens:
        data = urllib.parse.urlencode({"client_id": "agentic-iam-console", "grant_type": "password",
                                       "username": user, "password": base.USERS[user],
                                       "scope": "openid"}).encode()
        _tokens[user] = json.loads(urllib.request.urlopen(KEYCLOAK_TOKEN, data, timeout=15)
                                   .read())["access_token"]
    return _tokens[user]


def api(method: str, path: str, *, user: str | None = None, body=None, machine: bool = False):
    if machine:
        import cp_sign
        data, headers = cp_sign.signed(MACHINE_ADMIN, method, path.split("?")[0], body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token(user)}"}
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    for _ in range(6):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read() or "null")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                time.sleep(float(exc.headers.get("Retry-After", "5")))
                continue
            return exc.code, json.loads(exc.read() or "null")
    return 429, None


def workflow_count() -> int:
    return len(api("GET", "/api/v1/loan-workflows", user="auditor")[1] or [])


# --- browser helpers --------------------------------------------------------
INTERCEPT = """
(() => {
  if (!window.__realFetch) window.__realFetch = window.fetch.bind(window);
  window.__keys = window.__keys || [];
  window.__rules = window.__rules || [];
  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    const method = (init && init.method) || 'GET';
    const headers = (init && init.headers) || {};
    if (headers['Idempotency-Key']) window.__keys.push(headers['Idempotency-Key']);
    for (const r of window.__rules) {
      if (r.left > 0 && url.includes(r.path) && method === r.method) {
        r.left -= 1;
        if (r.delay) await new Promise(res => setTimeout(res, r.delay));
        if (r.mode === 'status') return new Response(JSON.stringify(r.body || {detail: 'injected'}),
            {status: r.status, headers: {'content-type': 'application/json'}});
        if (r.mode === 'lose') { await window.__realFetch(input, init);
            throw new TypeError('injected: response lost (network timeout)'); }
      }
    }
    return window.__realFetch(input, init);
  };
  return true;
})()
"""


async def rule(b: Browser, **r) -> None:
    await b.js(INTERCEPT)
    await b.js(f"window.__rules.push({json.dumps({'left': 1, **r})}); true")


async def clear_rules(b: Browser) -> None:
    await b.js("window.__rules = []; window.__keys = []; true")


async def set_field(b: Browser, selector: str, value: str, kind: str = "input") -> bool:
    proto = {"input": "HTMLInputElement", "textarea": "HTMLTextAreaElement",
             "select": "HTMLSelectElement"}[kind]
    event = "change" if kind == "select" else "input"
    return bool(await b.js(f"""(() => {{ const el = {selector}; if (!el) return false;
      Object.getOwnPropertyDescriptor(window.{proto}.prototype, 'value').set.call(el, {json.dumps(value)});
      el.dispatchEvent(new Event('{event}', {{bubbles: true}})); return true; }})()"""))


def by_label(label: str) -> str:
    return (f"[...document.querySelectorAll('label')].find(l => l.innerText.trim().startsWith("
            f"{json.dumps(label)}))?.querySelector('input')")


async def text_of(b: Browser, selector: str) -> str:
    return await b.js(f"(document.querySelector({json.dumps(selector)}) || {{}}).innerText || ''") or ""


async def wait_sel(b: Browser, selector: str, timeout: float = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if await b.js(f"!!document.querySelector({json.dumps(selector)})"):
            return True
        await asyncio.sleep(0.4)
    return False


def card(incident_id: str) -> str:
    return (f"[...document.querySelectorAll('span.mono')].find(s => s.innerText === "
            f"{json.dumps(incident_id)})?.closest('div.rounded-lg.border.p-4')")


async def wait_status(workflow_id: str, statuses: set[str], timeout: float = 120) -> dict:
    deadline, wf = time.time() + timeout, {}
    while time.time() < deadline:
        _, wf = api("GET", f"/api/v1/loan-workflows/{workflow_id}", user="auditor")
        if (wf or {}).get("status") in statuses:
            return wf
        await asyncio.sleep(2)
    return wf or {}


# --- scenarios --------------------------------------------------------------
async def audit_integrity(b: Browser) -> None:
    print("\nA. Audit integrity (auditor)")
    _, verdict = api("GET", "/api/v1/audit/integrity", user="auditor")
    await b.route("audit")
    check("integrity panel renders", await wait_sel(b, "[data-testid=integrity-coverage]"))
    coverage = await text_of(b, "[data-testid=integrity-coverage]")
    legacy = await text_of(b, "[data-testid=legacy-coverage]")
    expected = "VERIFIED" if verdict.get("ok") else "FINDINGS"
    check(f"covered records show the server verdict ({expected})", expected in coverage, coverage[:120])
    check("coverage starts at the server's genesis seq",
          f"#{verdict.get('covers_from_seq')}" in coverage, coverage[:160])
    legacy_n = f"{verdict.get('events_before_coverage', 0):,}"
    check(f"legacy block shows {legacy_n} events", legacy_n in legacy, legacy[:160])
    check("legacy block is labelled OUTSIDE INTEGRITY COVERAGE",
          "OUTSIDE INTEGRITY COVERAGE" in legacy, legacy[:160])
    badges = await b.js("[...document.querySelectorAll('[data-testid=legacy-coverage] span')]"
                        ".map(s => s.innerText.trim())")
    check("legacy block never carries a VERIFIED badge", "VERIFIED" not in (badges or []),
          str(badges))
    check("legacy block states it is not verified", "not verified" in legacy.lower())
    await b.js("[...document.querySelectorAll('[data-testid=integrity-checkpoints] button')][0].click(); true")
    check("checkpoints expand with signed entries",
          await b.wait_for("Trusted checkpoint key", timeout=15))
    shown = await b.js("[...document.querySelectorAll('[data-testid=integrity-checkpoints] tbody tr')].length")
    check("checkpoint rows rendered from the server", (shown or 0) > 0, f"rows={shown}")
    check("no private key material shown",
          not await b.has("PRIVATE KEY") and not await b.has("signature_b64"))
    await b.shot("40-audit-integrity.png")

    # Error state (INJECTED 503) and recovery through Retry.
    await b.route("overview")
    await rule(b, path="/api/v1/audit/integrity", method="GET", mode="status", status=503,
               body={"detail": "injected outage"})
    await b.route("audit")
    check("INJECTED 503: error state with Retry", await b.wait_for("Request failed (HTTP 503)"))
    await b.shot("41-audit-integrity-error.png")
    await clear_rules(b)
    await b.click("Retry")
    check("Retry recovers to the server verdict",
          await wait_sel(b, "[data-testid=integrity-coverage]"))

    # Loading state (INJECTED 4 s delay).
    await b.route("overview")
    await rule(b, path="/api/v1/audit/integrity", method="GET", mode="status", status=200,
               delay=4000, body=verdict)
    await b.js("window.location.hash = '#/audit'; true")
    await asyncio.sleep(1.2)
    busy = await b.js("!!document.querySelector('[aria-busy=true]')")
    check("loading skeleton while verification runs (INJECTED delay)", bool(busy))
    await b.settle(10)
    await clear_rules(b)


async def unauthorized(b: Browser) -> None:
    print("\nUnauthorized states (loan.officer)")
    await b.route("audit")
    check("audit integrity shows the server's 403 to a loan officer",
          await b.wait_for("Your role may not read this"))


async def transitions(b: Browser) -> None:
    print("\nB. Workflow transition history (auditor)")
    _, rows = api("GET", "/api/v1/loan-workflows", user="auditor")
    target, history = None, []
    for w in rows[:40]:
        _, history = api("GET", f"/api/v1/loan-workflows/{w['workflow_id']}/transitions",
                         user="auditor")
        if any("resumed" in (t.get("reason") or "") for t in history):
            target = w
            break
    target = target or rows[0]
    _, history = api("GET", f"/api/v1/loan-workflows/{target['workflow_id']}/transitions",
                     user="auditor")
    await b.route("workflow")
    await b.js(f"[...document.querySelectorAll('tbody tr')].find(r => r.innerText.includes("
               f"{json.dumps(target['workflow_id'])}))?.click(); true")
    check("workflow selected", await b.wait_for(f"Execution timeline · {target['workflow_id']}"))
    await b.js("document.querySelector('[data-testid=workflow-transitions] button').click(); true")
    check("state history expands", await wait_sel(b, "[data-testid=transition-list] li"))
    count = await b.js("document.querySelectorAll('[data-testid=transition-list] li').length")
    check(f"timeline shows every persisted transition ({len(history)})", count == len(history),
          f"ui={count}")
    listing = await text_of(b, "[data-testid=transition-list]")
    check("first transition is the submission", "created" in listing and "SUBMITTED" in listing)
    req = next((t["request_id"] for t in history if t.get("request_id")), "")
    check("request/correlation ids shown", bool(req) and req in listing, req)
    if any("resumed" in (t.get("reason") or "") for t in history):
        check("resume transitions are labelled RESUMED", "RESUMED" in listing)
    await b.shot("42-workflow-transitions.png")

    # Empty state (INJECTED []): select another workflow, whose history is fetched anew.
    other = next(w for w in rows if w["workflow_id"] != target["workflow_id"])
    await rule(b, path="/transitions", method="GET", mode="status", status=200, body=[])
    await b.js(f"[...document.querySelectorAll('tbody tr')].find(r => r.innerText.includes("
               f"{json.dumps(other['workflow_id'])}))?.click(); true")
    check("INJECTED []: empty history state", await b.wait_for("No transitions recorded", timeout=15))
    await clear_rules(b)


async def idempotency(b: Browser) -> None:
    print("\nE. Idempotent submission (loan.officer)")
    await b.route("workflow")
    await b.js(INTERCEPT)
    await clear_rules(b)

    before = workflow_count()
    await set_field(b, by_label("Amount (INR)"), "401000")
    await b.js("(() => { const btn = [...document.querySelectorAll('button')].find(x => "
               "x.innerText.trim() === 'Submit to the agents →'); btn.click(); btn.click(); "
               "return true; })()")
    check("double click: server confirms one submission", await b.wait_for("Submitted wf-"))
    await asyncio.sleep(1.5)
    check("double click created exactly ONE workflow", workflow_count() == before + 1,
          f"{before} -> {workflow_count()}")
    keys = await b.js("window.__keys")
    check("double click sent ONE request", len(keys or []) == 1, str(keys))

    # Lost response: the server stores it, the browser never hears back.
    await clear_rules(b)
    await rule(b, path="/api/v1/loan-workflows", method="POST", mode="lose")
    before = workflow_count()
    await set_field(b, by_label("Amount (INR)"), "402000")
    await b.click("Submit to the agents →")
    check("lost response is shown as NOT CONFIRMED (no false success)",
          await b.wait_for("Not confirmed"))
    check("...and never claims a workflow was created", not await b.has("Submitted wf-"))
    await b.shot("43-idempotency-not-confirmed.png")
    created = workflow_count()
    check("the server did store it once", created == before + 1, f"{before} -> {created}")
    await b.click("Submit to the agents →")
    check("retry is recognised by the server as the same submission",
          await b.wait_for("Already received — nothing new was created"))
    await asyncio.sleep(1)
    check("retry created NOTHING new", workflow_count() == created)
    keys = await b.js("window.__keys")
    check("retry reused the same Idempotency-Key", len(keys or []) == 2 and keys[0] == keys[1],
          str(keys))
    await b.shot("44-idempotency-replay.png")

    # A genuinely new application gets a new key and a new workflow.
    await set_field(b, by_label("Amount (INR)"), "403000")
    await b.click("Submit to the agents →")
    check("a new application is submitted", await b.wait_for("Submitted wf-"))
    keys = await b.js("window.__keys")
    check("...with a NEW Idempotency-Key", len(keys or []) == 3 and keys[2] != keys[0], str(keys))
    check("...creating one more workflow", workflow_count() == created + 1)
    await clear_rules(b)


async def containment(b: Browser) -> None:
    print("\nC/D. Containment and reinstatement (iam.admin)")
    # A REAL pending human approval held by decision-001.
    status, wf = api("POST", "/api/v1/loan-workflows", user="loan.officer", body={
        "customer_id": "customer-007", "applicant_name": "Containment Demo",
        "amount_inr": 2_500_000, "term_months": 60, "declared_monthly_income_inr": 900_000,
        "documents": [{"type": t, "content": f"{t} scan"} for t in
                      ("IDENTITY_PROOF", "INCOME_PROOF", "ADDRESS_PROOF")]})
    paused = await wait_status(wf["workflow_id"], {"AWAITING_APPROVAL", "APPROVED", "DECLINED", "FAILED"})
    approval_id = (paused.get("approval") or {}).get("approval_id")
    check("a real approval is pending for decision-001", paused.get("status") == "AWAITING_APPROVAL"
          and bool(approval_id), str(paused.get("status")))

    check("Keycloak login as iam.admin", await b.login("iam.admin"))
    await b.route("threats")
    await b.wait_for("Kill switch")
    await set_field(b, "document.querySelector('select')", "did:poc:agent:decision-001", "select")
    await set_field(b, "document.querySelector('textarea')",
                    "Console E2E: containment with a pending approval", "textarea")
    await b.click("Contain agent")
    check("containment result is server-confirmed", await wait_sel(b, "[data-testid=containment-result]", 30))
    result = await text_of(b, "[data-testid=containment-result]")
    cancelled = await text_of(b, "[data-testid=approvals-cancelled]")
    check("approvals_cancelled shows the real pending approval id",
          bool(approval_id) and approval_id in cancelled, cancelled)
    check("containment reason shown from the stored incident",
          "pending approval" in result, result[:200])
    _, incidents = api("GET", "/api/v1/security/incidents", user="auditor")
    incident = next(i for i in incidents if i["agent_did"] == "did:poc:agent:decision-001"
                    and i["status"] == "CONTAINED")
    check("incident id in the UI matches the server", incident["incident_id"] in result)
    await b.shot("45-containment-approvals-cancelled.png")

    await b.js(f"{card(incident['incident_id'])}?.querySelector('[aria-expanded]').click(); true")
    check("incident detail lists the cancelled approval",
          await b.wait_for(approval_id or "<none>", timeout=15))
    check("incident detail shows APPROVAL_CANCELLED audit evidence",
          await b.wait_for("APPROVAL_CANCELLED", timeout=15))

    # D1. Same administrator tries to reinstate: separation of duties.
    review = "Reviewed during the console E2E: synthetic containment, no misuse found."
    await set_field(b, f"{card(incident['incident_id'])}?.querySelector('textarea')", review, "textarea")
    await b.js(f"[...{card(incident['incident_id'])}.querySelectorAll('button')].find(x => "
               "x.innerText.trim() === 'Reinstate').click(); true")
    check("same principal: REFUSED by the server", await b.wait_for("REFUSED", timeout=20))
    check("refusal shows the server's reason", await b.has("separation of duties"))
    check("refusal says revalidation did not run", await b.has("before trust revalidation ran"))
    _, inc = api("GET", f"/api/v1/security/incidents/{incident['incident_id']}", user="auditor")
    check("incident is still CONTAINED on the server", inc.get("status") == "CONTAINED")
    await b.shot("46-reinstate-refused.png")

    # D2. Rendering of a failed check (INJECTED 409 shaped like the server's).
    await rule(b, path=f"/incidents/{incident['incident_id']}/reinstate", method="POST",
               mode="status", status=409, body={
                   "error": "CONFLICT",
                   "detail": "Reinstatement refused: trust revalidation failed: active_signing_key: 0 ACTIVE key(s)",
                   "revalidation": [
                       {"check": "identity_not_terminated", "passed": True, "detail": "SUSPENDED"},
                       {"check": "identity_not_expired", "passed": True, "detail": "no expiry"},
                       {"check": "active_signing_key", "passed": False, "detail": "0 ACTIVE key(s)"},
                       {"check": "ancestors_not_contained", "passed": True, "detail": "no delegation parent"}]})
    await b.js(f"[...{card(incident['incident_id'])}.querySelectorAll('button')].find(x => "
               "x.innerText.trim() === 'Reinstate').click(); true")
    await asyncio.sleep(1.5)
    shown = await text_of(b, "[data-testid=reinstate-result]")
    check("INJECTED 409: failed check rendered as FAILED", "FAILED" in shown and
          "active_signing_key" in shown, shown[:200])
    await clear_rules(b)

    # Clean up through the audited path: a DIFFERENT principal reinstates.
    code, _ = api("POST", f"/api/v1/security/incidents/{incident['incident_id']}/reinstate",
                  machine=True, body={"review": review})
    check("cleanup: a different principal reinstated decision-001", code == 200, str(code))

    # D3. Successful reinstatement in the UI, with the server's revalidation.
    code, contained = api("POST", "/api/v1/security/incidents", machine=True, body={
        "agent_did": "did:poc:agent:payments-001",
        "justification": "Console E2E: contained by the machine administrator"})
    check("payments-001 contained by the machine administrator", code == 201, str(code))
    inc_id = (contained or {}).get("incident_id", "")
    await b.route("overview")
    await b.route("threats")
    await b.wait_for(inc_id)
    await set_field(b, f"{card(inc_id)}?.querySelector('textarea')", review, "textarea")
    await b.js(f"[...{card(inc_id)}.querySelectorAll('button')].find(x => "
               "x.innerText.trim() === 'Reinstate').click(); true")
    check("different principal: REINSTATED, server-confirmed",
          await b.wait_for("Server-confirmed · incident now", timeout=25))
    shown = await text_of(b, "[data-testid=reinstate-result]")
    check("all four revalidation checks shown as PASSED",
          shown.count("PASSED") == 4 and "FAILED" not in shown, shown[:300])
    _, inc = api("GET", f"/api/v1/security/incidents/{inc_id}", user="auditor")
    check("server status is REINSTATED", inc.get("status") == "REINSTATED")
    await b.shot("47-reinstate-revalidation.png")


async def mobile(b: Browser) -> None:
    print("\nResponsive: phone width (auditor)")
    await b.viewport(390, 844, 2)
    check("Keycloak login at phone width", await b.login("auditor"))
    for name in ("audit", "workflow", "threats"):
        await b.route(name)
        if name == "workflow":
            await b.js("document.querySelector('tbody tr')?.click(); true")
            await asyncio.sleep(1)
            await b.js("document.querySelector('[data-testid=workflow-transitions] button')?.click(); true")
            await asyncio.sleep(1.5)
        width = await b.js("document.documentElement.scrollWidth")
        check(f"{name}: no horizontal page scroll at 390 px", width <= 392, f"scrollWidth={width}")
        await b.shot(f"5{('audit', 'workflow', 'threats').index(name)}-mobile-{name}-phase12.png")
    await b.viewport(1440, 900)


async def run() -> None:
    SHOTS.mkdir(parents=True, exist_ok=True)
    profile = tempfile.mkdtemp(prefix="console-p12-")
    chrome = subprocess.Popen(
        ["google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
         f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}",
         "--window-size=1440,900", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        page = None
        for _ in range(50):
            try:
                targets = json.loads(urllib.request.urlopen(
                    f"http://127.0.0.1:{PORT}/json/list", timeout=2).read())
                page = next(t for t in targets if t["type"] == "page")
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
            b = Browser(ws)
            await b.send("Page.enable")
            await b.send("Network.enable")
            await b.viewport(1440, 900)
            check("Keycloak login as auditor", await b.login("auditor"))
            await audit_integrity(b)
            await transitions(b)
            check("Keycloak login as loan.officer", await b.login("loan.officer"))
            await unauthorized(b)
            await idempotency(b)
            await containment(b)
            await mobile(b)
    finally:
        chrome.terminate()
        shutil.rmtree(profile, ignore_errors=True)


def main() -> int:
    asyncio.run(run())
    print(f"\n  {PASS} passed, {FAIL} failed  ·  screenshots: {SHOTS}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
