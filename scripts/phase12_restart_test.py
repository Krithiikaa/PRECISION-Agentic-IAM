"""Phase 12 live restart test: workflow state and audit integrity survive.

Against the RUNNING stack (scripts/run_local.sh + seed_credentials.py):

  1. a loan officer submits a large loan with an Idempotency-Key
  2. it runs through six agents and PAUSES for a human approval
  3. the IAM API PROCESS IS KILLED AND RESTARTED (agents keep running)
  4. after the restart:
       - the workflow is still AWAITING_APPROVAL, with the same approval
       - its transition history is intact
       - the same Idempotency-Key returns the same workflow (no duplicate)
       - maker-checker still refuses the submitting officer
       - a second officer approves and the workflow RESUMES to APPROVED
       - the audit chain verifies server-side, across the restart

Usage: python3 scripts/phase12_restart_test.py
"""
from __future__ import annotations

import json
import os
import pathlib
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.core.config import get_settings  # noqa: E402

API = "http://localhost:8000"
HUMANS = {"loan.officer": "loan-officer-demo", "loan.officer.2": "loan-officer-2-demo",
          "auditor": "auditor-demo", "iam.admin": "iam-admin-demo"}
DOCS = [{"type": t, "content": f"{t} scan"} for t in
        ("IDENTITY_PROOF", "INCOME_PROOF", "ADDRESS_PROOF")]
PASS = FAIL = 0
_tokens: dict[str, str] = {}


def token(user):
    if user not in _tokens:
        data = urllib.parse.urlencode({
            "client_id": get_settings().oidc_client_id, "grant_type": "password",
            "username": user, "password": HUMANS[user], "scope": "openid"}).encode()
        with urllib.request.urlopen(get_settings().oidc_token_url, data, timeout=15) as r:
            _tokens[user] = json.loads(r.read())["access_token"]
    return _tokens[user]


def call(method, path, body=None, *, human, headers=None):
    hdrs = {"Content-Type": "application/json", "Authorization": f"Bearer {token(human)}",
            **(headers or {})}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers=hdrs)
    for _ in range(6):                               # honour rate limiting, never bypass it
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read() or "{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                time.sleep(float(exc.headers.get("Retry-After", "5")))
                continue
            raw = exc.read()
            try:
                return exc.code, json.loads(raw or "{}")
            except json.JSONDecodeError:
                return exc.code, {"raw": raw.decode()[:300]}
    return 429, {}


def check(label, actual, expected):
    global PASS, FAIL
    ok = actual == expected
    PASS += ok
    FAIL += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}"
          + ("" if ok else f"\n         expected {expected!r}, got {actual!r}"))
    return ok


def wait_for(workflow_id, statuses, timeout=120):
    deadline, wf = time.time() + timeout, {}
    while time.time() < deadline:
        _, wf = call("GET", f"/api/v1/loan-workflows/{workflow_id}", human="auditor")
        if wf.get("status") in statuses:
            return wf
        time.sleep(2)
    return wf


def listener_pid():
    out = subprocess.run(["ss", "-lptnH", "sport = :8000"], capture_output=True, text=True).stdout
    import re
    m = re.search(r"pid=(\d+)", out)
    return int(m.group(1)) if m else None


def restart_api():
    """Kill whatever ACTUALLY listens on :8000 and prove a new process replaced it.

    (A first version trusted .run/iam-api.pid and any healthy answer; a stale
    server could then "survive" the restart and the test would pass without
    one. The old and new PIDs are now compared.)
    """
    old = listener_pid()
    if old is None:
        return False
    subprocess.run(["kill", str(old)], check=False)
    for _ in range(60):
        if listener_pid() is None:
            break
        time.sleep(0.5)
    else:
        return False
    pid_file = ROOT / ".run" / "iam-api.pid"
    script = (f"cd '{ROOT}' && set -a && . ./.env && set +a && cd backend && "
              f"nohup .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 "
              f"> '{ROOT}/.run/iam-api.log' 2>&1 & echo $! > '{pid_file}'")
    # Detached: the server must not inherit this script's stdout, or whoever
    # reads this script's output never sees EOF.
    subprocess.run(["env", "-i", f"HOME={os.environ['HOME']}", "PATH=/usr/bin:/bin",
                    "bash", "-c", script], check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   start_new_session=True)
    for _ in range(90):
        try:
            urllib.request.urlopen(API + "/health", timeout=2)
            new = listener_pid()
            print(f"        listener pid {old} -> {new}")
            return new is not None and new != old
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


print("\n1. Submit a large loan (idempotent) and let it pause for a human")
key = f"restart-{secrets.token_hex(4)}"
body = {"customer_id": "customer-007", "applicant_name": "Restart Applicant",
        "amount_inr": 2_500_000, "term_months": 60, "declared_monthly_income_inr": 900_000,
        "documents": DOCS}
status, created = call("POST", "/api/v1/loan-workflows", body, human="loan.officer",
                       headers={"Idempotency-Key": key})
check("submitted", status, 201)
wid = created.get("workflow_id")
paused = wait_for(wid, {"AWAITING_APPROVAL", "APPROVED", "DECLINED", "FAILED"})
check("workflow AWAITING_APPROVAL before the restart", paused.get("status"), "AWAITING_APPROVAL")
approval_id = (paused.get("approval") or {}).get("approval_id")
check("an approval is pending", bool(approval_id), True)
_, before = call("GET", f"/api/v1/loan-workflows/{wid}/transitions", human="auditor")
status, integrity_before = call("GET", "/api/v1/audit/integrity", human="auditor")
check("audit chain VERIFIED before the restart", integrity_before.get("status"), "VERIFIED")

print("\n2. Restart the IAM API process")
check("IAM API restarted (a NEW process holds :8000)", restart_api(), True)
time.sleep(3)

print("\n3. After the restart")
_, after = call("GET", f"/api/v1/loan-workflows/{wid}", human="auditor")
check("workflow still AWAITING_APPROVAL", after.get("status"), "AWAITING_APPROVAL")
check("same approval bound", (after.get("approval") or {}).get("approval_id"), approval_id)
check("application still AWAITING_DECISION",
      (after.get("application") or {}).get("status"), "AWAITING_DECISION")
_, history = call("GET", f"/api/v1/loan-workflows/{wid}/transitions", human="auditor")
check("transition history intact (prefix unchanged)", history[:len(before)], before)
status, replay = call("POST", "/api/v1/loan-workflows", body, human="loan.officer",
                      headers={"Idempotency-Key": key})
check("same Idempotency-Key -> same workflow", replay.get("workflow_id"), wid)
check("...reported as a replay", replay.get("idempotent_replay"), True)
status, _ = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                 {"decision": "APPROVED"}, human="loan.officer")
check("submitting officer still refused (maker-checker)", status, 403)
status, _ = call("POST", f"/api/v1/hitl/approvals/{approval_id}/decide",
                 {"decision": "APPROVED"}, human="loan.officer.2")
check("second officer approves", status, 200)
done = wait_for(wid, {"APPROVED", "DECLINED", "FAILED"}, timeout=120)
check("workflow RESUMES to APPROVED", done.get("status"), "APPROVED")
check("application APPROVED", (done.get("application") or {}).get("status"), "APPROVED")

print("\n4. Audit integrity across the restart")
time.sleep(4)                                       # one sealing interval
status, integrity = call("GET", "/api/v1/audit/integrity", human="auditor")
check("audit chain VERIFIED after the restart", integrity.get("status"), "VERIFIED")
check("chain grew across the restart",
      (integrity.get("head_index") or 0) > (integrity_before.get("head_index") or 0), True)
check("signed checkpoints verified", (integrity.get("checkpoints_verified") or 0) >
      (integrity_before.get("checkpoints_verified") or 0), True)
print(f"        head {integrity.get('head_index')}, {integrity.get('checkpoints_verified')} "
      f"checkpoints, {integrity.get('events_before_coverage')} legacy events outside coverage")

print(f"\n  {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
