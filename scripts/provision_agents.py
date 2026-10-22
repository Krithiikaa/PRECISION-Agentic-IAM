#!/usr/bin/env python3
"""Provision agent identities. An AUTHORIZED, AUDITED administrative act.

Until Phase 5 an agent created its own identity by POSTing to /api/v1/agents,
unauthenticated. That was S-7: anyone who could reach the port could mint
`did:poc:agent:risk-001` under their own key before the real agent started, and
every credential and discovery result would then point at them.

Creating an identity is now an administrative operation, so something
authorized has to do it. That is this script, acting as the
`identity-authority` machine administrator -- the same control-plane principal
and the same signed proof Phase 4.5 introduced. It has no browser and does not
need one; a human IAM_ADMIN can do exactly the same thing from the console.

WHAT IT DOES, and what it deliberately does not:

  * ensures each agent's KEY PAIR exists in the AGENT's own keystore, so key
    custody stays with the agent -- the API never holds an agent private key
  * registers the identity, publishing only the PUBLIC key
  * never overwrites an existing key, and refuses to re-point a DID at a
    different key: that would be the identity takeover this closes

Usage:
    python3 scripts/provision_agents.py                 # all demo agents
    python3 scripts/provision_agents.py risk-001 kyc-001
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cp_sign                                                     # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.agents.definitions import get_definition            # noqa: E402
from app.core.config import get_settings                     # noqa: E402
from app.identity.did import build_agent_did, key_id         # noqa: E402
from app.identity.keys import EncryptedFileKeyStore          # noqa: E402

API = os.environ.get("IAM_API_URL", "http://localhost:8000")

DEMO_AGENTS = [
    "coordinator-001", "kyc-001", "risk-001", "fraud-001",
    "decision-001", "risk-002", "risk-003",
    # Phase 7. The receiver of agent-to-agent payment instructions. It needs
    # a real identity with a real key because RECEIVER BINDING is enforced by
    # requiring the submitter to hold this agent's private key.
    "payments-001",
]


def call(method: str, path: str, body=None, principal: str | None = None):
    if principal is not None:
        data, headers = cp_sign.signed(principal, method, path, body)
    else:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
    request = urllib.request.Request(API + path, data=data, method=method,
                                     headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return exc.code, {"raw": raw.decode()[:300]}
    except urllib.error.URLError as exc:
        print(f"  CANNOT REACH {API}: {exc}")
        print("  Start the API first: scripts/run_local.sh")
        sys.exit(2)


def provision(slug: str) -> bool:
    settings = get_settings()
    definition = get_definition(slug)
    did = build_agent_did(slug, settings.did_method)
    kid = key_id(did)

    # The agent's OWN keystore. Creating the key here rather than letting the
    # agent create it at startup is what makes provisioning possible before the
    # process runs -- and the private key still never leaves this directory.
    keystore_dir = os.environ.get(
        "AGENT_KEYSTORE_DIR", str(REPO / "backend" / ".keystore-agents")
    )
    keystore = EncryptedFileKeyStore(
        os.path.join(keystore_dir, slug), settings.keystore_master_key
    )
    if keystore.exists(kid):
        handle = keystore.get_public_key(kid)
        key_state = "existing"
    else:
        handle = keystore.generate_key(kid)
        key_state = "generated"

    status, existing = call("GET", f"/api/v1/agents/did/{did}")
    if status == 200:
        published = (existing.get("active_key") or {}).get("public_key_multibase")
        if published != handle.public_key_multibase:
            print(f"  [CONFLICT] {slug:<18s} the registry publishes a DIFFERENT key "
                  f"for {did}.")
            print(f"             Refusing to re-point an existing DID at another key.")
            return False
        print(f"  [ok]       {slug:<18s} already provisioned ({key_state} key)")
        return True

    status, created = call("POST", "/api/v1/agents", {
        "slug": slug,
        "name": definition.name,
        "agent_type": definition.agent_type.value,
        "purpose": definition.purpose,
        "capabilities": list(definition.capabilities),
        "endpoint": os.environ.get(f"AGENT_PUBLIC_URL_{slug.replace('-', '_')}"),
        "public_key_multibase": handle.public_key_multibase,
        "metadata": {"provisioned_by": cp_sign.IDENTITY_ADMIN,
                     "runtime": "agent-service"},
    }, principal=cp_sign.IDENTITY_ADMIN)

    if status in (200, 201):
        print(f"  [created]  {slug:<18s} {created.get('did')}  ({key_state} key)")
        return True
    reason = (created.get("detail") or {})
    reason = reason.get("reason") if isinstance(reason, dict) else created
    print(f"  [FAILED]   {slug:<18s} HTTP {status} {reason}")
    return False


def main() -> int:
    slugs = sys.argv[1:] or DEMO_AGENTS
    print(f"Provisioning {len(slugs)} agent identit"
          f"{'y' if len(slugs) == 1 else 'ies'} as {cp_sign.IDENTITY_ADMIN}")
    ok = sum(provision(slug) for slug in slugs)
    print(f"\n  {ok}/{len(slugs)} provisioned")
    return 0 if ok == len(slugs) else 1


if __name__ == "__main__":
    sys.exit(main())
