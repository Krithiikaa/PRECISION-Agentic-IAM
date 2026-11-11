#!/usr/bin/env python3
"""Register each agent as an OAuth client for the MCP endpoint (Phase 8).

WHAT THIS DOES, AND WHY IT CREATES NO NEW SECRET.

Keycloak's `agentic-iam` realm supports `private_key_jwt` client
authentication with `EdDSA` client assertions. So an agent authenticates to
the token endpoint by signing a short-lived assertion with the SAME Ed25519
key it has held since Phase 1. This script publishes that key's PUBLIC half
to Keycloak as the client's JWKS and nothing else:

    * no client secret is generated, stored or printed
    * no private key is read, exported or transmitted
    * the KeyStore is never asked for private material at all

The agent's Keycloak `clientId` is its DID verbatim, which is what makes the
access token's `azp` claim carry the DID and lets the resource server map a
token to an identity without a side table.

WHAT THIS DOES NOT DO: grant anything. A client here can obtain a token.
Whether the agent behind it may invoke anything is decided per call by the
PDP against its verifiable credentials, and a revoked or suspended agent is
refused there even while this client still exists and its token is still
unexpired. See `--revoke` for closing the faster door as well.

    python scripts/provision_mcp_clients.py              # provision all
    python scripts/provision_mcp_clients.py --agent risk-001
    python scripts/provision_mcp_clients.py --revoke risk-001
    python scripts/provision_mcp_clients.py --list
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "backend"))

from app.core.config import get_settings  # noqa: E402
from app.db.database import get_sessionmaker  # noqa: E402
from app.identity.keys import EncryptedFileKeyStore, build_keystore  # noqa: E402

MCP_SCOPE = "mcp-invoke"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Keycloak:
    """The admin API, over stdlib urllib. No new dependency is introduced."""

    def __init__(self, base_url: str, realm: str, user: str, password: str) -> None:
        self.base = base_url.rstrip("/")
        self.realm = realm
        self._token = self._admin_token(user, password)

    def _admin_token(self, user: str, password: str) -> str:
        body = urllib.parse.urlencode({
            "client_id": "admin-cli", "grant_type": "password",
            "username": user, "password": password,
        }).encode()
        request = urllib.request.Request(
            f"{self.base}/realms/master/protocol/openid-connect/token",
            body, {"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.loads(response.read())["access_token"]

    def call(self, method: str, path: str, body=None):
        request = urllib.request.Request(
            f"{self.base}/admin/realms/{self.realm}{path}",
            json.dumps(body).encode() if body is not None else None,
            {
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()[:300]

    def client_by_id(self, client_id: str):
        quoted = urllib.parse.quote(client_id, safe="")
        _, found = self.call("GET", f"/clients?clientId={quoted}")
        return (found or [None])[0] if isinstance(found, list) else None

    def ensure_mcp_scope(self) -> str | None:
        """Create the `mcp-invoke` client scope if the realm lacks it.

        WHY THIS IS NOT LEFT TO THE REALM IMPORT FILE. `realm-agentic-iam.json`
        is read only when Keycloak first creates the realm, so a realm that
        already exists -- which is every running deployment -- never sees a
        later edit to that file. Relying on the import would mean the
        audience mapper silently did not exist, tokens came back without the
        `agentic-iam-mcp` audience, and every MCP call failed with an
        audience mismatch that looked like a bug in the resource server.
        That is a long way to debug, so the scope is ensured here instead.
        """
        _, scopes = self.call("GET", "/client-scopes")
        if isinstance(scopes, list):
            for scope in scopes:
                if scope.get("name") == MCP_SCOPE:
                    return scope["id"]

        status, _ = self.call("POST", "/client-scopes", {
            "name": MCP_SCOPE,
            "description": (
                "Phase 8. Adds the agentic-iam-mcp audience to an access "
                "token. Assigned to AGENT clients only."
            ),
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false",
            },
            "protocolMappers": [{
                "name": "agentic-iam-mcp-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.custom.audience": "agentic-iam-mcp",
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                    "introspection.token.claim": "true",
                },
            }],
        })
        if status not in (201, 409):
            print(f"  ! could not create the {MCP_SCOPE} scope: HTTP {status}")
            return None
        _, scopes = self.call("GET", "/client-scopes")
        for scope in scopes or []:
            if scope.get("name") == MCP_SCOPE:
                return scope["id"]
        return None

    def attach_scope(self, client_pk: str, scope_id: str) -> None:
        """Make the scope a DEFAULT one for this client.

        Default rather than optional: a client_credentials request sends no
        `scope` parameter, so an optional scope would never be applied and
        the audience would never appear.
        """
        self.call("PUT", f"/clients/{client_pk}/default-client-scopes/{scope_id}")


def client_definition(did: str, jwk: dict) -> dict:
    """A confidential client that can ONLY authenticate with a signed JWT.

    Every interactive flow is off. This client cannot be used in a browser,
    cannot exchange a password, and has no secret to leak -- the only way to
    get a token is to sign an assertion with the agent's Phase 1 private key,
    which never leaves the KeyStore.
    """
    return {
        "clientId": did,
        "name": f"MCP client for {did}",
        "description": (
            "Phase 8. Authenticates with private_key_jwt (EdDSA) using the "
            "agent's Phase 1 Ed25519 key. No client secret exists."
        ),
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "clientAuthenticatorType": "client-jwt",
        "defaultClientScopes": ["mcp-invoke"],
        "attributes": {
            "use.jwks.string": "true",
            "jwks.string": json.dumps({"keys": [jwk]}),
            "token.endpoint.auth.signing.alg": "EdDSA",
            # Keycloak refuses a replayed client assertion on its own; this
            # bounds how long one is accepted at all.
            "client.assertion.lifespan": "300",
        },
    }


def _public_key_for(agent_slug: str, did: str, settings):
    """Find an agent's PUBLIC key, wherever its custodian keeps it.

    AGENTS DO NOT SHARE A KEYSTORE, and that is the point of the deployment
    rather than an accident of it: `provision_agents.py` gives each agent its
    own `.keystore-agents/<slug>/` directory so that an agent process holds
    exactly one private key -- its own -- and compromising one agent does not
    hand over the others.

    This function therefore looks in the agent's own keystore FIRST and only
    then in the service keystore. An earlier version of this script read a
    single keystore and silently skipped every agent deployed by
    `run_local.sh`, which meant MCP could be provisioned for nobody real.

    Returns a KeyHandle or None. Only ever asks for the PUBLIC half: there is
    deliberately no call here that could return private material.
    """
    kid = f"{did}#key-1"

    root = os.environ.get(
        "AGENT_KEYSTORE_DIR", str(REPO / "backend" / ".keystore-agents")
    )
    own = os.path.join(root, agent_slug)
    if os.path.isdir(own):
        store = EncryptedFileKeyStore(own, settings.keystore_master_key)
        if store.exists(kid):
            return store.get_public_key(kid)

    service = build_keystore(settings)
    if service.exists(kid):
        return service.get_public_key(kid)
    return None


async def agent_keys() -> list[tuple[str, dict]]:
    """Every ACTIVE agent's DID with its current public key as a JWK."""
    from sqlalchemy import select

    from app.db.models.agent import Agent, AgentStatus

    settings = get_settings()
    maker = get_sessionmaker(settings)
    out: list[tuple[str, dict]] = []

    async with maker() as session:
        agents = (await session.execute(
            select(Agent).where(Agent.status == AgentStatus.ACTIVE)
        )).scalars().all()

        for agent in agents:
            handle = _public_key_for(agent.slug, agent.did, settings)
            if handle is None:
                print(f"  ! {agent.slug}: no key found in the agent keystore "
                      f"or the service keystore, skipped")
                continue
            raw = base64.b64decode(handle.public_key_b64)
            out.append((agent.did, {
                "kty": "OKP", "crv": "Ed25519", "x": b64u(raw),
                "use": "sig", "alg": "EdDSA", "kid": "key-1",
            }))
    return out


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", help="provision one agent slug or DID")
    parser.add_argument("--revoke", help="disable one agent's MCP client")
    parser.add_argument("--list", action="store_true",
                        help="show which agents have an MCP client")
    parser.add_argument("--keycloak", default=None)
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password", default="admin")
    args = parser.parse_args()

    settings = get_settings()
    base_url = args.keycloak or settings.keycloak_base_url

    try:
        kc = Keycloak(base_url, settings.keycloak_realm,
                      args.admin_user, args.admin_password)
    except Exception as exc:  # noqa: BLE001
        print(f"cannot reach Keycloak at {base_url}: {type(exc).__name__}")
        return 2

    if args.revoke:
        # The FASTER door, not the control. A revoked agent is already
        # refused by the PDP on every call, because the PIP re-reads agent
        # status inside each evaluation. Disabling the client additionally
        # stops new tokens being minted.
        record = kc.client_by_id(args.revoke)
        if record is None:
            print(f"no MCP client for {args.revoke}")
            return 1
        status, _ = kc.call("PUT", f"/clients/{record['id']}",
                            {**record, "enabled": False})
        print(f"disabled MCP client for {args.revoke}: HTTP {status}")
        print("note: existing access tokens stay valid until they expire; "
              "the PDP refuses the agent regardless.")
        return 0

    pairs = await agent_keys()
    if args.agent:
        pairs = [(did, jwk) for did, jwk in pairs if args.agent in did]
        if not pairs:
            print(f"no ACTIVE agent matching {args.agent!r}")
            return 1

    if args.list:
        for did, _ in pairs:
            record = kc.client_by_id(did)
            state = "absent"
            if record:
                state = "enabled" if record.get("enabled") else "DISABLED"
            print(f"  {did:<45} {state}")
        return 0

    print(f"provisioning {len(pairs)} MCP client(s) in realm "
          f"{settings.keycloak_realm!r}\n")

    scope_id = kc.ensure_mcp_scope()
    if scope_id is None:
        print("cannot continue without the mcp-invoke scope: tokens would be "
              "issued without the MCP audience and every call would fail "
              "authentication.")
        return 2

    for did, jwk in pairs:
        definition = client_definition(did, jwk)
        existing = kc.client_by_id(did)
        if existing:
            status, _ = kc.call("PUT", f"/clients/{existing['id']}",
                                {**existing, **definition})
            verb = "updated"
        else:
            status, _ = kc.call("POST", "/clients", definition)
            verb = "created"
        ok = status in (200, 201, 204)

        record = kc.client_by_id(did)
        if record:
            kc.attach_scope(record["id"], scope_id)
        print(f"  {'OK ' if ok else 'ERR'} {verb} {did}  (HTTP {status})")

    print("\nNo client secret was created: these clients authenticate with a")
    print("signed assertion using each agent's existing Ed25519 key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
