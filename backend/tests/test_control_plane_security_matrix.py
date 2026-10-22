"""The Phase 4.5 control-plane security matrix, as one auditable file.

Each test maps to a numbered requirement, so the matrix reads as a checklist
rather than being inferred from assertions scattered across the suite.

The organising claim:

    ANYONE CAN ASK          != SOMEONE MAY ACT
    PROVING WHO YOU ARE     != BEING ALLOWED
    AN AGENT'S AUTHORITY    != AN OPERATOR'S AUTHORITY

    AUTHENTICATION + CONTROL-PLANE AUTHORIZATION = A PERMITTED OPERATION

Every request here goes over HTTP through the real guard, against the real OPA.
Nothing is stubbed: a rejection in this file is the rejection a caller gets.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.controlplane.client import canonical_body, control_plane_headers
from app.identity.signer import Signer

pytestmark = pytest.mark.integration

HEARTBEAT = "/api/v1/ans/heartbeat"


def principal_self(principal):
    """The target that makes an operation self-directed, for policy probes."""
    return principal["did"]


def authorize_body(did, **overrides):
    body = {
        "subject": {"did": did},
        "action": "read",
        "resource": {"type": "credit_records", "id": "customer-007"},
        "purpose": "loan_assessment",
    }
    body.update(overrides)
    return body


@pytest.fixture
async def http_agent(client, control_plane, admin_post):
    """A registry-custodied agent created over HTTP, so its key is signable."""
    response = await admin_post("/api/v1/agents", {
        "slug": "risk-001", "name": "Credit Risk Analysis Agent",
        "agent_type": "RISK", "capabilities": ["credit_analysis"],
        "endpoint": "http://localhost:9003",
    })
    assert response.status_code == 201
    return response.json()


@pytest.fixture
async def attacker(client, control_plane, admin_post):
    """A REAL, fully valid identity that simply is not the victim.

    This is the important adversary. An attacker with no identity at all is
    stopped by authentication; an attacker holding a genuine key and a genuine
    DID is stopped only by authorization, and that is the boundary being tested.
    """
    response = await admin_post("/api/v1/agents", {
        "slug": "attacker-x", "name": "Attacker", "agent_type": "RISK",
        "capabilities": ["credit_analysis"], "endpoint": "http://localhost:9099",
    })
    assert response.status_code == 201
    return response.json()


class TestControlPlaneSecurityMatrix:
    # 1 -- legitimate heartbeat -> ACCEPT
    async def test_01_legitimate_heartbeat_is_accepted(
        self, ans_post, registered_risk_agent, opa_ready
    ):
        did = registered_risk_agent.did
        response = await ans_post(HEARTBEAT, did, {"did": did, "active_tasks": 1})
        assert response.status_code == 200
        assert response.json()["status"] == "ACTIVE"

    # 2 -- spoofed DID heartbeat -> REJECT
    async def test_02_spoofed_did_heartbeat_is_rejected(
        self, ans_post, registered_risk_agent, fraud_agent, opa_ready
    ):
        """The headline S-4 attack.

        The attacker holds a genuine identity and a genuine key, and signs a
        genuine proof -- for ITSELF. It then names the victim in the body. The
        proof verifies as the attacker's; the policy refuses it because the
        principal is not the subject.
        """
        victim = registered_risk_agent.did
        response = await ans_post(HEARTBEAT, fraud_agent.did,
                                  {"did": victim, "active_tasks": 0})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "PRINCIPAL_IS_NOT_THE_SUBJECT"

    # 3 -- invalid signature -> REJECT
    async def test_03_invalid_signature_is_rejected(
        self, ans_client, sign_control_plane, registered_risk_agent, opa_ready
    ):
        did = registered_risk_agent.did
        body = canonical_body({"did": did})
        headers = sign_control_plane(did, path=HEARTBEAT, body={"did": did})
        headers["X-CP-Signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

        response = await ans_client.post(HEARTBEAT, content=body, headers=headers)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "CONTROL_PLANE_SIGNATURE_INVALID"

    # 4 -- expired authentication -> REJECT
    async def test_04_a_stale_proof_is_rejected(
        self, ans_post, registered_risk_agent, opa_ready
    ):
        """Freshness is bounded, so a captured proof dies on its own."""
        did = registered_risk_agent.did
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        response = await ans_post(HEARTBEAT, did, {"did": did}, moment=old)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "CONTROL_PLANE_TIMESTAMP_STALE"

    # 5 -- replayed heartbeat -> REJECT
    async def test_05_a_replayed_heartbeat_is_rejected(
        self, ans_client, sign_control_plane, registered_risk_agent, opa_ready
    ):
        """Capture a WHOLE valid request and send it again."""
        did = registered_risk_agent.did
        body = canonical_body({"did": did, "active_tasks": 3})
        headers = sign_control_plane(did, path=HEARTBEAT,
                                     body={"did": did, "active_tasks": 3})

        first = await ans_client.post(HEARTBEAT, content=body, headers=headers)
        assert first.status_code == 200

        replay = await ans_client.post(HEARTBEAT, content=body, headers=headers)
        assert replay.status_code == 403
        assert replay.json()["detail"]["reason"] == "CONTROL_PLANE_NONCE_REPLAYED"

    # 6 -- deregistration without authorization -> REJECT
    async def test_06_deregistration_by_another_agent_is_rejected(
        self, ans_post, ans_client, registered_risk_agent, fraud_agent, opa_ready
    ):
        """Unauthenticated deregistration is one-request DoS against any agent."""
        victim = registered_risk_agent.did
        path = f"/api/v1/ans/unregister/{victim}"

        unauthenticated = await ans_client.post(path, json={"reason": "x"})
        assert unauthenticated.status_code == 401

        as_someone_else = await ans_post(path, fraud_agent.did, {"reason": "x"})
        assert as_someone_else.status_code == 403
        assert as_someone_else.json()["detail"]["reason"] == "PRINCIPAL_IS_NOT_THE_SUBJECT"

        # ... and the victim is still registered.
        from app.db.models.ans import ANSStatus
        agents = (await ans_client.get("/api/v1/ans/agents")).json()
        assert [a for a in agents if a["did"] == victim][0]["status"] == "ACTIVE"

    # 7 -- policy mutation without authorization -> REJECT
    async def test_07_policy_mutation_without_a_proof_is_rejected(
        self, client, opa_ready
    ):
        for path in ("/api/v1/policies/reload",
                     "/api/v1/policies/loan-credit-read/deactivate",
                     "/api/v1/policies/loan-credit-read/activate"):
            response = await client.post(path)
            assert response.status_code == 401, path
            assert response.json()["detail"]["reason"] == "CONTROL_PLANE_PROOF_MISSING"

    # 8 -- policy activation without authorization -> REJECT
    async def test_08_an_agent_cannot_administer_policy(
        self, cp_post, http_agent, policies_loaded
    ):
        """Privilege escalation, refused with its own diagnostic reason.

        The agent is fully authenticated. Capability credentials describe what
        it may do with DATA; they must never accumulate into authority over the
        machinery that decides.
        """
        response = await cp_post("/api/v1/policies/loan-credit-read/deactivate",
                                 http_agent["did"])
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "AGENT_MAY_NOT_ADMINISTER"

    # 9 -- invalid control-plane principal -> REJECT
    async def test_09_an_administrator_without_the_role_is_rejected(
        self, cp_post, control_plane, identity_admin_did, policies_loaded
    ):
        """LEAST PRIVILEGE, demonstrated rather than asserted.

        A genuine, authenticated, ACTIVE administrator -- holding the wrong
        role. If the roles were decorative this would pass.
        """
        response = await cp_post("/api/v1/policies/loan-credit-read/deactivate",
                                 identity_admin_did)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "MISSING_CONTROL_PLANE_ROLE"

    # 10 -- authorized policy administrator -> ACCEPT
    async def test_10_the_policy_administrator_may_administer_policy(
        self, cp_post, control_plane, policy_admin_did, opa_ready
    ):
        response = await cp_post("/api/v1/policies/reload", policy_admin_did)
        assert response.status_code == 200
        assert "loan-credit-read" in response.json()["loaded"]

    # 11 -- authorized agent heartbeat -> ACCEPT (with liveness actually moving)
    async def test_11_an_authenticated_agent_updates_its_own_liveness(
        self, ans_post, ans_client, registered_risk_agent, opa_ready
    ):
        did = registered_risk_agent.did
        response = await ans_post(HEARTBEAT, did, {"did": did, "active_tasks": 7})
        assert response.status_code == 200
        agent = [a for a in (await ans_client.get("/api/v1/ans/agents")).json()
                 if a["did"] == did][0]
        assert agent["active_tasks"] == 7

    # 12 -- existing discovery still works
    async def test_12_discovery_is_unchanged(
        self, ans_client, registered_risk_agent, issued_credential, opa_ready
    ):
        """Hardening the mutations must not close the reads.

        Discovery is a controlled read: the result is a routing hint the caller
        must still authenticate and authorize against.
        """
        outcome = (await ans_client.post("/api/v1/ans/discover",
                                         json={"capability": "credit_analysis"})).json()
        assert outcome["selected"]["did"] == registered_risk_agent.did
        assert outcome["selected"]["matched"] is True

        for path in ("/api/v1/ans/agents", "/api/v1/ans/capabilities",
                     f"/api/v1/ans/resolve/{registered_risk_agent.did}"):
            assert (await ans_client.get(path)).status_code == 200

    # 13 -- existing Phase 4 authorization still works
    async def test_13_phase_4_decisions_are_unchanged(
        self, cp_post, http_agent, client, issuers, opa_ready
, admin_post):
        """ALLOW, DENY and HUMAN_APPROVAL_REQUIRED all still come out."""
        did = http_agent["did"]
        issued = await admin_post("/api/v1/credentials/issue", {
            "issuer": "did:poc:organization:bank-demo", "subject": did,
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_actions": ["READ_CREDIT_PROFILE"],
                       "allowed_resources": ["credit_records"],
                       "purpose": "loan_assessment"},
            "expires_in_seconds": 3600,
        })
        assert issued.status_code == 201

        allow = (await cp_post("/api/v1/authorize", did, authorize_body(did))).json()
        assert allow["decision"] == "ALLOW"
        assert allow["reason"] == "VALID_CREDENTIAL_AND_POLICY_MATCH"

        deny = (await cp_post("/api/v1/authorize", did, authorize_body(
            did, resource={"type": "payroll_records", "id": "customer-007"}))).json()
        assert deny["decision"] == "DENY"
        assert deny["reason"] == "RESOURCE_NOT_ALLOWED"

        human = (await cp_post("/api/v1/authorize", did,
                               authorize_body(did, action="approve_loan"))).json()
        assert human["decision"] == "HUMAN_APPROVAL_REQUIRED"

    # 13b -- an approval is still not a token, and not a credential
    async def test_13b_an_approval_is_not_a_token_or_a_credential(self):
        """PHASE 5 UPDATE.

        This used to assert that no approval flow existed. Phase 5 built one,
        so the assertion now guards the distinctions that flow must preserve:

          * an approval is not a CREDENTIAL (no HumanApprovalCredential)
          * an approval is not a TOKEN -- there is no `approval_token`, because
            a bearer token that grants an action is exactly the standing
            permission the binding and single-use rules exist to prevent
        """
        import pathlib

        app_dir = pathlib.Path(__file__).resolve().parents[1] / "app"
        for path in app_dir.rglob("*.py"):
            source = path.read_text()
            for forbidden in ("HumanApprovalCredential", "approval_token"):
                assert forbidden not in source, f"{forbidden} found in {path}"


class TestSecurityBoundary:
    """The explicit boundary proofs (§19)."""

    async def test_attacker_spoofing_an_identity_cannot_heartbeat(
        self, ans_client, registered_risk_agent, opa_ready
    ):
        """No proof at all: refused before anything else happens."""
        response = await ans_client.post(
            HEARTBEAT, json={"did": registered_risk_agent.did, "status": "OFFLINE"})
        assert response.status_code == 401
        assert response.json()["detail"]["reason"] == "CONTROL_PLANE_PROOF_MISSING"

    async def test_an_unauthenticated_caller_cannot_take_an_agent_offline(
        self, ans_client, registered_risk_agent, opa_ready
    ):
        """The attack that made S-4 more than cosmetic.

        `status: OFFLINE` in an unauthenticated heartbeat removed a healthy
        agent from discovery -- a single unauthenticated request that stopped
        work being routed to it.
        """
        did = registered_risk_agent.did
        await ans_client.post(HEARTBEAT, json={"did": did, "status": "OFFLINE"})
        agent = [a for a in (await ans_client.get("/api/v1/ans/agents")).json()
                 if a["did"] == did][0]
        assert agent["status"] == "ACTIVE"

    async def test_attacker_cannot_mutate_policy(self, client, policies_loaded):
        response = await client.post("/api/v1/policies/loan-credit-read/deactivate")
        assert response.status_code == 401

        # And the policy is genuinely still loaded and still deciding.
        report = (await client.get("/api/v1/policies")).json()
        loaded = {p["policy_id"]: p for p in report["policies"]}
        assert loaded["loan-credit-read"]["in_engine"] is True

    async def test_the_opa_admin_api_is_not_exposed_by_this_service(self):
        """§11: OPA stays an internal policy engine.

        Two things are asserted. First, no route in either application proxies
        to OPA's administrative API -- the only path to policy is the PAP.
        Second, the published port is bound to loopback in compose, so the
        admin API is not reachable from the network.
        """
        import pathlib

        from app.ans.service import create_ans_app
        from app.main import create_app

        for app in (create_app(), create_ans_app()):
            for route in app.routes:
                path = getattr(route, "path", "")
                assert "/v1/policies/" not in path or path.startswith("/api/v1/")
                assert "8181" not in path

        compose = (pathlib.Path(__file__).resolve().parents[2]
                   / "docker-compose.yml").read_text()
        assert '"127.0.0.1:8181:8181"' in compose
        assert '"8181:8181"' not in compose

    async def test_a_legitimate_agent_heartbeat_is_accepted(
        self, ans_post, registered_risk_agent, opa_ready
    ):
        did = registered_risk_agent.did
        assert (await ans_post(HEARTBEAT, did, {"did": did})).status_code == 200

    async def test_an_authorized_administrator_may_update_policy(
        self, cp_post, control_plane, policy_admin_did, policies_loaded
    ):
        try:
            off = await cp_post("/api/v1/policies/sensitive-action/deactivate",
                                policy_admin_did)
            assert off.status_code == 200
            assert off.json()["status"] == "INACTIVE"
        finally:
            on = await cp_post("/api/v1/policies/sensitive-action/activate",
                               policy_admin_did)
            assert on.status_code == 200


class TestTheEnforcementBoundaryIsAuthenticated:
    """S-5, in its most consequential form.

    /enforce is the only route to a protected tool. Unauthenticated, ANY caller
    could name risk-001 and receive real credit data -- the PDP decided
    correctly about an identity nobody had checked.
    """

    async def test_enforce_without_a_proof_returns_no_data(self, client, opa_ready):
        response = await client.post("/api/v1/enforce", json={
            "subject": {"did": "did:poc:agent:risk-001"},
            "tool": "get_credit_profile",
            "arguments": {"customer_id": "customer-007"},
            "purpose": "loan_assessment",
        })
        assert response.status_code == 401
        assert "credit_score" not in response.text

    async def test_one_agent_cannot_enforce_as_another(
        self, cp_post, http_agent, attacker, client, issuers, opa_ready
, admin_post):
        """The victim holds a credential that WOULD allow this call.

        So the only thing standing between the attacker and the data is the
        binding between the proven principal and the named subject.
        """
        victim = http_agent["did"]
        issued = await admin_post("/api/v1/credentials/issue", {
            "issuer": "did:poc:organization:bank-demo", "subject": victim,
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_actions": ["READ_CREDIT_PROFILE"],
                       "allowed_resources": ["credit_records"],
                       "purpose": "loan_assessment"},
            "expires_in_seconds": 3600,
        })
        assert issued.status_code == 201

        response = await cp_post("/api/v1/enforce", attacker["did"], {
            "subject": {"did": victim}, "tool": "get_credit_profile",
            "arguments": {"customer_id": "customer-007"},
            "purpose": "loan_assessment",
        })
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "PRINCIPAL_IS_NOT_THE_SUBJECT"
        assert "credit_score" not in response.text

    async def test_the_enforcement_gateway_may_act_for_a_subject(
        self, cp_post, http_agent, client, control_plane, enforcement_did,
        issuers, opa_ready
, admin_post):
        """A PEP is a legitimate caller, and it is a NAMED principal with a role.

        This is the difference between "anyone may ask on anyone's behalf" and
        "one identified gateway may, and every call it makes is attributable
        to it".
        """
        victim = http_agent["did"]
        await admin_post("/api/v1/credentials/issue", {
            "issuer": "did:poc:organization:bank-demo", "subject": victim,
            "credential_type": "AgentCapabilityCredential",
            "claims": {"capability": "credit_analysis",
                       "allowed_actions": ["READ_CREDIT_PROFILE"],
                       "allowed_resources": ["credit_records"],
                       "purpose": "loan_assessment"},
            "expires_in_seconds": 3600,
        })
        response = await cp_post("/api/v1/enforce", enforcement_did, {
            "subject": {"did": victim}, "tool": "get_credit_profile",
            "arguments": {"customer_id": "customer-007"},
            "purpose": "loan_assessment",
        })
        assert response.status_code == 200
        assert response.json()["result"]["credit_score"] == 742


class TestSigningOracleIsClosed:
    """S-6: the endpoint that could forge every proof in the system."""

    async def test_signing_as_an_agent_requires_an_administrator(
        self, client, http_agent, opa_ready
    ):
        response = await client.post(
            f"/api/v1/agents/{http_agent['id']}/sign", json={"message": "anything"})
        assert response.status_code == 401
        assert "signature" not in response.json()

    async def test_an_agent_cannot_ask_the_registry_to_sign_for_it(
        self, cp_post, http_agent, opa_ready
    ):
        response = await cp_post(f"/api/v1/agents/{http_agent['id']}/sign",
                                 http_agent["did"], {"message": "anything"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "AGENT_MAY_NOT_ADMINISTER"

    async def test_the_full_forgery_chain_is_broken(
        self, client, cp_post, ans_client, registered_risk_agent, opa_ready
    ):
        """The complete attack, end to end, refused at its first step.

            GET  /api/v1/agents           -> find the victim   (still open: a read)
            POST /agents/{id}/sign        -> forge the proof   (REFUSED)
            POST /ans/heartbeat           -> never reached

        Without the middle step the attacker cannot produce a signature over
        the control-plane payload, so the heartbeat has nothing to present.
        """
        agents = (await client.get("/api/v1/agents")).json()
        victim = [a for a in agents if a["did"] == registered_risk_agent.did][0]

        forged = await client.post(f"/api/v1/agents/{victim['id']}/sign",
                                   json={"message": "any control-plane payload"})
        assert forged.status_code == 401

        blocked = await ans_client.post(HEARTBEAT,
                                        json={"did": registered_risk_agent.did})
        assert blocked.status_code == 401

    async def test_verification_stays_open(self, client, http_agent, opa_ready):
        """Verifying needs only a public key and changes nothing."""
        response = await client.post("/api/v1/identity/verify", json={
            "did": http_agent["did"], "message": "hello", "signature": "AAAA"})
        assert response.status_code == 200
        assert response.json()["valid"] is False


class TestControlPlaneFailsClosed:
    async def test_an_unavailable_policy_engine_refuses_the_operation(
        self, ans_client, sign_control_plane, registered_risk_agent, monkeypatch,
        opa_ready
    ):
        """§12: the control plane fails CLOSED, exactly like the data plane.

        A genuinely authenticated principal with a genuinely valid proof is
        still refused when policy cannot be consulted. There is no "we could
        not check, so proceed".
        """
        from app.authorization.opa import OPAClient, OPAUnavailableError

        async def unavailable(self, input_document, *, decision_url=None):
            raise OPAUnavailableError("the policy engine is not reachable")

        monkeypatch.setattr(OPAClient, "evaluate", unavailable)

        did = registered_risk_agent.did
        body = canonical_body({"did": did})
        headers = sign_control_plane(did, path=HEARTBEAT, body={"did": did})
        response = await ans_client.post(HEARTBEAT, content=body, headers=headers)

        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == \
            "CONTROL_PLANE_AUTHORIZATION_UNAVAILABLE"

    async def test_an_unknown_operation_cannot_be_protected_by_accident(self):
        """A route protected with an undeclared operation fails at import."""
        from app.controlplane.guard import ControlPlaneGuard, fixed

        with pytest.raises(KeyError):
            ControlPlaneGuard("quietly_do_anything", target=fixed("x"))

    async def test_every_declared_operation_is_reachable_by_somebody(
        self, opa_client, opa_ready
    ):
        """A protected route with no ALLOW rule is dead, and looks like a bug.

        Each declared operation is evaluated against the REAL engine twice: as
        an agent acting on itself, and as an administrator holding every role.
        At least one must ALLOW, otherwise the route was protected with an
        operation no policy can ever permit -- which would fail closed, safely
        and unusably, and only be discovered in production.
        """
        from app.controlplane.guard import OPERATIONS
        from app.core.config import get_settings
        from app.controlplane.principals import KNOWN_ROLES

        url = get_settings().control_plane_decision_url
        agent = {"did": "did:poc:agent:self-001", "type": "agent", "roles": []}
        root = {"did": "did:poc:administrator:root", "type": "administrator",
                "roles": sorted(KNOWN_ROLES)}
        # Phase 5: some operations belong to PEOPLE. A human holding every
        # realm role is the third probe, so an operation only a human can
        # perform is not mistaken for an unreachable one.
        human = {"did": "urn:iam:human:probe", "type": "human",
                 "roles": ["IAM_ADMIN", "LOAN_OFFICER", "AUDITOR"]}

        for name in OPERATIONS:
            outcomes = []
            for principal, target in ((agent, principal_self(agent)),
                                      (root, "any"), (human, "any")):
                result = await opa_client.evaluate(
                    {"principal": principal, "operation": name,
                     "target": {"type": "x", "id": target,
                                # The action an approval is about. Needed for
                                # the HITL operations, ignored by the rest.
                                "action": "approve_loan"}},
                    decision_url=url,
                )
                outcomes.append(result.document["decision"])
            assert "ALLOW" in outcomes, (
                f"operation {name!r} can never be permitted: it has no rule in "
                f"policies/control_plane/"
            )

    async def test_an_undeclared_operation_is_denied_by_name(self, opa_client,
                                                             opa_ready):
        """A typo'd or newly-added operation denies, and SAYS it was unknown."""
        from app.core.config import get_settings
        from app.controlplane.principals import KNOWN_ROLES

        result = await opa_client.evaluate(
            {
                "principal": {"did": "did:poc:administrator:root",
                              "type": "administrator", "roles": sorted(KNOWN_ROLES)},
                "operation": "quietly_do_anything",
                "target": {"type": "x", "id": "y"},
            },
            decision_url=get_settings().control_plane_decision_url,
        )
        assert result.document["decision"] == "DENY"
        assert result.document["reason"] == "UNKNOWN_CONTROL_PLANE_OPERATION"


class TestControlPlaneAudit:
    """§17: every security-sensitive control-plane action produces an event."""

    async def test_an_accepted_operation_is_audited_with_its_principal(
        self, ans_post, client, registered_risk_agent, opa_ready
    ):
        did = registered_risk_agent.did
        await ans_post(HEARTBEAT, did, {"did": did})

        events = (await client.get("/api/v1/audit?limit=200")).json()
        types = {e["event_type"] for e in events}
        assert {"CONTROL_PLANE_AUTHENTICATED", "CONTROL_PLANE_AUTHORIZED",
                "ANS_HEARTBEAT_ACCEPTED"} <= types

        authorized = [e for e in events
                      if e["event_type"] == "CONTROL_PLANE_AUTHORIZED"][0]
        for field in ("request_id", "agent_did", "action", "decision", "reason"):
            assert authorized[field], field
        assert authorized["metadata"]["policy"] == "cp-agent-self:v1"

    async def test_a_refusal_survives_the_rejection(
        self, ans_client, client, registered_risk_agent, opa_ready
    ):
        """The refusal is COMMITTED before the exception is raised.

        Without that, FastAPI's session dependency rolls back on the raise and
        the record of the attack disappears -- precisely when it matters.
        """
        await ans_client.post(HEARTBEAT, json={"did": registered_risk_agent.did})

        events = (await client.get("/api/v1/audit?limit=200")).json()
        types = {e["event_type"] for e in events}
        assert "CONTROL_PLANE_REJECTED" in types
        assert "ANS_HEARTBEAT_REJECTED" in types

        rejected = [e for e in events
                    if e["event_type"] == "CONTROL_PLANE_REJECTED"][0]
        assert rejected["reason"] == "CONTROL_PLANE_PROOF_MISSING"
        assert rejected["decision"] == "REJECTED"

    async def test_a_replay_is_audited_as_a_replay(
        self, ans_client, client, sign_control_plane, registered_risk_agent, opa_ready
    ):
        """A replay is evidence of a CAPTURED proof, not a broken client."""
        did = registered_risk_agent.did
        body = canonical_body({"did": did})
        headers = sign_control_plane(did, path=HEARTBEAT, body={"did": did})
        await ans_client.post(HEARTBEAT, content=body, headers=headers)
        await ans_client.post(HEARTBEAT, content=body, headers=headers)

        events = (await client.get("/api/v1/audit?limit=200")).json()
        assert "CONTROL_PLANE_REPLAY_DETECTED" in {e["event_type"] for e in events}

    async def test_a_denied_administrative_attempt_names_the_policy(
        self, cp_post, client, control_plane, identity_admin_did, policies_loaded
    ):
        await cp_post("/api/v1/policies/loan-credit-read/deactivate",
                      identity_admin_did)
        events = (await client.get("/api/v1/audit?limit=200")).json()
        denied = [e for e in events if e["event_type"] == "CONTROL_PLANE_DENIED"]
        assert denied
        assert denied[0]["reason"] == "MISSING_CONTROL_PLANE_ROLE"
        assert denied[0]["metadata"]["policy"] == "cp-administration:v1"
        assert denied[0]["metadata"]["classification"] == "HIGH_RISK_ADMINISTRATION"


class TestNoPolicyLogicLeakedIntoMiddleware:
    """§9: authentication establishes WHO; policy stays in OPA."""

    async def test_the_guard_contains_no_privilege_rules(self):
        import pathlib

        source = (pathlib.Path(__file__).resolve().parents[1]
                  / "app" / "controlplane" / "guard.py").read_text()
        for forbidden in ("policy_admin", "identity_admin", "registry_admin",
                          '"enforcement"'):
            assert forbidden not in source, (
                f"{forbidden!r} appears in the guard: a privilege rule has "
                f"leaked out of Rego and into middleware"
            )

    async def test_the_authenticator_contains_no_privilege_rules(self):
        import pathlib

        source = (pathlib.Path(__file__).resolve().parents[1]
                  / "app" / "controlplane" / "authenticator.py").read_text()
        for forbidden in ("policy_admin", "identity_admin", "registry_admin"):
            assert forbidden not in source

    async def test_the_role_names_only_have_meaning_in_rego(self):
        """The mapping operation -> required role lives in ONE place."""
        import pathlib

        rego = (pathlib.Path(__file__).resolve().parents[2] / "policies"
                / "control_plane" / "administration.rego").read_text()
        for role in ("policy_admin", "registry_admin", "identity_admin",
                     "enforcement"):
            assert role in rego
