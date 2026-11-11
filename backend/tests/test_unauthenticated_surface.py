"""What an anonymous caller can reach (Phase 9).

WHY THIS FILE EXISTS. Phase 4.5 and Phase 5 closed S-4 through S-7 by putting
a control-plane guard in front of every state-changing route. Those fixes are
tested individually, route by route, in the phase suites. What was missing
was a test of the PROPERTY -- that no privileged mutation anywhere in the
system is reachable without authentication -- asserted over the whole route
table at once, so a route added later is covered by a test nobody has to
remember to write.

That is what `TestNoPrivilegedMutationIsAnonymous` does. It walks the live
application's route table rather than a hand-written list, so a new mutating
route is caught the day it appears.

---------------------------------------------------------------------------
A KNOWN, DELIBERATE GAP IS DOCUMENTED HERE RATHER THAN HIDDEN
---------------------------------------------------------------------------

READ routes are NOT authenticated in this build. An anonymous caller can
currently read the audit trail, the agent registry, the credential
inventory, the human principal list, the approval queue, the policy
inventory, the authorization decision history and the loan records.

This is recorded in docs/PHASE_9_RELEASE.md as a HIGH finding against
production readiness, with its remediation. It is NOT fixed here because
closing it means changing the authentication model of the read API, which
also touches five gate scripts and the console's API client -- a change too
broad to make safely in a final hardening phase, and one whose shape (service
identity for the console, versus human OIDC for every read) is a product
decision rather than a defect fix.

THERE IS DELIBERATELY NO TEST HERE ASSERTING THAT THOSE READS ARE OPEN. A
test that pins a weakness in place is worse than no test: it turns fixing the
weakness into a test failure, and the next person reads the red test as
permission to leave the hole alone.
"""
from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

pytestmark = pytest.mark.integration

# Routes that legitimately take a non-GET verb without a control-plane proof,
# each with the reason it is safe. Anything NOT on this list must reject an
# anonymous caller.
EXEMPT: dict[str, str] = {
    # Pure verification. Takes a document, says whether it verifies, changes
    # nothing and reveals nothing the caller did not already hold.
    "/api/v1/credentials/verify": "stateless verification of a supplied document",
    "/api/v1/credentials/verify-presentation": "stateless verification",
    "/api/v1/identity/verify": "stateless signature verification",
    # The MCP endpoint authenticates with an OAuth bearer token instead of a
    # control-plane proof -- a DIFFERENT mechanism, not a missing one. Its
    # refusals are asserted in test_mcp_security.py.
    "/mcp": "OAuth 2.1 resource server; see test_mcp_security.py",
}


def mutating_routes():
    """Every non-GET route the application actually serves.

    Builds its own app rather than reaching into the test client's private
    `_transport.app`. The route TABLE is a property of the application, not
    of a particular client, and private-attribute access breaks silently on
    an httpx upgrade -- which here would turn a security sweep into a
    vacuous pass.
    """
    from app.main import create_app

    out = []
    for route in create_app().routes:
        if not isinstance(route, APIRoute):
            continue
        verbs = route.methods - {"HEAD", "OPTIONS", "GET"}
        if verbs:
            out.append((sorted(verbs), route.path))
    return out


class TestNoPrivilegedMutationIsAnonymous:
    """Every state-changing route refuses a caller who proved nothing."""

    async def test_the_route_table_is_non_trivial(self, client):
        """Guards the test itself. If the app ever exposed no mutating routes,
        every assertion below would pass vacuously and this file would be
        quietly worthless."""
        assert len(mutating_routes()) > 15

    async def test_every_mutating_route_rejects_an_anonymous_caller(self, client):
        """THE PROPERTY, asserted over the whole route table.

        A body is deliberately NOT crafted per route. Authentication must be
        decided BEFORE the request body is understood -- if a route rejected
        a bad body with 422 before checking the proof, an attacker would learn
        the schema of something they may not call. So an empty body is sent
        and 422 is NOT accepted as a pass.
        """
        reached = []

        for verbs, path in mutating_routes():
            if path in EXEMPT:
                continue
            # Fill path parameters with a value that cannot match a real
            # record, so a 404 can never be mistaken for a refusal.
            concrete = path
            while "{" in concrete:
                start = concrete.index("{")
                end = concrete.index("}", start)
                concrete = concrete[:start] + "phase9-probe" + concrete[end + 1:]

            for verb in verbs:
                response = await client.request(verb, concrete, json={})
                if response.status_code not in (401, 403):
                    reached.append(f"{verb} {path} -> {response.status_code}")

        assert not reached, (
            "these state-changing routes did not reject an unauthenticated "
            "caller:\n  " + "\n  ".join(reached)
        )

    @pytest.mark.parametrize(
        "verb,path,body",
        [
            # The S-4..S-7 routes, named explicitly as well as covered by the
            # sweep above. A named test says WHICH control broke; the sweep
            # says SOMETHING broke. Both are worth having.
            ("POST", "/api/v1/agents", {"slug": "anon"}),
            ("POST", "/api/v1/credentials/issue", {"subject_did": "did:poc:agent:x"}),
            ("POST", "/api/v1/credentials/urn:uuid:0/revoke", {"reason": "x"}),
            ("POST", "/api/v1/identity/sign", {"did": "did:poc:agent:x"}),
            ("POST", "/api/v1/enforce", {"tool": "get_credit_profile"}),
            ("POST", "/api/v1/authorize", {"action": "read"}),
            ("POST", "/api/v1/jit/request", {"subject_did": "did:poc:agent:x"}),
            ("POST", "/api/v1/policies/reload", {}),
            ("POST", "/api/v1/audit/events", {"event_type": "FORGED"}),
            ("POST", "/api/v1/a2a/transactions", {"envelope": {}}),
            ("POST", "/api/v1/loans/loan-7842/amount", {"amount_inr": 1}),
        ],
    )
    async def test_a_named_privileged_route_rejects_anonymity(
        self, client, verb, path, body
    ):
        response = await client.request(verb, path, json=body)
        assert response.status_code in (401, 403), (
            f"{verb} {path} answered {response.status_code} to a caller who "
            f"proved nothing"
        )

    async def test_a_forged_audit_event_cannot_be_injected(self, client):
        """Audit integrity: the trail is evidence, so writing to it is a
        privileged operation. If anyone could POST an event, every other
        audit assertion in this suite would be worthless."""
        response = await client.post(
            "/api/v1/audit/events",
            json={"event_type": "POLICY_ALLOW", "agent_did": "did:poc:agent:x",
                  "decision": "ALLOW", "reason": "FORGED"},
        )
        assert response.status_code in (401, 403)


class TestErrorsDoNotLeak:
    """A refusal says that you were refused, not what exists behind it."""

    async def test_an_anonymous_refusal_does_not_reveal_the_body_schema(
        self, client
    ):
        """401 before 422. Otherwise the error message hands an attacker the
        field names of an endpoint they may not call."""
        response = await client.post("/api/v1/agents", json={})
        assert response.status_code in (401, 403)
        body = response.text.lower()
        for leaked in ("field required", "controller_did", "agent_type"):
            assert leaked not in body, (
                f"an unauthenticated refusal leaked {leaked!r} from the "
                f"request schema"
            )

    async def test_no_stack_trace_reaches_an_anonymous_caller(self, client):
        response = await client.post("/api/v1/agents", json={})
        for leaked in ("Traceback", "/home/", "site-packages", "sqlalchemy"):
            assert leaked not in response.text

    async def test_a_refusal_does_not_echo_a_credential(self, client):
        """A caller who sends something secret-shaped must not get it back in
        the error -- errors are logged, forwarded and screenshotted."""
        secret = "Bearer eyJhbGciOiJIUzI1NiJ9.phase9probe.signature"
        response = await client.post(
            "/api/v1/agents", json={"slug": "x"},
            headers={"Authorization": secret},
        )
        assert response.status_code in (401, 403)
        assert "phase9probe" not in response.text
