"""The A2A HTTP surface, and the receiver binding the guard enforces.

THE PROPERTY UNDER TEST HERE, and it is the one that makes an envelope
unusable by whoever captured it:

    RECEIVER BINDING IS ENFORCED BY AUTHENTICATION, not by a URL.

The route is guarded with `a2a_submit`, whose target resolver reads the
envelope's own `receiverDid`. `agent_self.rego` then requires
`target.id == principal.did` -- a rule that existed before Phase 7 and
needed one word added to a set.

    A -> B, submitted by B    ALLOW
    A -> B, submitted by C    PRINCIPAL_IS_NOT_THE_SUBJECT
    A -> B, submitted by A    PRINCIPAL_IS_NOT_THE_SUBJECT
    A -> B, submitted by an administrator   refused: no admin holds it
"""
from __future__ import annotations

import pytest

from app.enforcement.resources import payment_execution_count

pytestmark = pytest.mark.asyncio


@pytest.fixture
def submit_http(client, keystore, control_plane, opa_ready):
    """POST an envelope as a signed control-plane principal."""
    from app.controlplane.client import canonical_body, control_plane_headers
    from app.identity.signer import Signer

    async def post(envelope, principal_did, kid=None):
        body = {"envelope": envelope}
        payload = canonical_body(body)
        headers = control_plane_headers(
            Signer(keystore), principal_did=principal_did,
            kid=kid or f"{principal_did}#key-1",
            method="POST", path="/api/v1/a2a/transactions", body=payload)
        return await client.post("/api/v1/a2a/transactions", content=payload,
                                 headers={**headers,
                                          "Content-Type": "application/json"})

    return post


class TestReceiverBindingAtTheHttpBoundary:
    async def test_the_addressed_receiver_may_submit(
        self, submit_http, a2a_envelope, payments_agent, payment_credential,
        a2a_policy_loaded,
    ):
        response = await submit_http(a2a_envelope(), payments_agent.did)
        assert response.status_code == 200, response.text
        assert response.json()["executed"] is True

    async def test_ANOTHER_AGENT_CANNOT_replay_the_same_envelope(
        self, submit_http, a2a_envelope, payments_agent, fraud_agent,
        payment_credential, a2a_policy_loaded,
    ):
        """THE HEADLINE TEST. A genuine, correctly signed, fresh, unspent
        envelope -- presented by an agent it is not addressed to."""
        envelope = a2a_envelope(receiver=payments_agent.did)
        response = await submit_http(envelope, fraud_agent.did)
        assert response.status_code == 403
        detail = response.json()["detail"]
        assert detail["reason"] == "PRINCIPAL_IS_NOT_THE_SUBJECT"
        assert payment_execution_count("pay-3310") == 0

    async def test_the_SENDER_cannot_submit_its_own_envelope(
        self, submit_http, a2a_envelope, risk_agent, payment_credential,
        a2a_policy_loaded,
    ):
        """If it could, it would control both ends and the receiver's
        consent to receive would not exist."""
        response = await submit_http(a2a_envelope(), risk_agent.did)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "PRINCIPAL_IS_NOT_THE_SUBJECT"

    async def test_NO_ADMINISTRATOR_may_submit(
        self, submit_http, a2a_envelope, payment_credential, a2a_policy_loaded
    ):
        """An administrator with `a2a_submit` would be a privileged bypass
        of the receiver binding: `enforcement` can already drive /authorize
        and /enforce for any subject."""
        for admin in ("did:poc:administrator:identity-authority",
                      "did:poc:administrator:enforcement-gateway",
                      "did:poc:administrator:platform-security"):
            response = await submit_http(a2a_envelope(), admin)
            assert response.status_code == 403, admin
            assert response.json()["detail"]["reason"] in {
                "MISSING_CONTROL_PLANE_ROLE", "UNKNOWN_CONTROL_PLANE_OPERATION",
                "NO_MATCHING_CONTROL_PLANE_POLICY",
            }
        assert payment_execution_count("pay-3310") == 0

    async def test_an_unsigned_submission_is_refused(
        self, client, a2a_envelope, payment_credential, a2a_policy_loaded
    ):
        response = await client.post("/api/v1/a2a/transactions",
                                     json={"envelope": a2a_envelope()})
        assert response.status_code == 401
        assert payment_execution_count("pay-3310") == 0

    async def test_a_human_may_not_submit(
        self, client, a2a_envelope, loan_officer_token, control_plane,
        opa_ready, payment_credential, a2a_policy_loaded,
    ):
        """Submitting is machine-to-machine traffic: it requires proving
        control of the receiving agent's key, which a browser does not
        have and must not be given."""
        response = await client.post(
            "/api/v1/a2a/transactions", json={"envelope": a2a_envelope()},
            headers={"Authorization": f"Bearer {loan_officer_token}"})
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == \
            "HUMAN_MAY_NOT_PERFORM_MACHINE_OPERATION"


class TestTheReadSurface:
    async def test_transactions_are_listed_by_receiver(
        self, submit_http, client, a2a_envelope, payments_agent,
        payment_credential, a2a_policy_loaded,
    ):
        await submit_http(a2a_envelope(), payments_agent.did)
        response = await client.get("/api/v1/a2a/transactions",
                                    params={"receiver_did": payments_agent.did})
        assert response.status_code == 200
        assert len(response.json()) == 1

    async def test_transactions_are_listed_by_sender(
        self, submit_http, client, a2a_envelope, payments_agent, risk_agent,
        payment_credential, a2a_policy_loaded,
    ):
        await submit_http(a2a_envelope(), payments_agent.did)
        response = await client.get("/api/v1/a2a/transactions",
                                    params={"sender_did": risk_agent.did})
        assert len(response.json()) == 1

    async def test_one_transaction_carries_its_envelope_and_attempts(
        self, submit_http, client, a2a_envelope, payments_agent,
        payment_credential, a2a_policy_loaded,
    ):
        """The ATTEMPTS matter as much as the record: a transaction with
        rejected attempts against it was probed."""
        envelope = a2a_envelope(transaction_id="txn-read")
        await submit_http(envelope, payments_agent.did)
        response = await client.get("/api/v1/a2a/transactions/txn-read")
        assert response.status_code == 200
        body = response.json()
        assert body["envelope"]["transactionId"] == "txn-read"
        assert "attempts" in body

    async def test_an_unknown_transaction_is_404(self, client):
        assert (await client.get(
            "/api/v1/a2a/transactions/txn-nope")).status_code == 404

    async def test_health_reports_the_configuration_honestly(
        self, client, a2a_policy_loaded
    ):
        """An operator seeing every payment denied should be able to
        confirm the cause here rather than infer it."""
        body = (await client.get("/api/v1/a2a/health")).json()
        assert body["phase"] == 7
        assert body["policy_configuration"]["loaded"] is True
        assert body["verification_required"] is True

    async def test_the_instructions_are_labelled_synthetic(self, client):
        for instruction in (await client.get("/api/v1/a2a/instructions")).json():
            assert "SYNTHETIC" in instruction["disclaimer"]


class TestAdministrativeRoutes:
    async def test_the_sweep_requires_an_authorized_administrator(
        self, client, cp_post, control_plane, opa_ready
    ):
        assert (await client.post("/api/v1/a2a/sweep")).status_code == 401
        response = await cp_post("/api/v1/a2a/sweep",
                                 "did:poc:administrator:identity-authority")
        assert response.status_code == 200

    async def test_an_agent_may_not_sweep(
        self, agent_post, risk_agent
    ):
        """Housekeeping is an operator action, deliberately asymmetric with
        submission -- exactly as jit_revoke is with jit_request."""
        response = await agent_post("/api/v1/a2a/sweep", risk_agent.did)
        assert response.status_code == 403

    async def test_amending_an_amount_requires_the_core_banking_principal(
        self, client, cp_post, control_plane, opa_ready
    ):
        assert (await client.post("/api/v1/a2a/instructions/pay-3310/amount",
                                  json={"amount_inr": 1})).status_code == 401
        refused = await cp_post("/api/v1/a2a/instructions/pay-3310/amount",
                                "did:poc:administrator:identity-authority",
                                {"amount_inr": 1, "reason": "test"})
        assert refused.status_code == 403
        allowed = await cp_post("/api/v1/a2a/instructions/pay-3310/amount",
                                "did:poc:administrator:core-banking",
                                {"amount_inr": 75_000, "reason": "restated"})
        assert allowed.status_code == 200
        assert allowed.json()["amount_inr"] == 75_000

    async def test_no_human_may_amend_an_amount(
        self, client, loan_officer_token, control_plane, opa_ready
    ):
        """An officer who could amend an amount and then approve it would
        defeat the amount policy and maker-checker in one move."""
        response = await client.post(
            "/api/v1/a2a/instructions/pay-3310/amount",
            json={"amount_inr": 1, "reason": "x"},
            headers={"Authorization": f"Bearer {loan_officer_token}"})
        assert response.status_code == 403


class TestTheOperationCatalogue:
    async def test_both_operations_are_declared(self):
        from app.controlplane.guard import OPERATIONS

        assert "a2a_submit" in OPERATIONS
        assert "a2a_administer" in OPERATIONS

    async def test_no_administrator_role_maps_to_a2a_submit(self):
        """A structural assertion on the policy itself."""
        import pathlib
        import re

        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "policies" / "control_plane"
                  / "administration.rego").read_text()
        mapping = re.search(r"required_role := \{(.*?)\n\}", source, re.S).group(1)
        assert '"a2a_submit"' not in mapping, (
            "an administrator holding a2a_submit would bypass receiver binding")
        assert '"a2a_administer"' in mapping

    async def test_a2a_submit_is_an_agent_self_operation(self):
        import pathlib
        import re

        repo = pathlib.Path(__file__).resolve().parents[2]
        source = (repo / "policies" / "control_plane"
                  / "agent_self.rego").read_text()
        operations = re.search(r"self_operations := \{(.*?)\n\}", source,
                               re.S).group(1)
        assert '"a2a_submit"' in operations
        assert '"a2a_administer"' not in operations
