"""Phase 6 security matrix: the whole path, end to end.

Real PostgreSQL, real OPA, real Rego, real signatures. Every test drives the
PDP or the AEM rather than a component in isolation, because the properties
that matter are properties of the COMPOSITION -- a mandate that verifies
correctly and is then handed to a policy that ignores it would pass every test
in the artifact suite and be worthless.

The three tests that matter most, and why:

  * `test_a_revoked_credential_stops_a_valid_mandate` -- proves JIT did not
    become standing permission. The grant is valid and correctly signed, and
    the request fails anyway.
  * `test_a_mandate_cannot_satisfy_a_human_approval_requirement` -- proves the
    Phase 5.5 boundary holds.
  * `test_a_mandate_issued_to_another_agent_is_refused` -- proves a mandate is
    not transferable.
"""
from __future__ import annotations

import pytest

from app.authorization.contracts import Decision, Reason
from app.credentials.issuer import IssueRequest
from app.jit.grant import JITBinding
from app.jit.service import JITService

pytestmark = pytest.mark.integration


@pytest.fixture
def jit_ready(opa_ready, jit_policy_loaded, opa_data_loaded):
    """Policies and both configuration documents present in the engine."""
    return True


async def _mandate(jit_service, binding, **overrides):
    params = dict(ttl_seconds=300, max_uses=3,
                  issuing_request_id="authz-setup",
                  justification={"credential_ids": []})
    params.update(overrides)
    return await jit_service.issue(binding=binding, **params)


# ===========================================================================
#  A -- the happy path, through the real PDP
# ===========================================================================
class TestValidMandate:
    async def test_a_valid_mandate_does_not_disturb_an_allowed_action(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Matrix item A.

        The read was already permitted on the agent's own credential. Presenting
        a mandate alongside it must not change that -- a mandate can only ever
        narrow, and here there is nothing to narrow.
        """
        record = await _mandate(jit_service, jit_binding())
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.ALLOW, decision.reason

    async def test_the_pip_reports_the_mandate_as_a_verdict(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Rego sees a verdict, never a signature -- as with credentials."""
        record = await _mandate(jit_service, jit_binding())
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        fact = decision.evaluation["pip"]["jit"]
        assert fact["present"] and fact["valid"]
        assert fact["grant_id"] == record.grant_id
        assert "signature" not in str(fact.get("constraints"))

    async def test_a_request_without_a_mandate_is_unaffected(
        self, pdp, jit_request, issued_credential, jit_ready
    ):
        """Phase 6 changes nothing for a caller that does not use it."""
        decision = await pdp.decide(jit_request())
        assert decision.decision is Decision.ALLOW
        assert decision.evaluation["pip"]["jit"]["present"] is False


# ===========================================================================
#  B-G, O -- the substitution and lifecycle refusals, through policy
# ===========================================================================
class TestRefusals:
    async def test_an_expired_mandate_denies(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready,
        session,
    ):
        """Matrix item B."""
        from datetime import timedelta

        from sqlalchemy import update

        from app.db.models.jit import JITGrant

        record = await _mandate(jit_service, jit_binding())
        await session.execute(
            update(JITGrant).where(JITGrant.grant_id == record.grant_id)
            .values(expires_at=record.issued_at - timedelta(seconds=1))
        )
        await session.flush()

        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_EXPIRED

    async def test_a_mandate_issued_to_another_agent_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential,
        fraud_agent, jit_ready
    ):
        """Matrix items C and Q.

        Perfectly signed, perfectly valid, and NOT YOURS. This is what makes a
        mandate non-transferable even if the document leaks.
        """
        record = await _mandate(jit_service, jit_binding(agent_did=fraud_agent.did))
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_BINDING_MISMATCH

    async def test_a_mandate_for_another_resource_type_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Matrix item D. A credit_records mandate is not a payroll one."""
        from app.authorization.contracts import Resource

        record = await _mandate(jit_service, jit_binding())
        decision = await pdp.decide(jit_request(
            jit_grant_id=record.grant_id,
            resource=Resource(type="payroll_records", id="customer-007"),
        ))
        assert decision.decision is Decision.DENY

    async def test_a_mandate_for_another_action_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Matrix item E."""
        record = await _mandate(jit_service, jit_binding(action="write"))
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_BINDING_MISMATCH

    async def test_a_mandate_for_another_purpose_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Matrix item F."""
        record = await _mandate(jit_service, jit_binding(purpose="marketing"))
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_BINDING_MISMATCH

    async def test_a_resource_outside_the_mandate_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Matrix item D, at instance granularity."""
        record = await _mandate(jit_service,
                                jit_binding(resource_ids=("customer-007",)))
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id,
                                                resource_id="customer-999"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_BINDING_MISMATCH

    async def test_an_unknown_mandate_is_refused(
        self, pdp, jit_request, issued_credential, jit_ready
    ):
        """Matrix item M."""
        decision = await pdp.decide(jit_request(jit_grant_id="jit-not-a-real-grant"))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_UNKNOWN

    async def test_a_revoked_mandate_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Matrix item N. Immediate, with nothing cached between uses."""
        record = await _mandate(jit_service, jit_binding())
        await jit_service.revoke(record.grant_id, reason="contained")
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_REVOKED

    async def test_an_exhausted_mandate_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential, jit_ready
    ):
        """Matrix item O: replay of a spent mandate."""
        record = await _mandate(jit_service, jit_binding(), max_uses=1)
        assert await jit_service.record_use(record.grant_id, request_id="authz-first")
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_GRANT_EXHAUSTED

    async def test_a_tampered_mandate_is_refused(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential,
        jit_ready, session
    ):
        """Matrix item L, through the whole stack.

        The STORED artifact is edited directly -- the closest thing to database
        tampering this system can be subjected to. The signature covers the
        scope, so the edit is caught.
        """
        from sqlalchemy import update

        from app.db.models.jit import JITGrant

        record = await _mandate(jit_service, jit_binding())
        tampered = dict(record.artifact)
        tampered["credentialSubject"] = {
            **tampered["credentialSubject"], "purpose": "anything_i_like",
        }
        await session.execute(
            update(JITGrant).where(JITGrant.grant_id == record.grant_id)
            .values(artifact=tampered)
        )
        await session.flush()

        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason in {
            Reason.JIT_GRANT_SIGNATURE_INVALID, Reason.JIT_GRANT_BINDING_MISMATCH,
        }


# ===========================================================================
#  U, V -- the underlying trust changes. THE MOST IMPORTANT SECTION.
# ===========================================================================
class TestUnderlyingTrust:
    async def test_a_revoked_credential_stops_a_valid_mandate(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential,
        session, jit_ready
    ):
        """Matrix item U. THE test that proves JIT is not standing permission.

        The mandate is valid, correctly signed, unexpired and unspent. The
        credential it rested on is revoked, and the request is refused anyway.

        If this ever passes as ALLOW, Phase 6 has created a window in which
        Phase 2's "revocation is invalid everywhere at once" is false.
        """
        from app.credentials.status import CredentialStatusService

        record = await _mandate(jit_service, jit_binding())
        # The mandate works while the credential is good.
        assert (await pdp.decide(
            jit_request(jit_grant_id=record.grant_id)
        )).decision is Decision.ALLOW

        await CredentialStatusService(session).revoke(
            issued_credential.credential_id, reason="compromised")

        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY, (
            "a mandate must never outlive the credential it rested on"
        )
        assert decision.reason == Reason.CREDENTIAL_REVOKED
        # And the mandate itself is still a perfectly good signed document --
        # it is the LIVE evaluation that refused, not the artifact.
        assert decision.evaluation["pip"]["jit"]["valid"] is True

    async def test_a_suspended_agent_stops_a_valid_mandate(
        self, pdp, jit_service, jit_binding, jit_request, issued_credential,
        registry, risk_agent, session, jit_ready
    ):
        """Matrix item V. Same property, via identity state."""
        from app.db.models.agent import AgentStatus

        record = await _mandate(jit_service, jit_binding())
        assert (await pdp.decide(
            jit_request(jit_grant_id=record.grant_id)
        )).decision is Decision.ALLOW

        risk_agent.status = AgentStatus.SUSPENDED
        await session.flush()

        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY

    async def test_an_expired_credential_stops_a_valid_mandate(
        self, pdp, jit_service, jit_binding, jit_request, credential_issuer,
        risk_agent, issuer_did, capability_claims, session, jit_ready
    ):
        """The same property again, reached by expiry rather than revocation."""
        import asyncio

        await credential_issuer.issue(IssueRequest(
            issuer_did=issuer_did, subject_did=risk_agent.did,
            credential_type="AgentCapabilityCredential",
            claims=capability_claims, ttl_seconds=1,
        ))
        record = await _mandate(jit_service, jit_binding())
        await asyncio.sleep(1.2)
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY

    async def test_the_mandate_records_the_credentials_it_rested_on(
        self, jit_service, jit_binding, issued_credential
    ):
        """So the intent is reviewable rather than emergent.

        Nobody reading this later should have to infer from the absence of a
        check that grants were meant to outlive revocation.
        """
        record = await _mandate(
            jit_service, jit_binding(),
            justification={"credential_ids": [issued_credential.credential_id]},
        )
        assert issued_credential.credential_id in record.justification["credential_ids"]


# ===========================================================================
#  The Phase 5.5 boundary
# ===========================================================================
class TestHITLBoundaryHolds:
    async def test_a_mandate_cannot_satisfy_a_human_approval_requirement(
        self, aem, jit_service, loan_credential, risk_agent, jit_ready
    ):
        """A mandate is not a human.

        A grant is fabricated for the escalated action -- which issuance would
        never produce -- and the action is STILL escalated, because
        `human_approval.rego` is what decides that and a mandate contributes
        nothing to it.
        """
        binding = JITBinding(
            agent_did=risk_agent.did, action="approve_loan",
            resource_type="loan_applications", resource_ids=("loan-7842",),
            purpose="loan_decision", constraints={},
        )
        record = await _mandate(jit_service, binding)

        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="approve_loan_application",
            arguments={"application_id": "loan-7842"}, purpose="loan_decision",
            jit_grant_id=record.grant_id,
        )
        assert not result.executed
        assert result.decision.decision is Decision.HUMAN_APPROVAL_REQUIRED

    async def test_issuance_refuses_an_escalated_action(
        self, aem, risk_agent, loan_credential, jit_ready
    ):
        """And the mandate above could never have been issued in the first place.

        Two independent defences: issuance refuses, and use would not help.
        """
        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="approve_loan",
            resource_type="loan_applications", resource_ids=["loan-7842"],
            purpose="loan_decision", ttl_seconds=300, max_uses=3,
        )
        assert not result.issued
        assert result.reason in {
            Reason.JIT_SCOPE_EXCEEDS_DECISION, Reason.JIT_ACTION_NOT_ELIGIBLE,
        }

    async def test_the_amount_band_is_re_evaluated_on_every_use(
        self, pdp, jit_service, risk_agent, loan_credential, jit_ready
    ):
        """Phase 5.5 still decides, with a mandate present.

        Even in the hypothetical where a loan mandate existed, moving the
        amount into a higher band changes the answer -- the band is computed
        live from the record, never read from the grant.
        """
        from app.authorization.contracts import AuthorizationRequest, Resource, Subject
        from app.enforcement.resources import set_loan_amount

        binding = JITBinding(
            agent_did=risk_agent.did, action="approve_loan",
            resource_type="loan_applications", resource_ids=("loan-2201",),
            purpose="loan_decision", constraints={},
        )
        record = await _mandate(jit_service, binding)

        def request():
            return AuthorizationRequest(
                subject=Subject(did=risk_agent.did), action="approve_loan",
                resource=Resource(type="loan_applications", id="loan-2201"),
                purpose="loan_decision", jit_grant_id=record.grant_id,
            )

        # Rs 5,00,000 -- inside the agent's autonomous band.
        assert (await pdp.decide(request())).decision is Decision.ALLOW

        # Move it into the dual-control band. The mandate is unchanged.
        set_loan_amount("loan-2201", 20_000_000)
        after = await pdp.decide(request())
        assert after.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert after.reason == Reason.DUAL_APPROVAL_REQUIRED


class TestFinancialBounding:
    """The mandate's amount ceiling, against LIVE server-side amounts.

    Reading a loan is JIT-eligible precisely so this ceiling has a live path.
    Approving one is not, and `TestHITLBoundaryHolds` keeps that true.
    """

    @pytest.fixture
    async def loan_read_credential(self, credential_issuer, risk_agent, issuer_did):
        from app.credentials.issuer import IssueRequest

        return await credential_issuer.issue(IssueRequest(
            issuer_did=issuer_did, subject_did=risk_agent.did,
            credential_type="AgentCapabilityCredential",
            claims={
                "capability": "credit_analysis",
                "allowed_actions": ["READ_LOAN_APPLICATION"],
                "allowed_resources": ["loan_applications"],
                "purpose": "loan_assessment",
            },
            ttl_seconds=3600,
        ))

    def _request(self, risk_agent, application_id, grant_id=None):
        from app.authorization.contracts import AuthorizationRequest, Resource, Subject

        return AuthorizationRequest(
            subject=Subject(did=risk_agent.did), action="read",
            resource=Resource(type="loan_applications", id=application_id),
            purpose="loan_assessment", jit_grant_id=grant_id,
        )

    async def _mandate_over(self, jit_service, risk_agent, ids, ceiling=1_000_000):
        return await jit_service.issue(
            binding=JITBinding(
                agent_did=risk_agent.did, action="read",
                resource_type="loan_applications",
                resource_ids=tuple(sorted(ids)), purpose="loan_assessment",
                constraints={"max_amount_inr": ceiling},
            ),
            ttl_seconds=300, max_uses=5,
            issuing_request_id="authz-money", justification={"credential_ids": []},
        )

    async def test_an_amount_within_the_ceiling_is_permitted(
        self, pdp, jit_service, risk_agent, loan_read_credential, jit_ready
    ):
        record = await self._mandate_over(jit_service, risk_agent,
                                          ["loan-2201", "loan-9001"])
        decision = await pdp.decide(
            self._request(risk_agent, "loan-2201", record.grant_id))
        assert decision.decision is Decision.ALLOW, decision.reason

    async def test_an_amount_above_the_ceiling_is_refused(
        self, pdp, jit_service, risk_agent, loan_read_credential, jit_ready
    ):
        """SAME mandate, SAME agent, SAME action. The amount decided it."""
        record = await self._mandate_over(jit_service, risk_agent,
                                          ["loan-2201", "loan-9001"])
        decision = await pdp.decide(
            self._request(risk_agent, "loan-9001", record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_CONSTRAINT_VIOLATED

    async def test_the_amount_is_read_server_side_not_from_the_caller(
        self, pdp, jit_service, risk_agent, loan_read_credential, jit_ready
    ):
        """A caller claiming a small amount cannot shrink a large loan."""
        record = await self._mandate_over(jit_service, risk_agent, ["loan-9001"])
        request = self._request(risk_agent, "loan-9001", record.grant_id)
        request.context = {"amount_inr": 1, "amount": 1}
        decision = await pdp.decide(request)
        assert decision.decision is Decision.DENY
        assert decision.reason == Reason.JIT_CONSTRAINT_VIOLATED

    async def test_the_ceiling_follows_the_record_when_the_amount_moves(
        self, pdp, jit_service, risk_agent, loan_read_credential, jit_ready
    ):
        """Re-evaluated per use, not frozen at issuance.

        The mandate is issued while the loan is small and stays valid; the loan
        grows past the ceiling and the SAME mandate stops covering it.
        """
        from app.enforcement.resources import set_loan_amount

        record = await self._mandate_over(jit_service, risk_agent, ["loan-2201"])
        assert (await pdp.decide(
            self._request(risk_agent, "loan-2201", record.grant_id)
        )).decision is Decision.ALLOW

        set_loan_amount("loan-2201", 5_000_000)

        after = await pdp.decide(
            self._request(risk_agent, "loan-2201", record.grant_id))
        assert after.decision is Decision.DENY
        assert after.reason == Reason.JIT_CONSTRAINT_VIOLATED

    async def test_an_unreadable_amount_fails_closed(
        self, pdp, jit_service, risk_agent, loan_read_credential, jit_ready
    ):
        """A ceiling on an amount nobody can state is a VIOLATION.

        Treating unknown as within-limit would be the most dangerous reading
        available.
        """
        record = await self._mandate_over(jit_service, risk_agent, ["loan-does-not-exist"])
        decision = await pdp.decide(
            self._request(risk_agent, "loan-does-not-exist", record.grant_id))
        assert decision.decision is Decision.DENY

    async def test_reading_loans_confers_nothing_over_approving_them(
        self, aem, risk_agent, loan_read_credential, jit_ready
    ):
        """The T-2 boundary at the enforcement layer, not just in policy."""
        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="approve_loan",
            resource_type="loan_applications", resource_ids=["loan-2201"],
            purpose="loan_decision", ttl_seconds=300, max_uses=3,
        )
        assert not result.issued


# ===========================================================================
#  P, Q -- issuance and usage authorization, through the AEM
# ===========================================================================
class TestIssuanceAuthorization:
    async def test_issuance_runs_the_full_pdp_evaluation(
        self, aem, risk_agent, issued_credential, jit_ready
    ):
        """A mandate can only be issued for something permitted RIGHT NOW."""
        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="read",
            resource_type="credit_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=300, max_uses=3,
        )
        assert result.issued, result.reason
        assert result.decision.decision is Decision.ALLOW
        assert result.grant is not None

    async def test_issuance_is_refused_without_a_valid_credential(
        self, aem, risk_agent, jit_ready
    ):
        """Matrix item P. No credential, no mandate."""
        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="read",
            resource_type="credit_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=300, max_uses=3,
        )
        assert not result.issued
        assert result.reason == Reason.JIT_SCOPE_EXCEEDS_DECISION

    async def test_issuance_is_refused_for_an_unregistered_agent(
        self, aem, jit_ready
    ):
        result = await aem.issue_jit_grant(
            subject_did="did:poc:agent:does-not-exist", action="read",
            resource_type="credit_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=300, max_uses=3,
        )
        assert not result.issued

    async def test_an_excessive_ttl_is_refused_by_policy(
        self, aem, risk_agent, issued_credential, jit_ready
    ):
        """Matrix item R, through the real issuance policy."""
        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="read",
            resource_type="credit_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=3_000, max_uses=3,
        )
        assert not result.issued
        assert result.reason == Reason.JIT_TTL_EXCEEDS_POLICY_MAXIMUM

    async def test_an_ineligible_resource_is_refused_by_policy(
        self, aem, risk_agent, issued_credential, jit_ready
    ):
        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="read",
            resource_type="payroll_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=300, max_uses=3,
        )
        assert not result.issued

    async def test_a_refusal_carries_the_pdp_decision_too(
        self, aem, risk_agent, jit_ready
    ):
        """"No mandate for you" and "you may not do this at all" differ."""
        result = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="read",
            resource_type="credit_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=300, max_uses=3,
        )
        payload = result.to_dict()
        assert payload["authorization"]["decision"] == "DENY"
        assert payload["issued"] is False

    async def test_there_is_no_python_issuance_shortcut(self):
        """No `if agent_is_valid: issue_grant()`, asserted structurally.

        `issue_jit_grant` must call the PDP and the issuance policy before it
        reaches the signing step. A refactor that dropped either would leave
        this failing.
        """
        import inspect

        from app.enforcement.aem import AdapterEnforcementMiddleware

        source = inspect.getsource(AdapterEnforcementMiddleware.issue_jit_grant)
        pdp_at = source.index("self.pdp.decide(request)")
        policy_at = source.index("self._jit_issuance_decision(")
        sign_at = source.index("self.jit.issue(")
        assert pdp_at < policy_at < sign_at, (
            "issuance must evaluate the PDP, then policy, THEN sign"
        )
        assert "JIT_ISSUANCE_PERMITTED" not in source, (
            "the permit reason must come from Rego, not be constructed here"
        )


# ===========================================================================
#  The AEM spends the mandate
# ===========================================================================
class TestEnforcementSpendsTheMandate:
    async def test_a_successful_call_spends_one_use(
        self, aem, jit_service, jit_binding, risk_agent, issued_credential, jit_ready
    ):
        record = await _mandate(jit_service, jit_binding())
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
            jit_grant_id=record.grant_id,
        )
        assert result.executed, result.error
        after = await jit_service.get(record.grant_id)
        assert after.uses == 1

    async def test_the_budget_bounds_real_enforcement(
        self, aem, jit_service, jit_binding, risk_agent, issued_credential, jit_ready
    ):
        """A mandate is a BUDGET, and the budget runs out."""
        record = await _mandate(jit_service, jit_binding(), max_uses=2)
        for _ in range(2):
            result = await aem.enforce(
                subject_did=risk_agent.did, tool_name="get_credit_profile",
                arguments={"customer_id": "customer-007"},
                purpose="loan_assessment", jit_grant_id=record.grant_id,
            )
            assert result.executed, result.error

        third = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"},
            purpose="loan_assessment", jit_grant_id=record.grant_id,
        )
        assert not third.executed
        assert third.decision.reason == Reason.JIT_GRANT_EXHAUSTED

    async def test_a_blocked_call_does_not_spend_the_budget(
        self, aem, jit_service, jit_binding, risk_agent, issued_credential, jit_ready
    ):
        """A refused action must not cost a unit of somebody's mandate."""
        record = await _mandate(jit_service, jit_binding())
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_payroll_record",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
            jit_grant_id=record.grant_id,
        )
        assert not result.executed
        after = await jit_service.get(record.grant_id)
        assert after.uses == 0

    async def test_the_enforcement_grant_and_the_mandate_are_different_objects(
        self, aem, jit_service, jit_binding, risk_agent, issued_credential, jit_ready
    ):
        """Two layers, two ids. Conflating them would make the trail unreadable."""
        record = await _mandate(jit_service, jit_binding())
        result = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
            jit_grant_id=record.grant_id,
        )
        assert result.grant["grant_id"].startswith("grant-")
        assert record.grant_id.startswith("jit-")
        assert result.grant["grant_id"] != record.grant_id


# ===========================================================================
#  Audit and correlation
# ===========================================================================
class TestAudit:
    async def test_the_whole_mandate_arc_is_recorded(
        self, aem, jit_service, jit_binding, risk_agent, issued_credential,
        session, jit_ready
    ):
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        issued = await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="read",
            resource_type="credit_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=300, max_uses=2,
        )
        assert issued.issued, issued.reason
        grant_id = issued.grant.grant_id

        await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
            jit_grant_id=grant_id,
        )
        await jit_service.revoke(grant_id, reason="done with it")

        result = await session.execute(select(AuditEvent))
        types = [e.event_type for e in result.scalars().all()]
        for expected in ("JIT_REQUESTED", "JIT_ISSUED", "JIT_USED", "JIT_REVOKED"):
            assert expected in types, f"{expected} missing from {sorted(set(types))}"

    async def test_a_refusal_is_audited_as_its_own_event(
        self, aem, risk_agent, session, jit_ready
    ):
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        await aem.issue_jit_grant(
            subject_did=risk_agent.did, action="read",
            resource_type="credit_records", resource_ids=["customer-007"],
            purpose="loan_assessment", ttl_seconds=300, max_uses=3,
        )
        result = await session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "JIT_DENIED")
        )
        assert list(result.scalars().all()), "a refused mandate must be audited"

    async def test_a_replay_is_audited_as_its_own_event(
        self, jit_service, jit_binding, session, jit_ready
    ):
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        record = await _mandate(jit_service, jit_binding(), max_uses=1)
        await jit_service.record_use(record.grant_id, request_id="authz-1")
        await jit_service.record_use(record.grant_id, request_id="authz-2")

        result = await session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "JIT_REPLAY_BLOCKED")
        )
        events = list(result.scalars().all())
        assert events
        assert events[0].event_metadata["grant_id"] == record.grant_id

    async def test_events_correlate_by_grant_id(
        self, aem, jit_service, jit_binding, risk_agent, issued_credential,
        session, jit_ready
    ):
        """A whole mandate is reconstructible from the trail alone."""
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        record = await _mandate(jit_service, jit_binding())
        await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
            jit_grant_id=record.grant_id,
        )
        result = await session.execute(select(AuditEvent))
        correlated = [
            e for e in result.scalars().all()
            if (e.event_metadata or {}).get("grant_id") == record.grant_id
            or (e.event_metadata or {}).get("jit_grant_id") == record.grant_id
        ]
        assert len(correlated) >= 2

    async def test_no_key_material_appears_in_the_trail(
        self, aem, jit_service, jit_binding, risk_agent, issued_credential,
        session, jit_ready
    ):
        import json

        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        record = await _mandate(jit_service, jit_binding())
        await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment",
            jit_grant_id=record.grant_id,
        )
        result = await session.execute(select(AuditEvent))
        raw = json.dumps([e.event_metadata for e in result.scalars().all()])
        for forbidden in ("PRIVATE KEY", "privateKey", "private_key_b64", "BEGIN "):
            assert forbidden not in raw


# ===========================================================================
#  S-7 and the existing boundaries stay closed
# ===========================================================================
class TestNoRegression:
    async def test_a_mandate_does_not_confer_a_capability(
        self, pdp, jit_service, jit_binding, jit_request, risk_agent, jit_ready
    ):
        """With NO credential, a mandate allows nothing.

        The clearest statement of "an input, not a permission": the mandate
        verifies perfectly and the request is still denied for want of a
        credential.
        """
        record = await _mandate(jit_service, jit_binding())
        decision = await pdp.decide(jit_request(jit_grant_id=record.grant_id))
        assert decision.decision is Decision.DENY
        assert decision.evaluation["pip"]["jit"]["valid"] is True

    async def test_an_agent_cannot_self_assert_a_mandate(
        self, pdp, jit_request, issued_credential, jit_ready
    ):
        """Matrix item S / self-assertion.

        A caller supplying `{"jit": {"valid": true}}` in context is supplying a
        string. The PIP overwrites the field with what it established, and the
        attempt is recorded.
        """
        decision = await pdp.decide(jit_request(context={
            "jit": {"valid": True, "grant_id": "jit-made-up"},
            "grant_id": "jit-made-up",
        }))
        assert decision.evaluation["pip"]["jit"]["present"] is False
        assert "jit" in decision.evaluation["rejected_context_keys"]
        assert "grant_id" in decision.evaluation["rejected_context_keys"]

    async def test_the_decision_set_is_still_three_values(self):
        """No fourth verdict was introduced for JIT."""
        assert {d.value for d in Decision} == {
            "ALLOW", "DENY", "HUMAN_APPROVAL_REQUIRED",
        }

    async def test_the_aem_remains_the_enforcement_boundary(
        self, jit_service, jit_binding, risk_agent, issued_credential, jit_ready
    ):
        """A mandate does not make a protected tool directly callable."""
        from app.enforcement.tools import EnforcementBypassError, build_default_registry

        await _mandate(jit_service, jit_binding())
        tool = build_default_registry().get("get_credit_profile")
        with pytest.raises(EnforcementBypassError):
            await tool(customer_id="customer-007")
