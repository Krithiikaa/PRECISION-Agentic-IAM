"""The authorization request and decision contracts.

No OPA needed: these test the contract itself -- what a well-formed request is,
what a decision must carry, and what a caller is not permitted to assert.
"""
from __future__ import annotations

import pytest

from app.authorization.contracts import (
    AuthorizationDecision,
    AuthorizationRequest,
    Decision,
    MalformedAuthorizationRequest,
    Reason,
    Resource,
    Stage,
    Subject,
)


def build(**overrides) -> AuthorizationRequest:
    params = dict(
        subject=Subject(did="did:poc:agent:risk-001"),
        action="read",
        resource=Resource(type="credit_records", id="customer-007"),
        purpose="loan_assessment",
    )
    params.update(overrides)
    return AuthorizationRequest(**params)


class TestRequestValidation:
    async def test_a_complete_request_validates(self):
        build().validate()

    async def test_request_id_is_generated_and_correlatable(self):
        request = build()
        assert request.request_id.startswith("authz-")
        assert build().request_id != request.request_id

    @pytest.mark.parametrize(
        "overrides, expect",
        [
            ({"purpose": ""}, "purpose"),
            ({"purpose": "Loan Assessment"}, "purpose"),
            ({"action": ""}, "action"),
            ({"action": "READ"}, "action"),
            ({"subject": Subject(did="not-a-did")}, "did"),
            ({"resource": Resource(type="")}, "resource.type"),
        ],
    )
    async def test_malformed_requests_are_rejected_not_evaluated(self, overrides, expect):
        with pytest.raises(MalformedAuthorizationRequest) as exc:
            build(**overrides).validate()
        assert expect in str(exc.value)

    async def test_purpose_is_mandatory(self):
        """An action name alone does not describe why it is being taken."""
        with pytest.raises(MalformedAuthorizationRequest) as exc:
            AuthorizationRequest(
                subject=Subject(did="did:poc:agent:risk-001"),
                action="read",
                resource=Resource(type="credit_records"),
                purpose="",
            ).validate()
        assert "purpose is required" in str(exc.value)

    async def test_human_subjects_are_not_authorized_in_phase_4(self):
        """HITL is a later phase; a human principal must not silently work."""
        with pytest.raises(MalformedAuthorizationRequest) as exc:
            build(subject=Subject(did="did:poc:human:alice", type="human")).validate()
        assert "HITL" in str(exc.value)


class TestSelfAssertedAuthorizationIsIgnored:
    """A subject may say anything. It may not decide anything."""

    @pytest.mark.parametrize(
        "key", ["allow", "allowed", "decision", "authorized", "permit",
                "granted", "policy_id", "override", "bypass", "trust_score"],
    )
    async def test_verdict_keys_are_stripped_from_context(self, key):
        request = build(context={key: True, "tenant": "retail"})
        stripped = request.strip_decision_claims()
        assert key not in stripped
        # Legitimate context survives -- this is a filter, not a purge.
        assert stripped["tenant"] == "retail"

    async def test_the_attempt_is_reported_not_silently_dropped(self):
        request = build(context={"allow": True, "trust_score": 99, "tenant": "retail"})
        assert request.rejected_context_keys() == ["allow", "trust_score"]

    async def test_case_insensitive(self):
        request = build(context={"ALLOW": True, "Decision": "ALLOW"})
        assert request.strip_decision_claims() == {}

    async def test_clean_context_is_untouched(self):
        request = build(context={"channel": "api", "tenant": "retail"})
        assert request.strip_decision_claims() == {"channel": "api", "tenant": "retail"}
        assert request.rejected_context_keys() == []


class TestDecisionContract:
    async def test_a_decision_is_never_a_bare_boolean(self):
        decision = AuthorizationDecision(
            decision=Decision.DENY,
            request_id="authz-1",
            reason=Reason.RESOURCE_NOT_ALLOWED,
            policy_id="resource-scope",
            policy_version="v1",
        )
        body = decision.to_dict()
        for field in ("decision", "request_id", "reason", "policy_id",
                      "policy_version", "policy", "stages", "latency_ms", "decided_at"):
            assert field in body
        assert body["policy"] == "resource-scope:v1"

    async def test_latency_is_the_sum_of_measured_stages(self):
        decision = AuthorizationDecision(
            decision=Decision.ALLOW, request_id="authz-1", reason=Reason.POLICY_MATCH,
            stages=[Stage("pip", True, "", 4.0), Stage("opa", True, "", 2.5)],
        )
        assert decision.total_latency_ms == 6.5

    async def test_denied_helper_carries_the_request_facts(self):
        request = build()
        decision = AuthorizationDecision.denied(
            request.request_id, Reason.AUTHORIZATION_UNAVAILABLE,
            detail="OPA down", request=request,
        )
        assert decision.decision is Decision.DENY
        assert decision.allowed is False
        assert decision.subject_did == "did:poc:agent:risk-001"
        assert decision.resource_type == "credit_records"
        assert decision.purpose == "loan_assessment"

    async def test_the_three_decision_values_exist_and_no_others(self):
        assert {d.value for d in Decision} == {
            "ALLOW", "DENY", "HUMAN_APPROVAL_REQUIRED",
        }
