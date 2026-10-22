"""The approval artifact and its lifecycle.

The security matrix asserts the outcomes the phase requires. This file asserts
the properties those outcomes depend on: what the artifact binds, who can have
signed it, and what the state machine will and will not do.

    "A human approved this agent"   is a standing permission with a name on it
    "Human X approved agent A doing B on R for P under request Q, once, until T"
                                     is an approval

Everything below exists to make the second sentence true and the first
impossible.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import get_settings
from app.db.models.hitl import ApprovalDecision, ApprovalStatus
from app.hitl.artifact import (
    APPROVAL_PROOF_PURPOSE,
    ARTIFACT_TYPE,
    ApprovalBinding,
    ArtifactReason,
    verify_artifact,
)
from app.hitl.service import (
    ALLOWED_TRANSITIONS,
    ApprovalNotPending,
    ApprovalService,
    InvalidTransition,
)

pytestmark = pytest.mark.integration


class _Approver:
    """A stand-in for an authenticated human, shaped like the real one."""

    def __init__(self, username="loan.officer", roles=("LOAN_OFFICER",)):
        self.subject = f"sub-{username}"
        self.issuer = get_settings().keycloak_issuer
        self.username = username
        self.roles = roles
        self.provider = "keycloak-oidc"
        self.principal_urn = f"urn:iam:human:{self.subject}"


@pytest.fixture
def approver():
    return _Approver()


@pytest.fixture
def service(session, keystore, approval_authority):
    return ApprovalService(session, keystore, get_settings())


@pytest.fixture
def binding(risk_agent):
    def make(**overrides):
        params = dict(
            request_id="authz-loan-1", agent_did=risk_agent.did,
            action="approve_loan", resource_type="loan_applications",
            resource_id="loan-7842", purpose="loan_decision",
        )
        params.update(overrides)
        return ApprovalBinding(**params)
    return make


@pytest.fixture
async def approved(service, binding, approver):
    """A requested-and-approved approval, ready to be spent."""
    record = await service.request_approval(
        binding=binding(), presentation={"demo": True}, reason="SENSITIVE_ACTION_REQUIRES_HUMAN",
    )
    return await service.decide(record=record, approver=approver,
                                decision=ApprovalDecision.APPROVED)


class TestBinding:
    def test_the_digest_covers_every_defining_field(self, binding):
        base = binding()
        for field in ("request_id", "agent_did", "action",
                      "resource_type", "resource_id", "purpose"):
            assert binding(**{field: "changed"}).digest() != base.digest(), field

    def test_the_digest_is_order_independent(self, risk_agent):
        a = ApprovalBinding(request_id="r", agent_did=risk_agent.did,
                            action="approve_loan", resource_type="loan_applications",
                            resource_id="l1", purpose="loan_decision")
        b = ApprovalBinding(purpose="loan_decision", resource_id="l1",
                            resource_type="loan_applications", action="approve_loan",
                            agent_did=risk_agent.did, request_id="r")
        assert a.digest() == b.digest()

    def test_differences_name_the_field_that_moved(self, binding):
        """A denial must be diagnostic: 'the resource changed' and 'this is a
        different request' are very different incidents."""
        assert binding().differences(binding(resource_id="loan-1001")) == ["resource_id"]
        assert binding().differences(binding(agent_did="did:poc:agent:other")) == ["agent_did"]

    def test_it_is_built_from_the_authorization_request(self, loan_request):
        request = loan_request()
        built = ApprovalBinding.from_request(request)
        assert built.request_id == request.request_id
        assert built.agent_did == request.subject.did
        assert built.action == "approve_loan"
        assert built.resource_id == "loan-7842"


class TestTheSignedArtifact:
    async def test_it_is_signed_by_the_approval_authority(self, approved,
                                                          approval_authority):
        artifact = approved.artifact
        assert artifact["issuer"] == get_settings().approval_authority_did
        assert artifact["issuer"].startswith("did:poc:service:")
        assert approved.artifact_signed_by == artifact["issuer"]

    async def test_it_is_not_signed_by_the_agent(self, approved, risk_agent):
        """The self-approval defence, at the key level.

        If the agent's key signed this, the agent could manufacture its own
        human approval and the entire phase would be theatre.
        """
        assert approved.artifact["proof"]["verificationMethod"] != risk_agent.active_key.kid
        assert risk_agent.did not in approved.artifact["proof"]["verificationMethod"]

    async def test_the_authority_holds_no_agent_or_issuer_key(
        self, approval_authority, issuers, risk_agent
    ):
        """Separation of duties, asserted rather than assumed."""
        principal = await approval_authority.require()
        issuer_kids = {i.kid for i in await issuers.list_issuers()}
        assert principal.kid not in issuer_kids
        assert principal.kid != risk_agent.active_key.kid

    async def test_the_authority_holds_no_control_plane_roles(self, approval_authority):
        """Signing approvals confers no authority over agents, credentials or
        policy. Being able to record a decision is not being able to change
        what the system enforces."""
        principal = await approval_authority.require()
        assert principal.roles == []

    async def test_the_proof_purpose_is_its_own_domain(self, approved):
        from app.ans.proof import PROOF_PURPOSE as ANS_PURPOSE
        from app.controlplane.proof import PROOF_PURPOSE as CP_PURPOSE
        from app.credentials.vc import (
            CREDENTIAL_PROOF_PURPOSE,
            PRESENTATION_PROOF_PURPOSE,
        )

        assert approved.artifact["proof"]["proofPurpose"] == APPROVAL_PROOF_PURPOSE
        purposes = {APPROVAL_PROOF_PURPOSE, ANS_PURPOSE, CP_PURPOSE,
                    CREDENTIAL_PROOF_PURPOSE, PRESENTATION_PROOF_PURPOSE}
        assert len(purposes) == 5

    async def test_the_artifact_carries_the_approver_and_the_binding(
        self, approved, risk_agent
    ):
        subject = approved.artifact["credentialSubject"]
        assert subject["decision"] == "APPROVED"
        assert subject["approver"]["username"] == "loan.officer"
        assert subject["approver"]["roles"] == ["LOAN_OFFICER"]
        assert subject["agent_did"] == risk_agent.did
        assert subject["resource_id"] == "loan-7842"
        assert subject["bindingHash"]
        # Phase 9 will bind sessions. Explicitly null, not absent.
        assert subject["sessionId"] is None

    async def test_no_secret_is_in_the_artifact(self, approved):
        serialised = str(approved.artifact).lower()
        for forbidden in ("password", "secret", "private", "refresh_token",
                          "access_token", "bearer"):
            assert forbidden not in serialised


class TestVerification:
    @pytest.fixture
    async def authority_document(self, approval_authority):
        return (await approval_authority.require()).did_document

    async def test_a_valid_artifact_verifies(self, approved, authority_document,
                                             binding):
        report = verify_artifact(
            approved.artifact, authority_document=authority_document,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        assert report.valid is True
        assert report.reason == ArtifactReason.VALID

    async def test_every_check_is_reported_not_just_a_boolean(
        self, approved, authority_document, binding
    ):
        """Same discipline as the Phase 2 verifier: a caller that cannot see
        WHICH check failed cannot fix it, and an auditor cannot review it."""
        report = verify_artifact(
            approved.artifact, authority_document=authority_document,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        names = [c.name for c in report.checks]
        # `signing_key` is absent here because this call supplies no key
        # register; with one it appears after `authority`. Phase 5.5 covers
        # that path in test_approval_key_rotation.py.
        assert names == ["present", "structure", "proof_purpose", "authority",
                         "verification_method", "signature", "decision",
                         "validity_window", "domain", "binding", "approvers"]

    async def test_tampering_with_the_decision_breaks_the_signature(
        self, approved, authority_document, binding
    ):
        artifact = dict(approved.artifact)
        subject = dict(artifact["credentialSubject"])
        subject["decision"] = "APPROVED"
        subject["resource_id"] = "loan-1001"          # a different loan
        artifact["credentialSubject"] = subject
        report = verify_artifact(
            artifact, authority_document=authority_document,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.SIGNATURE_INVALID

    async def test_flipping_the_proof_purpose_breaks_the_signature(
        self, approved, authority_document, binding
    ):
        """The proof options are INSIDE the signed payload, so the purpose is a
        real domain separator rather than an advisory label."""
        artifact = dict(approved.artifact)
        artifact["proof"] = {**artifact["proof"], "proofPurpose": "assertionMethod"}
        report = verify_artifact(
            artifact, authority_document=authority_document,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.PROOF_PURPOSE_INVALID

    async def test_an_artifact_from_another_issuer_is_refused(
        self, approved, binding, issuers, issuer_did
    ):
        """A credential issuer's DID Document, presented as the authority."""
        issuer = await issuers.get_by_did(issuer_did)
        report = verify_artifact(
            approved.artifact, authority_document=issuer.did_document,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.AUTHORITY_UNKNOWN

    async def test_a_credential_is_not_an_approval(
        self, issued_credential, authority_document, binding
    ):
        """TOKEN CONFUSION. A genuine, correctly signed VERIFIABLE CREDENTIAL
        presented where an approval is required."""
        report = verify_artifact(
            issued_credential.document, authority_document=authority_document,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.MALFORMED

    async def test_a_wrong_domain_is_refused(self, approved, authority_document,
                                             binding):
        """Audience binding, preserving the Phase 2 S-2 protection."""
        report = verify_artifact(
            approved.artifact, authority_document=authority_document,
            expected_binding=binding(), expected_domain="payments-service",
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.DOMAIN_MISMATCH

    @pytest.mark.parametrize("field,value", [
        ("request_id", "authz-someone-else"),
        ("agent_did", "did:poc:agent:fraud-001"),
        ("action", "disburse_funds"),
        ("resource_type", "credit_records"),
        ("resource_id", "loan-1001"),
        ("purpose", "marketing_analytics"),
    ])
    async def test_every_bound_field_is_checked(
        self, approved, authority_document, binding, field, value
    ):
        """Change ANY defining field of the request and the approval no longer
        applies. Nothing is bypassed -- the artifact was never about it."""
        report = verify_artifact(
            approved.artifact, authority_document=authority_document,
            expected_binding=binding(**{field: value}),
            expected_domain=get_settings().approval_domain,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.BINDING_MISMATCH

    async def test_a_missing_artifact_is_a_fact_not_a_crash(
        self, authority_document, binding
    ):
        report = verify_artifact(
            None, authority_document=authority_document,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.MISSING

    async def test_an_unresolvable_authority_denies(self, approved, binding):
        """FAIL CLOSED: if we cannot resolve who signed it, it is not valid."""
        report = verify_artifact(
            approved.artifact, authority_document=None,
            expected_binding=binding(), expected_domain=get_settings().approval_domain,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.AUTHORITY_UNKNOWN


class TestStateMachine:
    def test_terminal_states_are_terminal(self):
        for terminal in (ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED,
                         ApprovalStatus.CANCELLED, ApprovalStatus.CONSUMED):
            assert ALLOWED_TRANSITIONS[terminal] == frozenset()

    def test_consumed_cannot_go_back_to_approved(self):
        assert ApprovalStatus.APPROVED not in ALLOWED_TRANSITIONS[ApprovalStatus.CONSUMED]

    def test_rejected_cannot_be_consumed(self):
        assert ApprovalStatus.CONSUMED not in ALLOWED_TRANSITIONS[ApprovalStatus.REJECTED]

    def test_only_an_approved_request_can_be_consumed(self):
        for status, permitted in ALLOWED_TRANSITIONS.items():
            if ApprovalStatus.CONSUMED in permitted:
                assert status is ApprovalStatus.APPROVED

    async def test_deciding_twice_is_refused(self, service, approved, approver):
        with pytest.raises(ApprovalNotPending):
            await service.decide(record=approved, approver=approver,
                                 decision=ApprovalDecision.REJECTED)

    async def test_a_rejected_approval_cannot_be_approved_later(
        self, service, binding, approver
    ):
        record = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        await service.decide(record=record, approver=approver,
                             decision=ApprovalDecision.REJECTED)
        with pytest.raises(ApprovalNotPending):
            await service.decide(record=record, approver=approver,
                                 decision=ApprovalDecision.APPROVED)

    async def test_cancelling_a_decided_approval_is_refused(self, service, approved):
        with pytest.raises(InvalidTransition):
            await service.cancel(approved, "changed my mind")

    async def test_a_rejection_produces_no_artifact(self, service, binding, approver):
        """There is nothing to present, because nothing is permitted."""
        record = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        record = await service.decide(record=record, approver=approver,
                                      decision=ApprovalDecision.REJECTED)
        assert record.status is ApprovalStatus.REJECTED
        assert record.artifact is None


class TestSingleUse:
    async def test_an_approval_is_consumed_once(self, service, approved):
        assert await service.consume(approved.approval_id, request_id="r1") is True
        assert await service.consume(approved.approval_id, request_id="r2") is False

    async def test_consumption_is_recorded_with_who_spent_it(self, service, approved):
        await service.consume(approved.approval_id, request_id="authz-spender")
        record = await service.get(approved.approval_id)
        assert record.status is ApprovalStatus.CONSUMED
        assert record.consumed_by_request == "authz-spender"
        assert record.consumed_at is not None

    async def test_a_pending_approval_cannot_be_consumed(self, service, binding):
        record = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        assert await service.consume(record.approval_id, request_id="r") is False

    async def test_a_rejected_approval_cannot_be_consumed(
        self, service, binding, approver
    ):
        record = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        await service.decide(record=record, approver=approver,
                             decision=ApprovalDecision.REJECTED)
        assert await service.consume(record.approval_id, request_id="r") is False

    async def test_concurrent_consumption_has_exactly_one_winner(
        self, engine, session, service, approved
    ):
        """§49. Two requests arrive together with the same approval.

        Run on SEPARATE database sessions and connections, so this is a real
        race against PostgreSQL rather than three calls sharing one
        transaction. The winner is decided by a conditional UPDATE, not by
        Python state -- which is the whole point: an in-process check would be
        a race with a comfortable-looking shape.

        The approval is committed first, because an uncommitted row is
        invisible to the other connections and all three would lose for the
        wrong reason.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker

        await session.commit()
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def spend(label: str) -> bool:
            async with maker() as own:
                won = await ApprovalService(own).consume(
                    approved.approval_id, request_id=label)
                await own.commit()
                return won

        results = await asyncio.gather(spend("a"), spend("b"), spend("c"))
        assert sum(results) == 1, f"expected exactly one winner, got {results}"


class TestExpiry:
    async def test_an_approval_expires_on_the_server_clock(
        self, session, keystore, binding, approver, approval_authority
    ):
        """Real elapsed time, a real expiry. No clock is faked and none is
        supplied by a client."""
        from app.core.config import Settings

        settings = Settings.model_construct(
            **{**get_settings().model_dump(), "approval_ttl_seconds": 1}
        )
        service = ApprovalService(session, keystore, settings)
        record = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        record = await service.decide(record=record, approver=approver,
                                      decision=ApprovalDecision.APPROVED)
        assert record.status is ApprovalStatus.APPROVED

        await asyncio.sleep(1.2)

        fact = await service.fact_for(binding())
        assert fact.valid is False
        assert fact.reason == ArtifactReason.EXPIRED
        assert (await service.get(record.approval_id)).status is ApprovalStatus.EXPIRED

    async def test_an_expired_approval_cannot_be_consumed(
        self, session, keystore, binding, approver, approval_authority
    ):
        from app.core.config import Settings

        settings = Settings.model_construct(
            **{**get_settings().model_dump(), "approval_ttl_seconds": 1}
        )
        service = ApprovalService(session, keystore, settings)
        record = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        record = await service.decide(record=record, approver=approver,
                                      decision=ApprovalDecision.APPROVED)
        await asyncio.sleep(1.2)
        assert await service.consume(record.approval_id, request_id="r") is False

    async def test_expiry_is_never_silently_extended(self, service, approved):
        """The deadline is written once, at decision time."""
        original = approved.expires_at
        await service.fact_for(
            ApprovalBinding(request_id=approved.request_id,
                            agent_did=approved.agent_did, action=approved.action,
                            resource_type=approved.resource_type,
                            resource_id=approved.resource_id,
                            purpose=approved.purpose))
        assert (await service.get(approved.approval_id)).expires_at == original


class TestFactsForPolicy:
    async def test_a_valid_approval_reports_valid(self, service, approved, binding):
        fact = await service.fact_for(binding())
        assert fact.present is True
        assert fact.valid is True
        assert fact.reason == ArtifactReason.VALID
        assert fact.bound_to_request is True

    async def test_no_approval_is_a_fact_not_a_default(self, service, binding):
        fact = await service.fact_for(binding(request_id="never-asked"))
        assert fact.present is False
        assert fact.valid is False
        assert fact.reason == ArtifactReason.MISSING

    async def test_lookup_is_by_binding_so_another_action_is_not_found(
        self, service, approved, binding
    ):
        """An approval for a DIFFERENT action is not found, rather than found
        and then rejected. The narrower behaviour is the safer one."""
        fact = await service.fact_for(binding(action="disburse_funds"))
        assert fact.present is False

    async def test_offering_an_id_does_not_make_an_approval_apply(
        self, service, approved, binding
    ):
        """An offered approval_id is a CLAIM. It narrows which approval is
        considered; it can never make one apply to the wrong request."""
        fact = await service.fact_for(binding(resource_id="loan-1001"),
                                      approval_id=approved.approval_id)
        assert fact.valid is False
        assert fact.reason == ArtifactReason.BINDING_MISMATCH

    async def test_a_consumed_approval_reports_consumed(self, service, approved,
                                                        binding):
        await service.consume(approved.approval_id, request_id="r")
        fact = await service.fact_for(binding())
        assert fact.valid is False
        assert fact.reason == ArtifactReason.ALREADY_CONSUMED


class TestIdempotentRequests:
    async def test_asking_twice_returns_the_same_open_request(self, service, binding):
        """Two open approvals for one action would let one person approve while
        a colleague rejects, with both artifacts valid."""
        first = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        second = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        assert first.approval_id == second.approval_id

    async def test_a_different_action_gets_its_own_request(self, service, binding):
        first = await service.request_approval(
            binding=binding(), presentation={}, reason="x")
        second = await service.request_approval(
            binding=binding(resource_id="loan-1001"), presentation={}, reason="x")
        assert first.approval_id != second.approval_id
