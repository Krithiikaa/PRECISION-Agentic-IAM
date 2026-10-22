"""Phase 5.5 -- two-person control, and separation of duties.

    ONE PERSON APPROVING TWICE IS NOT TWO PEOPLE APPROVING.

That sentence is the whole file. Everything below is an attempt to make it
false, and an assertion that it stays true.

THREE INDEPENDENT REFUSALS, on purpose. Separation of duties failing quietly is
the failure nobody notices until an audit, so it is enforced at every layer that
could be reached:

    POLICY      cp-humans denies `approval_decide` to a human already on the
                sign-off list, and to the officer who submitted the application
    DATABASE    UNIQUE (approval_id, approver_issuer, approver_subject) --
                the layer that survives a race
    ARTIFACT    the verifier refuses a signed document naming one person twice,
                so a hand-built artifact cannot claim two approvals either

The database one is the load-bearing one. A check in Python is read-then-write:
two requests from the same person arriving together both find no existing row,
both pass, and the second approval is satisfied by the first person.
"""
from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import get_settings
from app.db.models.hitl import ApprovalDecision, ApprovalStatus
from app.hitl.artifact import ApprovalBinding, ArtifactReason, verify_artifact
from app.hitl.service import (
    ApprovalNotPending,
    ApprovalService,
    DuplicateApprover,
    SelfApprovalRefused,
)

pytestmark = pytest.mark.integration

DUAL = "loan-9001"          # Rs 2,00,00,000 -- above the single-approver limit
SINGLE = "loan-7842"        # Rs 25,00,000
SELF_SUBMITTED = "loan-5150"  # submitted_by: loan.officer


class _Approver:
    """A stand-in for an authenticated human, shaped like the real one.

    `subject` is derived from the username so two officers are genuinely two
    people: (issuer, subject) is the identity the whole mechanism turns on.
    """

    def __init__(self, username="loan.officer", roles=("LOAN_OFFICER",)):
        self.subject = f"sub-{username}"
        self.issuer = get_settings().keycloak_issuer
        self.username = username
        self.roles = roles
        self.provider = "keycloak-oidc"
        self.principal_urn = f"urn:iam:human:{self.subject}"


@pytest.fixture
def officer_a():
    return _Approver("loan.officer")


@pytest.fixture
def officer_b():
    return _Approver("loan.officer.2")


@pytest.fixture
def dual_binding(risk_agent):
    """A binding for the two-crore application, with its real amount."""
    from app.authorization.contracts import AuthorizationRequest, Resource, Subject

    def make(application_id=DUAL, **overrides):
        request = AuthorizationRequest(
            subject=Subject(did=overrides.pop("did", risk_agent.did)),
            action=overrides.pop("action", "approve_loan"),
            resource=Resource(type="loan_applications", id=application_id),
            purpose="loan_decision",
            **overrides,
        )
        return ApprovalBinding.from_request(request)

    return make


@pytest.fixture
async def dual_request(approval_service, dual_binding):
    """A PENDING approval that needs two distinct humans."""
    return await approval_service.request_approval(
        binding=dual_binding(), presentation={"demo": True},
        reason="DUAL_APPROVAL_REQUIRED", required_approvals=2,
    )


class TestOneSignOffIsNotEnough:
    async def test_the_first_sign_off_leaves_it_pending(
        self, approval_service, dual_request, officer_a
    ):
        """Still waiting on a human, which is exactly what PENDING means.

        No new state was introduced for "partially approved": the §14
        transition table is untouched and the count is a separate fact.
        """
        record = await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.APPROVED,
        )
        assert record.status is ApprovalStatus.PENDING
        assert record.required_approvals == 2
        assert len(await approval_service.signoffs(record.approval_id)) == 1

    async def test_nothing_is_signed_until_both_have_decided(
        self, approval_service, dual_request, officer_a
    ):
        """No artifact means nothing can be presented. A half-approved action
        has no evidence to offer the PDP, which is the correct shape: the
        absence is not a policy check that could be got wrong."""
        record = await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.APPROVED,
        )
        assert record.artifact is None
        assert record.artifact_signed_by is None

    async def test_the_second_distinct_human_completes_it(
        self, approval_service, dual_request, officer_a, officer_b
    ):
        await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.APPROVED)
        record = await approval_service.decide(
            record=dual_request, approver=officer_b,
            decision=ApprovalDecision.APPROVED)

        assert record.status is ApprovalStatus.APPROVED
        assert record.artifact is not None
        approvers = record.artifact["credentialSubject"]["approvers"]
        assert [a["username"] for a in approvers] == ["loan.officer", "loan.officer.2"]
        assert record.artifact["credentialSubject"]["requiredApprovals"] == 2

    async def test_the_artifact_is_signed_once_naming_both(
        self, approval_service, dual_request, officer_a, officer_b, approval_authority
    ):
        await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.APPROVED)
        record = await approval_service.decide(
            record=dual_request, approver=officer_b,
            decision=ApprovalDecision.APPROVED)

        principal = await approval_authority.require()
        report = verify_artifact(
            record.artifact,
            authority_document=principal.did_document,
            expected_binding=ApprovalBinding(**record.binding),
            expected_domain=get_settings().approval_domain,
            authority_keys=await approval_authority.key_register(),
        )
        assert report.valid is True
        assert report.distinct_approvers == 2
        assert report.required_approvals == 2


class TestTheSameHumanCannotSatisfyBoth:
    async def test_the_second_sign_off_by_the_same_human_is_refused(
        self, approval_service, dual_request, officer_a
    ):
        """§6. Human A approves; Human A attempts a second approval. DENY."""
        await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.APPROVED)

        with pytest.raises(DuplicateApprover) as raised:
            await approval_service.decide(
                record=dual_request, approver=officer_a,
                decision=ApprovalDecision.APPROVED)
        assert "two different people" in str(raised.value)
        assert dual_request.status is ApprovalStatus.PENDING

    async def test_a_lookalike_with_the_same_username_but_another_issuer_is_a_different_person(
        self, approval_service, dual_request, officer_a
    ):
        """Identity is (issuer, subject). Two realms can both mint the same
        username, and treating those as one person would be an identity
        confusion bug in the direction that BLOCKS a legitimate approver."""
        elsewhere = _Approver("loan.officer")
        elsewhere.issuer = "https://another-realm.invalid/realms/other"
        elsewhere.subject = "sub-loan.officer"

        await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.APPROVED)
        record = await approval_service.decide(
            record=dual_request, approver=elsewhere,
            decision=ApprovalDecision.APPROVED)
        assert record.status is ApprovalStatus.APPROVED

    async def test_the_database_refuses_it_even_without_the_service(
        self, session, dual_request, officer_a
    ):
        """The load-bearing refusal, asserted directly against the constraint.

        Everything above goes through the service. This asserts that the rule
        survives the service being bypassed, which is what makes it safe under
        a race rather than merely correct under sequential calls.
        """
        from datetime import datetime, timezone

        from sqlalchemy.exc import IntegrityError

        from app.db.models.hitl import ApprovalSignoff

        now = datetime.now(timezone.utc)

        def row(sequence):
            return ApprovalSignoff(
                approval_id=dual_request.approval_id, sequence=sequence,
                approver_subject=officer_a.subject,
                approver_issuer=officer_a.issuer,
                approver_username=officer_a.username,
                approver_roles=["LOAN_OFFICER"],
                decision=ApprovalDecision.APPROVED, decided_at=now,
            )

        session.add(row(1))
        await session.flush()
        session.add(row(2))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()

    async def test_a_forged_artifact_naming_one_person_twice_is_refused(
        self, approval_service, dual_binding, officer_a, officer_b,
        approval_authority, session
    ):
        """The third refusal. Even a correctly SIGNED artifact carrying the
        same human twice does not verify -- so an attacker who reached the
        signing path still cannot manufacture two-person approval from one
        person."""
        request = await approval_service.request_approval(
            binding=dual_binding(), presentation={}, reason="DUAL_APPROVAL_REQUIRED",
            required_approvals=2,
        )
        await approval_service.decide(record=request, approver=officer_a,
                                      decision=ApprovalDecision.APPROVED)
        record = await approval_service.decide(record=request, approver=officer_b,
                                               decision=ApprovalDecision.APPROVED)

        # Rewrite the second approver to be the first, and re-sign properly.
        from app.hitl.artifact import proof_options_for, signing_bytes
        from app.identity.signer import Signer

        forged = {k: v for k, v in record.artifact.items() if k != "proof"}
        subject = dict(forged["credentialSubject"])
        subject["approvers"] = [
            dict(subject["approvers"][0]),
            {**subject["approvers"][0], "sequence": 2},
        ]
        forged["credentialSubject"] = subject

        principal = await approval_authority.require()
        key = await approval_authority.require_active_key()
        options = proof_options_for(forged, key.kid)
        signature = Signer(approval_service.keystore).sign(
            key.kid, signing_bytes(forged, options))
        forged["proof"] = {**options, "signatureValue": signature.signature_b64}

        report = verify_artifact(
            forged, authority_document=principal.did_document,
            expected_binding=ApprovalBinding(**record.binding),
            expected_domain=get_settings().approval_domain,
            authority_keys=await approval_authority.key_register(),
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.APPROVERS_NOT_DISTINCT


class TestSelfApproval:
    """§7. Maker and checker are different people."""

    async def test_the_officer_who_submitted_it_cannot_sign_it_off(
        self, approval_service, dual_binding, officer_a
    ):
        request = await approval_service.request_approval(
            binding=dual_binding(SELF_SUBMITTED), presentation={},
            reason="SENSITIVE_ACTION_REQUIRES_HUMAN",
        )
        with pytest.raises(SelfApprovalRefused) as raised:
            await approval_service.decide(
                record=request, approver=officer_a,
                decision=ApprovalDecision.APPROVED)
        assert "maker and the checker must be different" in str(raised.value)
        assert request.status is ApprovalStatus.PENDING

    async def test_a_different_officer_may_sign_the_same_application_off(
        self, approval_service, dual_binding, officer_b
    ):
        """The rule refuses ONE person, not the application."""
        request = await approval_service.request_approval(
            binding=dual_binding(SELF_SUBMITTED), presentation={},
            reason="SENSITIVE_ACTION_REQUIRES_HUMAN",
        )
        record = await approval_service.decide(
            record=request, approver=officer_b,
            decision=ApprovalDecision.APPROVED)
        assert record.status is ApprovalStatus.APPROVED

    async def test_the_refusal_is_audited_as_self_approval(
        self, session, approval_service, dual_binding, officer_a
    ):
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        request = await approval_service.request_approval(
            binding=dual_binding(SELF_SUBMITTED), presentation={}, reason="x")
        with pytest.raises(SelfApprovalRefused):
            await approval_service.decide(
                record=request, approver=officer_a,
                decision=ApprovalDecision.APPROVED)

        rows = (await session.execute(
            select(AuditEvent).where(
                AuditEvent.event_type == "APPROVAL_SELF_APPROVAL_REJECTED")
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].event_metadata["submitted_by"] == "loan.officer"
        assert rows[0].event_metadata["approver_username"] == "loan.officer"


class TestRejectionEndsIt:
    async def test_one_rejection_ends_a_dual_control_request(
        self, approval_service, dual_request, officer_a, officer_b
    ):
        """Dual control means two people must AGREE. If a rejection merely
        failed to count, the request would stay open for somebody else to
        approve -- which turns it into 'ask until one of them says yes'."""
        record = await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.REJECTED)
        assert record.status is ApprovalStatus.REJECTED

        with pytest.raises(ApprovalNotPending):
            await approval_service.decide(
                record=record, approver=officer_b,
                decision=ApprovalDecision.APPROVED)

    async def test_a_rejection_after_one_approval_still_ends_it(
        self, approval_service, dual_request, officer_a, officer_b
    ):
        await approval_service.decide(
            record=dual_request, approver=officer_a,
            decision=ApprovalDecision.APPROVED)
        record = await approval_service.decide(
            record=dual_request, approver=officer_b,
            decision=ApprovalDecision.REJECTED)
        assert record.status is ApprovalStatus.REJECTED
        assert record.artifact is None


class TestConcurrency:
    """§15. The database arbitrates, not application memory."""

    async def test_only_one_of_two_concurrent_identical_sign_offs_wins(
        self, session, engine, dual_request, officer_a, keystore
    ):
        """The same human, three times, on separate database connections.

        Sequential calls would be settled by a Python check. These are not
        sequential: all three reach the INSERT, and the unique constraint
        decides. The request is committed first, because an uncommitted row is
        invisible to the other connections and all three would lose for the
        wrong reason.
        """
        await session.commit()
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def attempt():
            async with maker() as session:
                service = ApprovalService(session, keystore, get_settings())
                record = await service.require(dual_request.approval_id)
                try:
                    await service.decide(record=record, approver=officer_a,
                                         decision=ApprovalDecision.APPROVED)
                    await session.commit()
                    return "won"
                except Exception as exc:                      # noqa: BLE001
                    await session.rollback()
                    return type(exc).__name__

        outcomes = await asyncio.gather(*(attempt() for _ in range(3)))
        assert outcomes.count("won") == 1, outcomes

        # And the record reflects one sign-off, not three.
        async with maker() as own:
            signoffs = await ApprovalService(own).signoffs(dual_request.approval_id)
        assert len(signoffs) == 1

    async def test_two_distinct_humans_racing_produce_exactly_one_completion(
        self, session, engine, dual_request, officer_a, officer_b, keystore,
        approval_authority
    ):
        """Both sign-offs are legitimate and both must be recorded -- but only
        one of them completes the approval and signs. Two artifacts for one
        decision would mean two things to present."""
        await session.commit()
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def attempt(approver):
            async with maker() as session:
                service = ApprovalService(session, keystore, get_settings())
                record = await service.require(dual_request.approval_id)
                try:
                    result = await service.decide(
                        record=record, approver=approver,
                        decision=ApprovalDecision.APPROVED)
                    await session.commit()
                    return result.status.value, result.artifact is not None
                except Exception as exc:                      # noqa: BLE001
                    await session.rollback()
                    return type(exc).__name__, False

        outcomes = await asyncio.gather(attempt(officer_a), attempt(officer_b))
        signed = [o for o in outcomes if o[1]]
        assert len(signed) == 1, outcomes

        async with maker() as own:
            service = ApprovalService(own, keystore, get_settings())
            final = await service.require(dual_request.approval_id)
            signoffs = await service.signoffs(final.approval_id)

        # Both sign-offs recorded, exactly one artifact, and the approval
        # actually COMPLETED. The failure this guards against is not two
        # artifacts -- it is neither: two people signing concurrently, each
        # seeing only their own sign-off, and the approval being left with
        # every signature it needed and nothing to present.
        assert len(signoffs) == 2
        assert final.status is ApprovalStatus.APPROVED
        assert final.artifact is not None
        assert len(final.artifact["credentialSubject"]["approvers"]) == 2
