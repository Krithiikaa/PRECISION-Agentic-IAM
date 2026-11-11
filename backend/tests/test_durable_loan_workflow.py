"""Phase 12: the loan workflow survives a restart and never repeats itself.

The defect: workflow state lived in process memory and vanished on restart,
and the claim was "atomic" only because one process held the dict.

A "restart" here is what a restart actually does to this code: committed
rows stay, process memory goes (`store.forget_cached_facts()`), and new
sessions read the database. Concurrency uses separate connections, so the
database -- not the event loop -- decides the winners.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.banking import store
from app.db.models.audit import AuditEvent
from app.db.models.loan import LoanApplicationRecord, LoanWorkflowRecord
from app.enforcement.resources import get_loan_application, material_attributes
from tests.test_loan_workflow import DOCS, InProcessRunner, crew  # noqa: F401  (fixture)

pytestmark = pytest.mark.integration

COORD_A, COORD_B = "did:poc:agent:coord-a", "did:poc:agent:coord-b"


@pytest.fixture(autouse=True)
def _forget():
    store.forget_cached_facts()
    yield
    store.forget_cached_facts()


@pytest.fixture
def maker(engine, session):          # `session` => tables truncated afterwards
    return async_sessionmaker(bind=engine, expire_on_commit=False)


async def _submit(s, amount=500_000, officer="loan.officer", key=None, docs=DOCS):
    body = {"amount": amount, "officer": officer}
    application, workflow, created = await store.submit(
        s, customer_id="customer-007", applicant_name="R. Applicant", amount_inr=amount,
        term_months=36, product="SECURED_PERSONAL_LOAN", declared_monthly_income_inr=200_000,
        submitted_by=officer, documents=docs, idempotency_key=key,
        request_digest=store.submission_digest(body) if key else None)
    return application, workflow, created


async def _committed_submit(maker, **kw):
    async with maker() as s:
        result = await _submit(s, **kw)
        await s.commit()
    return result


async def _expire(maker_or_session, workflow_id):
    stmt = update(LoanWorkflowRecord).where(LoanWorkflowRecord.workflow_id == workflow_id) \
        .values(lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    if isinstance(maker_or_session, async_sessionmaker):
        async with maker_or_session() as s:
            await s.execute(stmt)
            await s.commit()
    else:
        await maker_or_session.execute(stmt)


# --------------------------------------------------------------------------
class TestRestart:
    async def test_a_submitted_workflow_survives_a_restart(self, maker):
        application, workflow, _ = await _committed_submit(maker)
        store.forget_cached_facts()                    # the process is gone
        async with maker() as s:
            again = await store.get_workflow(s, workflow["workflow_id"])
            docs = await store.documents(s, application["application_id"])
        assert again["status"] == "SUBMITTED"
        assert {d["type"] for d in docs} == {d["type"] for d in DOCS}

    async def test_policy_facts_are_reloaded_from_the_database_after_a_restart(self, maker):
        application, _, _ = await _committed_submit(maker, amount=2_500_000)
        store.forget_cached_facts()
        attrs = material_attributes("loan_applications", application["application_id"])
        assert attrs == {"available": True, "amount_inr": 2_500_000, "currency": "INR",
                         "submitted_by": "loan.officer"}
        assert get_loan_application(application["application_id"])["status"] == \
            "AWAITING_DECISION"

    async def test_an_unknown_application_is_unavailable_never_defaulted(self):
        attrs = material_attributes("loan_applications", "loan-wdeadbeef")
        assert attrs["available"] is False and "amount_inr" not in attrs

    async def test_a_paused_approval_survives_a_restart_and_resumes(self, maker, monkeypatch):
        _, workflow, _ = await _committed_submit(maker, amount=2_500_000)
        async with maker() as s:
            claim = await store.claim_next(s, queue="loan-intake", request_id="r1",
                                           coordinator=COORD_A)
            await store.record_outcome(
                s, workflow_id=workflow["workflow_id"], status="AWAITING_APPROVAL",
                claim_token=claim["workflow"]["claim_token"], request_id="r1",
                approval={"approval_id": "approval-x", "request_id": "wf-decision"})
            await s.commit()
        store.forget_cached_facts()
        monkeypatch.setattr(store, "RESUME_AFTER_SECONDS", 0)
        async with maker() as s:
            resumed = await store.claim_next(s, queue="loan-intake", request_id="r2",
                                             coordinator=COORD_A)
            await s.commit()
        assert resumed["workflow"]["resuming"] is True
        assert resumed["workflow"]["approval"]["approval_id"] == "approval-x"

    async def test_maker_checker_still_holds_after_a_restart(
        self, maker, session, approval_service, risk_agent
    ):
        """Before Phase 12 a restart lost the application, so the officer of
        record was unknown -- and maker-checker only fires on a known one."""
        from app.hitl.artifact import ApprovalBinding
        from app.hitl.service import ApprovalDecision, SelfApprovalRefused
        from tests.test_phase12_containment import _Approver

        application, _, _ = await _committed_submit(maker, amount=2_500_000,
                                                    officer="loan.officer")
        store.forget_cached_facts()
        record = await approval_service.request_approval(
            binding=ApprovalBinding(request_id="wf-x-decision", agent_did=risk_agent.did,
                                    action="approve_loan", resource_type="loan_applications",
                                    resource_id=application["application_id"],
                                    purpose="loan_decision", amount_inr=2_500_000,
                                    currency="INR", submitted_by="loan.officer"),
            presentation={}, reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        with pytest.raises(SelfApprovalRefused):
            await approval_service.decide(record=record, approver=_Approver("loan.officer"),
                                          decision=ApprovalDecision.APPROVED)

    async def test_an_unreadable_officer_of_record_fails_closed(
        self, session, approval_service, risk_agent
    ):
        from app.hitl.artifact import ApprovalBinding
        from app.hitl.service import ApprovalDecision, SelfApprovalRefused
        from tests.test_phase12_containment import _Approver

        record = await approval_service.request_approval(
            binding=ApprovalBinding(request_id="wf-y-decision", agent_did=risk_agent.did,
                                    action="approve_loan", resource_type="loan_applications",
                                    resource_id="loan-wnotthere", purpose="loan_decision"),
            presentation={}, reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        with pytest.raises(SelfApprovalRefused, match="cannot be established"):
            await approval_service.decide(record=record, approver=_Approver("loan.officer.2"),
                                          decision=ApprovalDecision.APPROVED)


class TestConcurrency:
    async def test_two_coordinators_never_hold_the_same_workflow(self, maker):
        ids = {(await _committed_submit(maker))[1]["workflow_id"] for _ in range(6)}

        async def coordinator(did):
            got = []
            while True:
                async with maker() as s:
                    claim = await store.claim_next(s, queue="loan-intake", request_id=None,
                                                   coordinator=did)
                    await s.commit()
                if claim["workflow"] is None:
                    return got
                got.append(claim["workflow"]["workflow_id"])

        a, b, c = await asyncio.gather(coordinator(COORD_A), coordinator(COORD_B),
                                       coordinator("did:poc:agent:coord-c"))
        claimed = a + b + c
        assert sorted(claimed) == sorted(ids)          # every one, exactly once

    async def test_a_stale_run_cannot_overwrite_the_run_that_replaced_it(self, maker):
        _, workflow, _ = await _committed_submit(maker)
        wid = workflow["workflow_id"]
        async with maker() as s:
            first = await store.claim_next(s, queue="loan-intake", request_id="a",
                                           coordinator=COORD_A)
            await s.commit()
        await _expire(maker, wid)
        async with maker() as s:
            second = await store.claim_next(s, queue="loan-intake", request_id="b",
                                            coordinator=COORD_B)
            await s.commit()
        assert second["workflow"]["workflow_id"] == wid
        async with maker() as s:
            with pytest.raises(store.WorkflowConflict, match="stale or missing claim token"):
                await store.record_outcome(s, workflow_id=wid, status="APPROVED",
                                           claim_token=first["workflow"]["claim_token"],
                                           request_id="a")
        async with maker() as s:
            done = await store.record_outcome(s, workflow_id=wid, status="DECLINED",
                                              claim_token=second["workflow"]["claim_token"],
                                              request_id="b", decision={"summary": "x"})
            await s.commit()
        assert done["status"] == "DECLINED"

    async def test_concurrent_identical_records_apply_once(self, maker):
        _, workflow, _ = await _committed_submit(maker)
        wid = workflow["workflow_id"]
        async with maker() as s:
            claim = await store.claim_next(s, queue="loan-intake", request_id="a",
                                           coordinator=COORD_A)
            await s.commit()
        token = claim["workflow"]["claim_token"]

        async def record():
            async with maker() as s:
                out = await store.record_outcome(s, workflow_id=wid, status="FAILED",
                                                 claim_token=token, request_id="a",
                                                 decision={"summary": "failed"})
                await s.commit()
                return out

        results = await asyncio.gather(record(), record())
        assert sorted(bool(r.get("idempotent_replay")) for r in results) == [False, True]
        async with maker() as s:
            n = (await s.execute(select(func.count()).select_from(AuditEvent).where(
                AuditEvent.event_type == "LOAN_WORKFLOW_TRANSITION",
                AuditEvent.decision == "FAILED"))).scalar_one()
        assert n == 1


class TestIdempotencyAndAtMostOnce:
    async def test_recording_without_a_claim_is_refused(self, session):
        _, workflow, _ = await _submit(session)
        with pytest.raises(store.WorkflowConflict, match="not IN_PROGRESS"):
            await store.record_outcome(session, workflow_id=workflow["workflow_id"],
                                       status="APPROVED", claim_token="guess", request_id="x")

    async def test_a_terminal_workflow_cannot_be_reopened(self, session):
        _, workflow, _ = await _submit(session)
        claim = await store.claim_next(session, queue="loan-intake", request_id="a",
                                       coordinator=COORD_A)
        await store.record_outcome(session, workflow_id=workflow["workflow_id"],
                                   status="FAILED", claim_token=claim["workflow"]["claim_token"],
                                   request_id="a")
        with pytest.raises(store.WorkflowConflict, match="already FAILED"):
            await store.record_outcome(session, workflow_id=workflow["workflow_id"],
                                       status="APPROVED", claim_token="other", request_id="b")

    async def test_an_application_is_decided_at_most_once(self, session):
        application, _, _ = await _submit(session)
        await store.approve(session, application["application_id"], decision_note="1",
                            request_id="r1")
        with pytest.raises(store.WorkflowConflict, match="refusing a second decision"):
            await store.approve(session, application["application_id"], decision_note="2",
                                request_id="r2")

    async def test_a_repeated_submission_with_the_same_key_creates_nothing_new(self, session):
        a1, w1, created1 = await _submit(session, key="idem-1")
        a2, w2, created2 = await _submit(session, key="idem-1")
        assert created1 and not created2 and w1["workflow_id"] == w2["workflow_id"]
        assert (await session.execute(select(func.count()).select_from(
            LoanApplicationRecord))).scalar_one() == 1

    async def test_the_same_key_with_a_different_body_is_a_conflict(self, session):
        await _submit(session, key="idem-2", amount=100_000)
        with pytest.raises(store.WorkflowConflict, match="different submission"):
            await _submit(session, key="idem-2", amount=900_000)

    async def test_keys_are_scoped_per_officer(self, session):
        _, w1, _ = await _submit(session, key="shared", officer="loan.officer")
        _, w2, _ = await _submit(session, key="shared", officer="loan.officer.2")
        assert w1["workflow_id"] != w2["workflow_id"]

    async def test_reserved_argument_names_cannot_be_smuggled_to_a_durable_tool(
        self, session, aem, crew
    ):
        result = await aem.enforce(
            subject_did=crew["wf-coord"].did, tool_name="claim_next_loan_workflow",
            arguments={"queue": "loan-intake", "subject_did": "did:poc:agent:someone-else"},
            purpose="loan_assessment")
        assert result.executed is False and "reserved" in (result.error or "")

    async def test_the_recorded_coordinator_is_the_authenticated_caller(self, session, aem, crew):
        _, workflow, _ = await _submit(session)
        claim = await aem.enforce(subject_did=crew["wf-coord"].did,
                                  tool_name="claim_next_loan_workflow",
                                  arguments={"queue": "loan-intake"}, purpose="loan_assessment")
        record = await aem.enforce(
            subject_did=crew["wf-coord"].did, tool_name="record_loan_workflow_outcome",
            arguments={"workflow_id": workflow["workflow_id"], "status": "FAILED",
                       "claim_token": claim.result["workflow"]["claim_token"],
                       "coordinator": "did:poc:agent:framed"},
            purpose="loan_assessment")
        assert record.executed is False and "authenticated caller" in record.error


class TestRecoveryWithoutRepetition:
    async def test_an_interrupted_decision_is_recorded_not_repeated(
        self, session, aem, crew, opa_data_loaded
    ):
        """The run approved the loan, then died before recording the outcome."""
        _, workflow, _ = await _submit(session, amount=500_000)
        runner = InProcessRunner(aem, crew)
        claim = await aem.enforce(subject_did=crew["wf-coord"].did,
                                  tool_name="claim_next_loan_workflow",
                                  arguments={"queue": "loan-intake"}, purpose="loan_assessment")
        assert claim.executed
        decided = await aem.enforce(
            subject_did=crew["wf-decision"].did, tool_name="approve_loan_application",
            arguments={"application_id": workflow["application_id"]},
            purpose="loan_decision", request_id=f"{workflow['workflow_id']}-decision")
        assert decided.executed, decided.decision.reason
        # ...crash. The lease expires and the coordinator picks it up again.
        await _expire(session, workflow["workflow_id"])
        assert await runner.run_once() is True
        done = await store.get_workflow(session, workflow["workflow_id"])
        assert done["status"] == "APPROVED" and done["decision"]["recovered"] is True
        executed = (await session.execute(select(func.count()).select_from(AuditEvent).where(
            AuditEvent.event_type == "TOOL_EXECUTED",
            AuditEvent.resource == "loan_applications"))).scalar_one()
        assert executed == 1                          # the decision ran exactly once

    async def test_a_second_decision_through_the_aem_is_refused(
        self, session, aem, crew, opa_data_loaded
    ):
        _, workflow, _ = await _submit(session, amount=500_000)
        for attempt, expected in ((1, True), (2, False)):
            result = await aem.enforce(
                subject_did=crew["wf-decision"].did, tool_name="approve_loan_application",
                arguments={"application_id": workflow["application_id"]},
                purpose="loan_decision", request_id=f"dec-{attempt}")
            assert result.executed is expected, (attempt, result.error)

    async def test_a_failing_durable_tool_leaves_no_partial_write(self, session, aem, crew):
        _, workflow, _ = await _submit(session)
        claim = await aem.enforce(subject_did=crew["wf-coord"].did,
                                  tool_name="claim_next_loan_workflow",
                                  arguments={"queue": "loan-intake"}, purpose="loan_assessment")
        before = await store.get_workflow(session, workflow["workflow_id"])
        bad = await aem.enforce(
            subject_did=crew["wf-coord"].did, tool_name="record_loan_workflow_outcome",
            arguments={"workflow_id": workflow["workflow_id"], "status": "NOT_A_STATUS",
                       "claim_token": claim.result["workflow"]["claim_token"]},
            purpose="loan_assessment")
        assert bad.executed is False
        after = await store.get_workflow(session, workflow["workflow_id"])
        assert after["version"] == before["version"] and after["status"] == "IN_PROGRESS"


class TestAuditCorrelationAndAPI:
    async def test_every_transition_is_a_row_and_an_audit_event_with_the_request_id(
        self, session, aem, crew
    ):
        _, workflow, _ = await _submit(session)
        claim = await aem.enforce(subject_did=crew["wf-coord"].did,
                                  tool_name="claim_next_loan_workflow",
                                  arguments={"queue": "loan-intake"}, purpose="loan_assessment",
                                  request_id="claim-req-1")
        await aem.enforce(
            subject_did=crew["wf-coord"].did, tool_name="record_loan_workflow_outcome",
            arguments={"workflow_id": workflow["workflow_id"], "status": "FAILED",
                       "claim_token": claim.result["workflow"]["claim_token"],
                       "decision": {"summary": "test"}},
            purpose="loan_assessment", request_id="record-req-1")
        rows = await store.transitions(session, workflow["workflow_id"])
        assert [(r["from"], r["to"]) for r in rows] == [
            (None, "SUBMITTED"), ("SUBMITTED", "IN_PROGRESS"), ("IN_PROGRESS", "FAILED")]
        assert [r["request_id"] for r in rows[1:]] == ["claim-req-1", "record-req-1"]
        assert rows[1]["actor"] == crew["wf-coord"].did
        events = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == "LOAN_WORKFLOW_TRANSITION",
            AuditEvent.request_id == "record-req-1"))).scalars().all()
        assert len(events) == 1 and events[0].event_metadata["workflow_id"] == \
            workflow["workflow_id"]

    async def test_idempotent_submission_over_http(self, client, sign_control_plane,
                                                   control_plane, opa_ready):
        from app.controlplane.client import canonical_body
        body = {"customer_id": "customer-007", "applicant_name": "H. Applicant",
                "amount_inr": 300000, "term_months": 24, "declared_monthly_income_inr": 90000,
                "documents": DOCS}
        principal = "did:poc:administrator:core-banking"

        async def post(key, payload):
            headers = sign_control_plane(principal, method="POST", path="/api/v1/loan-workflows",
                                         body=payload)
            return await client.post("/api/v1/loan-workflows", content=canonical_body(payload),
                                     headers={**headers, "Content-Type": "application/json",
                                              "Idempotency-Key": key})

        first, again = await post("k-1", body), await post("k-1", body)
        assert first.status_code == 201 and again.status_code == 201
        assert first.json()["workflow_id"] == again.json()["workflow_id"]
        assert again.json()["idempotent_replay"] is True
        conflict = await post("k-1", {**body, "amount_inr": 999_000})
        assert conflict.status_code == 409

    async def test_transitions_require_loan_read(self, client, cp_get, session):
        _, workflow, _ = await _submit(session)
        path = f"/api/v1/loan-workflows/{workflow['workflow_id']}/transitions"
        assert (await client.get(path)).status_code == 401
        ok = await cp_get(path, "did:poc:administrator:core-banking")
        assert ok.status_code == 200, ok.text
        assert ok.json()[0]["to"] == "SUBMITTED"
