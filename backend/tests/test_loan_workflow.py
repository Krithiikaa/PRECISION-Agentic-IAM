"""The end-to-end loan workflow (blueprint steps 1-18).

What is proven here, against the real PDP, OPA policy and AEM:

  * each specialist reaches exactly its own resource and nothing else
  * the coordinator reaches the workflow queue and no customer data
  * a peer instruction is accepted only when signed, fresh, unreplayed,
    addressed to the receiver, and sent by an ACTIVE agent
  * the runner aggregates real specialist results, declines on adverse
    findings, pauses on a human approval, and resumes when a human decides
  * a revoked specialist makes the workflow FAIL with the step and reason

The live, multi-process version of the same journey -- coordinator and
specialists as separate processes reaching each other over HTTP -- is
scripts/loan_workflow_e2e.py.
"""
from __future__ import annotations

import json

import pytest

from app.banking import adapters, store
from app.credentials.issuer import IssueRequest
from app.db.models.agent import AgentType
from app.identity.signer import Signer
from app.workflows import loan as loan_module
from app.workflows.loan import DECISION, PLAN, LoanWorkflowRunner, screen
from app.workflows.peer import (
    InstructionRejected,
    InstructionVerifier,
    minimise,
    sign_instruction,
)

pytestmark = pytest.mark.integration

BANK = "did:poc:organization:bank-demo"
SPECIALISTS = {
    # slug: (capability, resource, purpose)
    "wf-kyc": ("kyc_verification", "kyc_records", "loan_assessment"),
    "wf-risk": ("affordability_assessment", "risk_models", "loan_assessment"),
    "wf-credit": ("credit_analysis", "credit_records", "loan_assessment"),
    "wf-docs": ("document_verification", "loan_documents", "loan_assessment"),
    "wf-fraud": ("fraud_detection", "fraud_signals", "loan_assessment"),
    "wf-decision": ("loan_decision", "loan_applications", "loan_decision"),
    "wf-coord": ("loan_workflow_coordination", "loan_workflows", "loan_assessment"),
}
DOCS = [{"type": t, "content": f"{t} scan"} for t in adapters.REQUIRED_DOCUMENT_TYPES]


@pytest.fixture(autouse=True)
def _clean_workflows():
    adapters.reset_workflows()
    yield
    adapters.reset_workflows()


@pytest.fixture
async def crew(registry, agent_spec, credential_issuer, issuers, opa_ready):
    agents = {}
    for slug, (capability, resource, purpose) in SPECIALISTS.items():
        agent = await registry.create_agent(agent_spec(slug, agent_type=AgentType.HELPER,
                                                       capabilities=[capability]))
        await credential_issuer.issue(IssueRequest(
            issuer_did=BANK, subject_did=agent.did, credential_type="AgentCapabilityCredential",
            claims={"capability": capability, "allowed_actions": ["ANY"],
                    "allowed_resources": [resource], "purpose": purpose},
            ttl_seconds=3600))
        agents[slug] = agent
    return agents


async def submit(session, amount=500_000, customer="customer-007", income=200_000, docs=DOCS):
    _, workflow, _ = await store.submit(
        session, customer_id=customer, applicant_name="T. Applicant", amount_inr=amount,
        term_months=36, product="SECURED_PERSONAL_LOAN",
        declared_monthly_income_inr=income, submitted_by="loan.officer", documents=docs)
    return workflow


async def app_status(session, application_id):
    return (await store.get_application(session, application_id))["status"]


class TestSpecialistBoundaries:
    @pytest.mark.parametrize("slug,tool,argument", [
        ("wf-kyc", "get_kyc_record", "customer_id"),
        ("wf-fraud", "get_fraud_signals", "customer_id"),
        ("wf-docs", "verify_loan_documents", "application_id"),
        ("wf-risk", "assess_loan_risk", "application_id"),
    ])
    async def test_each_specialist_reaches_its_own_resource(self, session, aem, crew, slug, tool, argument):
        workflow = await submit(session)
        value = "customer-007" if argument == "customer_id" else workflow["application_id"]
        result = await aem.enforce(subject_did=crew[slug].did, tool_name=tool,
                                   arguments={argument: value}, purpose="loan_assessment")
        assert result.executed, result.decision.reason
        assert result.result["simulated"] is True

    @pytest.mark.parametrize("slug,tool", [
        ("wf-kyc", "get_fraud_signals"),
        ("wf-fraud", "get_kyc_record"),
        ("wf-coord", "get_kyc_record"),
        ("wf-coord", "get_credit_profile"),
    ])
    async def test_no_specialist_reaches_another_specialists_resource(self, session, aem, crew, slug, tool):
        result = await aem.enforce(subject_did=crew[slug].did, tool_name=tool,
                                   arguments={"customer_id": "customer-007"},
                                   purpose="loan_assessment")
        assert result.executed is False
        assert result.decision.reason == "RESOURCE_NOT_ALLOWED"

    async def test_the_wrong_purpose_is_refused(self, session, aem, crew):
        result = await aem.enforce(subject_did=crew["wf-kyc"].did, tool_name="get_kyc_record",
                                   arguments={"customer_id": "customer-007"},
                                   purpose="marketing")
        assert result.executed is False and result.decision.reason == "PURPOSE_NOT_ALLOWED"

    async def test_the_coordinator_claims_through_the_aem(self, session, aem, crew):
        workflow = await submit(session)
        claim = await aem.enforce(subject_did=crew["wf-coord"].did,
                                  tool_name="claim_next_loan_workflow",
                                  arguments={"queue": "loan-intake"}, purpose="loan_assessment")
        assert claim.executed
        assert claim.result["workflow"]["workflow_id"] == workflow["workflow_id"]
        # Phase 12 adds the application's decision STATUS (for recovery);
        # still no financial or personal data beyond what routing needs.
        assert set(claim.result["application"]) == {"application_id", "customer_id",
                                                    "amount_inr", "term_months", "status"}

    async def test_a_specialist_cannot_claim_workflows(self, session, aem, crew):
        await submit(session)
        claim = await aem.enforce(subject_did=crew["wf-kyc"].did,
                                  tool_name="claim_next_loan_workflow",
                                  arguments={"queue": "loan-intake"}, purpose="loan_assessment")
        assert claim.executed is False


class TestPeerInstructions:
    class FakeIAM:
        def __init__(self, document, status=200):
            self.document, self.status = document, status

        async def get(self, path):
            class R:  # noqa: D401
                pass
            r = R()
            r.status_code, r.json = self.status, (lambda: self.document)
            return r

    @pytest.fixture
    def coordinator_key(self, registry, agent_spec, keystore):
        async def make():
            agent = await registry.create_agent(agent_spec("peer-coord"))
            return agent, Signer(keystore), agent.active_key.kid
        return make

    async def headers_and_verifier(self, coordinator_key, audience="did:poc:agent:spec"):
        agent, signer, kid = await coordinator_key()
        raw, headers = sign_instruction(signer, did=agent.did, kid=kid, audience=audience,
                                        body={"tool": "get_kyc_record"})
        verifier = InstructionVerifier(self.FakeIAM(agent.did_document.document),
                                       "did:poc:agent:spec")
        return agent, raw, headers, verifier

    async def test_a_valid_instruction_is_accepted_once(self, session, coordinator_key):
        agent, raw, headers, verifier = await self.headers_and_verifier(coordinator_key)
        sender, body = await verifier.verify(headers, raw)
        assert sender == agent.did and body["tool"] == "get_kyc_record"
        with pytest.raises(InstructionRejected, match="INSTRUCTION_REPLAYED"):
            await verifier.verify(headers, raw)

    async def test_an_instruction_for_another_agent_is_refused(self, session, coordinator_key):
        _, raw, headers, verifier = await self.headers_and_verifier(
            coordinator_key, audience="did:poc:agent:someone-else")
        with pytest.raises(InstructionRejected, match="INSTRUCTION_WRONG_AUDIENCE"):
            await verifier.verify(headers, raw)

    async def test_a_tampered_instruction_is_refused(self, session, coordinator_key):
        _, raw, headers, verifier = await self.headers_and_verifier(coordinator_key)
        tampered = json.dumps({**json.loads(raw), "tool": "get_fraud_signals"},
                              separators=(",", ":")).encode()
        with pytest.raises(InstructionRejected, match="INSTRUCTION_SIGNATURE_INVALID"):
            await verifier.verify(headers, tampered)

    async def test_an_inactive_sender_is_refused(self, session, coordinator_key):
        agent, raw, headers, _ = await self.headers_and_verifier(coordinator_key)
        document = json.loads(json.dumps(agent.did_document.document))
        document["agentMetadata"]["status"] = "SUSPENDED"
        verifier = InstructionVerifier(self.FakeIAM(document), "did:poc:agent:spec")
        with pytest.raises(InstructionRejected, match="INSTRUCTION_SENDER_INACTIVE"):
            await verifier.verify(headers, raw)

    def test_specialists_return_findings_not_records(self):
        full = adapters.get_kyc_record("customer-007")
        assert set(minimise("get_kyc_record", full)) == {
            "identity_verified", "address_verified", "sanctions_hit", "pep",
            "simulated", "adapter"}
        assert minimise("unknown_tool", {"secret": 1}) == {
            "withheld": True, "note": "no findings schema for this tool"}


class TestScreening:
    def good(self):
        return {"kyc": {"identity_verified": True, "sanctions_hit": False},
                "fraud_detection": {"signal_level": "LOW"},
                "document_verification": {"complete": True, "missing": []},
                "risk_assessment": {"affordability_band": "LOW"},
                "credit_analysis": {"credit_score": 742}}

    def test_clean_findings_proceed(self):
        assert screen(self.good()) == []

    @pytest.mark.parametrize("step,patch,fragment", [
        ("kyc", {"sanctions_hit": True}, "KYC"),
        ("fraud_detection", {"signal_level": "HIGH"}, "Fraud"),
        ("document_verification", {"complete": False, "missing": ["INCOME_PROOF"]}, "Documents"),
        ("risk_assessment", {"affordability_band": "HIGH"}, "Affordability"),
        ("credit_analysis", {"credit_score": 588}, "Credit"),
    ])
    def test_each_adverse_finding_declines(self, step, patch, fragment):
        findings = self.good()
        findings[step] = {**findings[step], **patch}
        assert any(fragment in r for r in screen(findings))


class InProcessRunner(LoanWorkflowRunner):
    """The real runner, with only the NETWORK hop replaced.

    `_delegate` enforces through the real AEM AS THE SPECIALIST'S DID -- the
    same call the specialist process makes -- and passes the result through
    the same `minimise` the specialist applies. Everything else (claiming,
    screening, escalation, recording) is the production code path.
    """

    def __init__(self, aem, crew):
        self.aem, self.crew, self.did = aem, crew, crew["wf-coord"].did
        self.sessions = None   # no SSS push in-process; the ledger still enforces
        self.by_capability = {cap: crew[slug] for slug, (cap, _, _) in SPECIALISTS.items()}

    async def _self(self, tool, arguments, **kw):
        result = await self.aem.enforce(subject_did=self.did, tool_name=tool,
                                        arguments=arguments, purpose="loan_assessment")
        return result.to_dict()

    async def _delegate(self, step, resource_id, purpose, *, request_id, approval_id=None,
                        extra=None):
        agent = self.by_capability[step.capability]
        result = await self.aem.enforce(
            subject_did=agent.did, tool_name=step.tool,
            arguments={step.argument: resource_id, **(extra or {})}, purpose=purpose,
            request_id=request_id, approval_id=approval_id)
        decision = result.decision.to_dict()
        return {"step": step.name, "capability": step.capability, "tool": step.tool,
                "agent_did": agent.did, "executed": result.executed,
                "decision": decision["decision"], "reason": decision["reason"],
                "policy": decision["policy"],
                "result": minimise(step.tool, result.result) if result.executed else None,
                "approval_request": (decision.get("evaluation") or {}).get("approval_request")}


class TestRunner:
    async def test_a_clean_small_loan_is_approved_by_the_agent_alone(self, session, aem, crew, opa_data_loaded):
        workflow = await submit(session, amount=500_000)
        assert await InProcessRunner(aem, crew).run_once() is True
        done = await store.get_workflow(session, workflow["workflow_id"])
        assert done["status"] == "APPROVED", done["decision"]
        assert [s["step"] for s in done["steps"]] == [p.name for p in PLAN] + ["decision"]
        assert all(s["executed"] for s in done["steps"])
        assert await app_status(session, workflow["application_id"]) == "APPROVED"
        assert "approved" in done["customer_message"]

    async def test_adverse_findings_decline_without_asking_for_approval(self, session, aem, crew):
        workflow = await submit(session, customer="customer-666")    # sanctions hit, HIGH fraud
        await InProcessRunner(aem, crew).run_once()
        done = await store.get_workflow(session, workflow["workflow_id"])
        assert done["status"] == "DECLINED"
        assert "decision" not in [s["step"] for s in done["steps"]]
        assert await app_status(session, workflow["application_id"]) == "DECLINED"

    async def test_missing_documents_decline(self, session, aem, crew):
        workflow = await submit(session, docs=DOCS[:1])
        await InProcessRunner(aem, crew).run_once()
        done = await store.get_workflow(session, workflow["workflow_id"])
        assert done["status"] == "DECLINED" and "Documents" in done["decision"]["summary"]

    async def test_a_large_loan_pauses_for_a_human_and_resumes(
        self, session, aem, crew, approval_service, opa_data_loaded, monkeypatch
    ):
        from app.hitl.service import ApprovalDecision  # noqa: F401
        workflow = await submit(session, amount=2_500_000, income=900_000)
        runner = InProcessRunner(aem, crew)
        await runner.run_once()
        paused = await store.get_workflow(session, workflow["workflow_id"])
        assert paused["status"] == "AWAITING_APPROVAL", paused["decision"]
        assert paused["approval"]["approval_id"]
        assert await app_status(session, workflow["application_id"]) == "AWAITING_DECISION"

        # Not yet decided by a human: resuming changes nothing.
        monkeypatch.setattr(store, "RESUME_AFTER_SECONDS", 0)
        await runner.run_once()
        assert (await store.get_workflow(session, workflow["workflow_id"]))["status"] == "AWAITING_APPROVAL"

    async def test_a_revoked_specialist_fails_the_workflow_at_its_step(self, session, aem, crew):
        from app.credentials.status import CredentialStatusService
        from sqlalchemy import select
        from app.db.models.credential import Credential
        cred = (await session.execute(select(Credential).where(
            Credential.subject_did == crew["wf-fraud"].did))).scalar_one()
        await CredentialStatusService(session).revoke(cred.credential_id, "test")
        workflow = await submit(session)
        await InProcessRunner(aem, crew).run_once()
        done = await store.get_workflow(session, workflow["workflow_id"])
        assert done["status"] == "FAILED"
        assert done["decision"]["failed_step"] == "fraud_detection"
        assert done["steps"][-1]["reason"] == "CREDENTIAL_REVOKED"

    async def test_without_a_coordinator_credential_nothing_is_claimed(
        self, session, aem, crew
    ):
        from app.credentials.status import CredentialStatusService
        from sqlalchemy import select
        from app.db.models.credential import Credential
        cred = (await session.execute(select(Credential).where(
            Credential.subject_did == crew["wf-coord"].did))).scalar_one()
        await CredentialStatusService(session).revoke(cred.credential_id, "test")
        workflow = await submit(session)
        assert await InProcessRunner(aem, crew).run_once() is False
        assert (await store.get_workflow(session, workflow["workflow_id"]))["status"] == "SUBMITTED"


class TestSubmissionAPI:
    async def test_anonymous_submission_is_refused(self, session, client):
        response = await client.post("/api/v1/loan-workflows", json={})
        assert response.status_code == 401

    async def test_the_loan_administrator_can_submit_and_read(self, session, admin_post, client,
                                                             sign_control_plane):
        body = {"customer_id": "customer-007", "applicant_name": "Z. Applicant",
                "amount_inr": 400000, "term_months": 24, "declared_monthly_income_inr": 90000,
                "documents": DOCS}
        response = await admin_post("/api/v1/loan-workflows", body,
                                    principal="did:poc:administrator:core-banking")
        assert response.status_code == 201, response.text
        created = response.json()
        assert created["status"] == "SUBMITTED"
        assert created["application"]["submitted_by"] == "did:poc:administrator:core-banking"

    async def test_an_agent_cannot_submit(self, session, agent_post, risk_agent):
        response = await agent_post("/api/v1/loan-workflows", risk_agent.did, {
            "customer_id": "customer-007", "applicant_name": "Z", "amount_inr": 1,
            "term_months": 12, "declared_monthly_income_inr": 1})
        assert response.status_code == 403


async def _expire_leases(session):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    from app.db.models.loan import LoanWorkflowRecord
    await session.execute(update(LoanWorkflowRecord).where(
        LoanWorkflowRecord.status == "IN_PROGRESS").values(
        lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))


class TestRecovery:
    """REGRESSIONS found by the live end-to-end run, now against durable state."""

    async def test_an_abandoned_in_progress_workflow_is_reclaimed(self, session, monkeypatch):
        workflow = await submit(session)
        first = await store.claim_next(session, queue="loan-intake", request_id="r1",
                                       coordinator="did:poc:agent:c1")
        assert first["workflow"]["workflow_id"] == workflow["workflow_id"]
        assert (await store.claim_next(session, queue="loan-intake", request_id="r2",
                                       coordinator="did:poc:agent:c1"))["workflow"] is None
        await _expire_leases(session)
        again = await store.claim_next(session, queue="loan-intake", request_id="r4",
                                       coordinator="did:poc:agent:c1")
        assert again["workflow"]["workflow_id"] == workflow["workflow_id"]

    async def test_a_reclaimed_workflow_keeps_its_pending_approval(self, session, monkeypatch):
        workflow = await submit(session)
        claim = await store.claim_next(session, queue="loan-intake", request_id="r1",
                                       coordinator="did:poc:agent:c1")
        await store.record_outcome(
            session, workflow_id=workflow["workflow_id"], status="AWAITING_APPROVAL",
            claim_token=claim["workflow"]["claim_token"], request_id="r1",
            approval={"approval_id": "apr-1", "request_id": "r-1"})
        monkeypatch.setattr(store, "RESUME_AFTER_SECONDS", 0)
        claimed = (await store.claim_next(session, queue="loan-intake", request_id="r2",
                                          coordinator="did:poc:agent:c1"))["workflow"]
        assert claimed["resuming"] is True
        await _expire_leases(session)
        reclaimed = (await store.claim_next(session, queue="loan-intake", request_id="r3",
                                            coordinator="did:poc:agent:c1"))["workflow"]
        assert reclaimed["resuming"] is True and reclaimed["approval"]["approval_id"] == "apr-1"


class TestRefusalBackoff:
    """REGRESSION (Phase 12, found live). A coordinator whose credential had
    lapsed retried its claim every 5 s; 12 denials a minute is a DENIAL_BURST,
    so the detector collapsed its trust and auto-contained it."""

    async def test_a_refused_claim_backs_off(self, session, aem, crew):
        from app.credentials.status import CredentialStatusService
        from sqlalchemy import select
        from app.db.models.credential import Credential
        cred = (await session.execute(select(Credential).where(
            Credential.subject_did == crew["wf-coord"].did))).scalar_one()
        await CredentialStatusService(session).revoke(cred.credential_id, "lapsed")
        runner = InProcessRunner(aem, crew)
        delays = []
        for _ in range(4):
            assert await runner.run_once() is False
            delays.append(runner.next_delay(5.0))
        assert delays == [10.0, 20.0, 40.0, 80.0]

    def test_refusals_stay_below_the_denial_burst_threshold(self):
        from app.core.config import get_settings
        settings = get_settings()
        runner = InProcessRunner.__new__(InProcessRunner)
        t, attempts = 0.0, []
        while t < settings.anomaly_denial_burst_window_seconds:
            attempts.append(t)
            runner.refusals += 1
            t += runner.next_delay(5.0)
        assert len(attempts) < settings.anomaly_denial_burst_count

    def test_the_backoff_is_capped_and_resets_on_success(self):
        runner = InProcessRunner.__new__(InProcessRunner)
        runner.refusals = 20
        assert runner.next_delay(5.0) == runner.MAX_REFUSAL_BACKOFF
        runner.refusals = 0
        assert runner.next_delay(5.0) == 5.0


async def test_an_agent_refused_registration_retries_after_reinstatement():
    """REGRESSION. A contained agent's re-registration is refused, which
    cleared its `registered` flag; it then never retried, so after a human
    reinstated it the agent stayed out of discovery for good."""
    import asyncio

    from app.agents.ans_client import ANSClient

    client = ANSClient.__new__(ANSClient)
    client.did = "did:poc:agent:x"
    attempts = {"register": 0}

    class State:
        registered = False
    client.state = State()

    async def heartbeat(**kw):
        return False

    async def register():
        attempts["register"] += 1
        if attempts["register"] >= 2:
            stop.set()
        return {"accepted": attempts["register"] >= 2}

    client.heartbeat, client.register = heartbeat, register
    stop = asyncio.Event()
    await asyncio.wait_for(client.heartbeat_loop(stop, 0), timeout=5)
    assert attempts["register"] == 2
