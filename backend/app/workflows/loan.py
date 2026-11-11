"""The coordinator agent's loan workflow (blueprint steps 3-17).

Runs INSIDE the coordinator agent process, as the coordinator. Per workflow:

  3  claim the next workflow        protected tool, coordinator's own credential
  4  discover each specialist       ANS, by capability, endpoint cross-checked
                                    against the DID Document (coordinator.py)
  5  KYC                     kyc_verification          get_kyc_record
  6  risk assessment         affordability_assessment  assess_loan_risk
  7  credit analysis         credit_analysis           get_credit_profile
  8  document verification   document_verification     verify_loan_documents
  9  fraud detection         fraud_detection           get_fraud_signals
 10-12  each specialist calls the AEM with ITS OWN key; the PDP decides on
        ITS OWN verified credentials (app/workflows/peer.py)
 13  the decision agent records the outcome; policy escalates to humans by
     amount (and by trust), and the workflow PAUSES until they decide
 16  aggregate the findings
 17  record the outcome and a customer-facing message   protected tool

THE SCREENING RULES BELOW ARE NOT AUTHORIZATION. They decide whether the
findings support asking for an approval at all -- a business rule, stated
here so it is reviewable. Who may approve, and how many people must, is
decided by Rego and the HITL machinery, never here. No rule below can make
an approval happen: the strongest thing the coordinator can do is ask.

Failure is reported, never papered over: a specialist that cannot be
discovered, refuses an instruction, or is DENIED by the PDP makes the
workflow FAILED with the step and the reason, rather than a guessed result.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from app.agents.coordinator import CoordinationError, Coordinator
from app.core.logging import get_logger
from app.identity.signer import Signer
from app.workflows.peer import enforce_as_self, sign_instruction

log = get_logger("workflows.loan")

ASSESSMENT = "loan_assessment"
DECISION_PURPOSE = "loan_decision"
QUEUE = "loan-intake"


@dataclass(frozen=True)
class Step:
    name: str
    capability: str
    tool: str
    argument: str     # "customer_id" | "application_id"


PLAN = (
    Step("kyc", "kyc_verification", "get_kyc_record", "customer_id"),
    Step("risk_assessment", "affordability_assessment", "assess_loan_risk", "application_id"),
    Step("credit_analysis", "credit_analysis", "get_credit_profile", "customer_id"),
    Step("document_verification", "document_verification", "verify_loan_documents",
         "application_id"),
    Step("fraud_detection", "fraud_detection", "get_fraud_signals", "customer_id"),
)
DECISION = Step("decision", "loan_decision", "approve_loan_application", "application_id")

MIN_CREDIT_SCORE = 620


def screen(findings: dict[str, dict[str, Any]]) -> list[str]:
    """Reasons the findings do NOT support seeking approval. Empty = proceed."""
    reasons = []
    kyc = findings.get("kyc", {})
    if not kyc.get("identity_verified") or kyc.get("sanctions_hit"):
        reasons.append("KYC: identity not verified or sanctions match")
    if findings.get("fraud_detection", {}).get("signal_level") == "HIGH":
        reasons.append("Fraud: HIGH signal level")
    if not findings.get("document_verification", {}).get("complete"):
        missing = findings.get("document_verification", {}).get("missing")
        reasons.append(f"Documents incomplete: missing {missing}")
    if findings.get("risk_assessment", {}).get("affordability_band") in ("HIGH", "UNASSESSABLE"):
        reasons.append("Affordability: instalment too high for declared income")
    if (findings.get("credit_analysis", {}).get("credit_score") or 0) < MIN_CREDIT_SCORE:
        reasons.append(f"Credit: score below {MIN_CREDIT_SCORE}")
    return reasons


class LoanWorkflowRunner:
    def __init__(self, *, coordinator: Coordinator, iam: httpx.AsyncClient, signer: Signer,
                 did: str, kid: str, sessions=None) -> None:
        self.coordinator = coordinator
        self.iam = iam
        self.signer = signer
        self.did = did
        self.kid = kid
        self.http = httpx.AsyncClient(timeout=45.0)
        # Local view of the SSS push. When OUR session is locked out we stop
        # claiming work at once instead of waiting to be denied by the PDP.
        self.sessions = sessions
        self.refusals = 0

    # Phase 12. Back off after a REFUSED claim. Before this, a coordinator
    # whose credential had lapsed (1-hour demo TTL) retried every 5 s; 12
    # CREDENTIAL_EXPIRED denials a minute is exactly a DENIAL_BURST, so the
    # anomaly detector -- correctly -- collapsed its trust and contained it.
    # A refusal will not change by asking again five seconds later.
    MAX_REFUSAL_BACKOFF = 300.0
    refusals: int = 0

    def next_delay(self, interval: float) -> float:
        if self.refusals == 0:
            return interval
        return min(interval * (2 ** self.refusals), self.MAX_REFUSAL_BACKOFF)

    async def run_forever(self, stop: asyncio.Event, interval: float = 5.0) -> None:
        while not stop.is_set():
            try:
                worked = await self.run_once()
            except Exception as exc:  # noqa: BLE001 - must not kill the loop
                log.error("workflow_runner_error", error=f"{type(exc).__name__}: {exc}")
                worked = False
            if not worked:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.next_delay(interval))
                except asyncio.TimeoutError:
                    pass
        await self.http.aclose()

    async def _self(self, tool: str, arguments: dict[str, Any], **kw) -> dict[str, Any]:
        return await enforce_as_self(self.iam, self.signer, did=self.did, kid=self.kid,
                                     tool=tool, arguments=arguments, purpose=ASSESSMENT, **kw)

    async def run_once(self) -> bool:
        if self.sessions is not None and self.sessions.is_locked(self.did):
            return False
        claim = await self._self("claim_next_loan_workflow", {"queue": QUEUE})
        if not claim.get("executed"):
            reason = (claim.get("decision") or {}).get("reason")
            self.refusals += 1
            log.warning("workflow_claim_refused", reason=reason, refusals=self.refusals,
                        next_attempt_in_s=self.next_delay(5.0))
            return False
        self.refusals = 0
        workflow = (claim.get("result") or {}).get("workflow")
        if not workflow:
            return False
        application = claim["result"]["application"]
        log.info("workflow_claimed", workflow=workflow["workflow_id"],
                 resuming=workflow.get("resuming", False))
        decided = application.get("status")
        if decided in ("APPROVED", "DECLINED"):
            # RECOVERY (Phase 12). The decision already executed in the loan
            # management system, but the run that made it never recorded the
            # outcome (crash, restart, lost response). Record what happened;
            # never ask for the decision a second time.
            outcome = self._outcome(
                decided, workflow["steps"],
                {"summary": f"{decided.lower()} (recovered: the decision was already "
                            f"recorded by an earlier run)", "recovered": True},
                workflow.get("approval"),
                (f"Your loan of INR {application['amount_inr']:,} has been approved."
                 if decided == "APPROVED"
                 else "We are unable to offer this loan at this time."))
        elif workflow.get("resuming"):
            outcome = await self._decide(workflow, application, workflow["steps"],
                                         workflow.get("approval") or {})
        else:
            outcome = await self._assess(workflow, application)
        # Retried on a rate limit: an unrecorded outcome would leave the
        # workflow IN_PROGRESS until the stale-claim timeout reclaims it.
        for attempt in range(5):
            # The claim token is the lease's FENCING token: if this run was too
            # slow and the workflow was re-claimed, the store refuses this
            # record instead of letting it overwrite the newer run.
            recorded = await self._self("record_loan_workflow_outcome", {
                "workflow_id": workflow["workflow_id"], "coordinator": self.did,
                "claim_token": workflow.get("claim_token"), **outcome})
            if recorded.get("http_status") != 429:
                break
            await asyncio.sleep(2 ** attempt)
        if not recorded.get("executed"):
            log.error("workflow_record_refused", workflow=workflow["workflow_id"],
                      reason=(recorded.get("decision") or {}).get("reason"))
        return True

    # ------------------------------------------------------------- steps
    async def _assess(self, workflow: dict[str, Any], application: dict[str, Any]) -> dict[str, Any]:
        steps, findings = [], {}
        for step in PLAN:
            record = await self._delegate(step, application[step.argument], ASSESSMENT,
                                          request_id=f"{workflow['workflow_id']}-{step.name}")
            steps.append(record)
            if not record["executed"]:
                return self._outcome("FAILED", steps, {
                    "summary": f"step {step.name} did not complete: {record['reason']}",
                    "failed_step": step.name}, None,
                    "We could not complete the checks on your application. "
                    "A member of staff will contact you.")
            findings[step.name] = record["result"]
        reasons = screen(findings)
        if reasons:
            return self._outcome("DECLINED", steps, {
                "summary": "; ".join(reasons), "screening": reasons}, None,
                "We are unable to offer this loan at this time.")
        return await self._decide(workflow, application, steps, {})

    async def _decide(self, workflow, application, steps, approval) -> dict[str, Any]:
        request_id = approval.get("request_id") or f"{workflow['workflow_id']}-decision"
        record = await self._delegate(
            DECISION, application["application_id"], DECISION_PURPOSE, request_id=request_id,
            approval_id=approval.get("approval_id"),
            extra={"decision_note": f"workflow {workflow['workflow_id']}"})
        steps = [s for s in steps if s["step"] != "decision"] + [record]
        decision = record.get("decision") or "ERROR"
        if record["executed"]:
            return self._outcome("APPROVED", steps, {
                "summary": "approved", "policy": record.get("policy"),
                "reason": record.get("reason")}, approval or None,
                f"Your loan of INR {application['amount_inr']:,} has been approved.")
        if decision == "HUMAN_APPROVAL_REQUIRED":
            pending = record.get("approval_request") or {}
            return self._outcome("AWAITING_APPROVAL", steps, {
                "summary": f"awaiting human approval ({record.get('reason')})"}, {
                "approval_id": pending.get("approval_id") or approval.get("approval_id"),
                "required_approvals": pending.get("required_approvals"),
                "request_id": request_id},
                "Your application is with a loan officer for review.")
        if '"rate_limited"' in str(record.get("reason")) and approval:
            # Still rate limited after retries: stay paused and try again on
            # the next pass, rather than failing a workflow a human is deciding.
            return self._outcome("AWAITING_APPROVAL", steps, {
                "summary": "awaiting human approval (re-check deferred: rate limited)"},
                approval, "Your application is with a loan officer for review.")
        if record.get("reason") == "APPROVAL_REJECTED":
            return self._outcome("DECLINED", steps, {
                "summary": "a loan officer rejected the application"}, approval or None,
                "We are unable to offer this loan at this time.")
        return self._outcome("FAILED", steps, {
            "summary": f"decision refused: {record.get('reason')}", "failed_step": "decision"},
            approval or None, "We could not complete your application. Staff will contact you.")

    async def _delegate(self, step: Step, resource_id: str, purpose: str, *, request_id: str,
                        approval_id: str | None = None,
                        extra: dict[str, Any] | None = None) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        base = {"step": step.name, "capability": step.capability, "tool": step.tool,
                "started_at": started.isoformat()}
        try:
            outcome = await self.coordinator.coordinate(
                f"loan workflow step: {step.name}", capability=step.capability)
        except CoordinationError as exc:
            return {**base, "executed": False, "decision": "NOT_DISCOVERED", "reason": str(exc)}
        if not (outcome.selected and outcome.verified):
            return {**base, "executed": False, "decision": "NOT_DISCOVERED",
                    "reason": outcome.reason or "no verified provider"}
        agent_did, endpoint = outcome.selected["did"], outcome.selected["endpoint"]
        body = {"tool": step.tool, "purpose": purpose, "request_id": request_id,
                "arguments": {step.argument: resource_id, **(extra or {})}}
        if approval_id:
            body["approval_id"] = approval_id
        raw, headers = sign_instruction(self.signer, did=self.did, kid=self.kid,
                                        audience=agent_did, body=body)
        try:
            response = await self.http.post(f"{endpoint.rstrip('/')}/work",
                                            content=raw, headers=headers)
        except httpx.HTTPError as exc:
            return {**base, "agent_did": agent_did, "executed": False,
                    "decision": "UNREACHABLE", "reason": f"{type(exc).__name__}"}
        if response.status_code != 200:
            return {**base, "agent_did": agent_did, "executed": False,
                    "decision": "INSTRUCTION_REFUSED", "reason": response.text[:300]}
        result = response.json().get("enforcement") or {}
        decision = result.get("decision") or {}
        approval_request = (decision.get("evaluation") or {}).get("approval_request")
        return {**base, "agent_did": agent_did, "executed": bool(result.get("executed")),
                "decision": decision.get("decision"), "reason": decision.get("reason"),
                "policy": decision.get("policy_ref") or decision.get("policy"),
                "result": result.get("result") if result.get("executed") else None,
                "approval_request": approval_request,
                "finished_at": datetime.now(timezone.utc).isoformat()}

    @staticmethod
    def _outcome(status, steps, decision, approval, message) -> dict[str, Any]:
        return {"status": status, "steps": steps, "decision": decision,
                "approval": approval, "customer_message": message}
