"""Trust & Risk Engine, anomaly detection, Session Authority and the kill switch.

CSA paper sections 4.2 (Layer 4), 5.3 and 5.4. The properties under test:

  * trust is DERIVED from recorded signals, explainable, and recovers
  * policy narrows on trust: REDUCED escalates sensitive actions, UNTRUSTED denies
  * a lockout in the SSS ledger denies the agent through the real PDP
  * only AUTHENTICATED events move trust; a forged claim cannot get a victim contained
  * the detector is idempotent across reruns
  * containment is TARGETED: the compromised agent stops, the others do not
  * reinstatement needs a different person and a written review
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update

from app.audit.service import AuditService
from app.authorization.contracts import AuthorizationRequest, Decision, Resource, Subject
from app.core.config import get_settings
from app.core.errors import ConflictError, ValidationError
from app.db.models.agent import AgentStatus
from app.db.models.security import (
    IncidentTrigger,
    SecurityAlert,
    SessionState,
    TrustLevel,
    TrustSignal,
)
from app.monitoring.events import Event, EventType
from app.sessions.authority import SessionAuthority
from app.sessions.sss import SessionStateSynchronizer
from app.trust.detector import AnomalyDetector
from app.trust.engine import TrustEngine

pytestmark = pytest.mark.integration

AUTONOMOUS_LOAN = "loan-2201"   # Rs 5,00,000: inside the agent's own band


@pytest.fixture
def trust(session):
    return TrustEngine(session, get_settings())


@pytest.fixture
def authority(session, keystore):
    return SessionAuthority(session, keystore, get_settings())


@pytest.fixture
def detector(session, keystore):
    return AnomalyDetector(session, keystore, get_settings())


def credit_read(did):
    return AuthorizationRequest(
        subject=Subject(did=did), action="read",
        resource=Resource(type="credit_records", id="customer-007"),
        purpose="loan_assessment")


def small_approval(did):
    return AuthorizationRequest(
        subject=Subject(did=did), action="approve_loan",
        resource=Resource(type="loan_applications", id=AUTONOMOUS_LOAN),
        purpose="loan_decision")


# --------------------------------------------------------------------------
class TestTrustEngine:
    async def test_an_agent_with_no_signals_is_fully_trusted(self, trust, risk_agent):
        a = await trust.assess(risk_agent.did)
        assert (a.score, a.level, a.active_signals) == (100, TrustLevel.TRUSTED, 0)

    async def test_score_is_100_minus_unexpired_signal_weights(self, trust, risk_agent):
        await trust.record_signal(risk_agent.did, "SCOPE_VIOLATION", 15)
        a = await trust.record_signal(risk_agent.did, "DENIAL_BURST", 25)
        assert a.score == 60
        assert a.level == TrustLevel.REDUCED
        assert a.changed_level

    async def test_bands_follow_configuration(self, trust, risk_agent):
        s = get_settings()
        assert trust.level_for(s.trust_reduced_below) == TrustLevel.TRUSTED
        assert trust.level_for(s.trust_reduced_below - 1) == TrustLevel.REDUCED
        assert trust.level_for(s.trust_untrusted_below - 1) == TrustLevel.UNTRUSTED

    async def test_score_never_goes_negative(self, trust, risk_agent):
        for _ in range(4):
            a = await trust.record_signal(risk_agent.did, "CREDENTIAL_REPLAY", 35)
        assert a.score == 0

    async def test_expired_signals_stop_counting(self, session, trust, risk_agent):
        await trust.record_signal(risk_agent.did, "SCOPE_VIOLATION", 50)
        await session.execute(update(TrustSignal).values(
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        a = await trust.assess(risk_agent.did)
        assert a.score == 100 and a.level == TrustLevel.TRUSTED

    async def test_a_signal_must_have_positive_weight(self, trust, risk_agent):
        with pytest.raises(ValueError):
            await trust.record_signal(risk_agent.did, "X", 0)

    async def test_every_point_is_explained_by_a_signal(self, trust, risk_agent):
        await trust.record_signal(risk_agent.did, "SCOPE_VIOLATION", 15, detail="payroll")
        signals = await trust.signals(risk_agent.did)
        assert [(s["signal_type"], s["weight"]) for s in signals] == [("SCOPE_VIOLATION", 15)]

    def test_inverted_bands_are_refused_at_startup(self):
        from app.core.config import Settings
        with pytest.raises(Exception, match="TRUST_UNTRUSTED_BELOW"):
            Settings(trust_reduced_below=40, trust_untrusted_below=50)


# --------------------------------------------------------------------------
class TestPolicyNarrowsOnTrustAndSession:
    async def test_pip_reports_trust_and_session(self, pdp, issued_credential, risk_agent):
        decision = await pdp.decide(credit_read(risk_agent.did))
        pip = decision.evaluation["pip"]
        assert pip["trust"]["level"] == "TRUSTED" and pip["trust"]["score"] == 100
        assert pip["session"]["state"] == "ACTIVE"

    async def test_a_trusted_agent_is_decided_exactly_as_before(
        self, pdp, issued_credential, risk_agent
    ):
        assert (await pdp.decide(credit_read(risk_agent.did))).decision is Decision.ALLOW

    async def test_untrusted_is_denied_even_with_a_valid_credential(
        self, pdp, trust, issued_credential, risk_agent
    ):
        await trust.record_signal(risk_agent.did, "CREDENTIAL_REPLAY", 70)
        decision = await pdp.decide(credit_read(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == "TRUST_TOO_LOW"

    async def test_reduced_trust_escalates_a_sensitive_action_inside_the_agent_band(
        self, pdp, trust, loan_credential, risk_agent, opa_data_loaded
    ):
        before = await pdp.decide(small_approval(risk_agent.did))
        assert before.decision is Decision.ALLOW   # within the agent's own band
        await trust.record_signal(risk_agent.did, "SCOPE_VIOLATION", 35)
        after = await pdp.decide(small_approval(risk_agent.did))
        assert after.decision is Decision.HUMAN_APPROVAL_REQUIRED
        assert after.reason == "REDUCED_TRUST_REQUIRES_HUMAN"

    async def test_reduced_trust_does_not_touch_non_sensitive_reads(
        self, pdp, trust, issued_credential, risk_agent
    ):
        await trust.record_signal(risk_agent.did, "SCOPE_VIOLATION", 35)
        assert (await pdp.decide(credit_read(risk_agent.did))).decision is Decision.ALLOW

    async def test_a_security_lockout_denies_through_the_real_pdp(
        self, session, pdp, issued_credential, risk_agent
    ):
        await SessionStateSynchronizer(session).set_state(
            risk_agent.did, SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT,
            reason="test", changed_by="test")
        decision = await pdp.decide(credit_read(risk_agent.did))
        assert decision.decision is Decision.DENY
        assert decision.reason == "SESSION_TERMINATED_SECURITY_LOCKOUT"

    async def test_trust_cannot_be_asserted_through_request_context(
        self, pdp, trust, issued_credential, risk_agent
    ):
        await trust.record_signal(risk_agent.did, "CREDENTIAL_REPLAY", 70)
        request = credit_read(risk_agent.did)
        request.context["trust_score"] = 100
        decision = await pdp.decide(request)
        assert decision.decision is Decision.DENY


# --------------------------------------------------------------------------
class TestDetector:
    async def test_a_real_scope_violation_becomes_a_trust_signal(
        self, aem, detector, trust, issued_credential, risk_agent
    ):
        blocked = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_payroll_record",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment")
        assert blocked.executed is False
        run = await detector.run_once()
        assert [a["rule"] for a in run.alerts] == ["SCOPE_VIOLATION"]
        assert (await trust.assess(risk_agent.did)).score == 85

    async def test_rerunning_does_not_double_count(
        self, aem, detector, trust, issued_credential, risk_agent
    ):
        await aem.enforce(subject_did=risk_agent.did, tool_name="get_payroll_record",
                          arguments={"customer_id": "customer-007"}, purpose="loan_assessment")
        first = await detector.run_once()
        second = await detector.run_once()
        # The second run reads only the detector's OWN output events, and skips them.
        assert len(first.alerts) == 1 and second.alerts == []
        assert (await trust.assess(risk_agent.did)).score == 85

    async def test_a_forged_identity_claim_alerts_but_never_moves_trust(
        self, session, detector, trust, risk_agent
    ):
        """The attribution rule. An unauthenticated request can NAME any DID;
        letting it lower that DID's trust would let an attacker get a victim
        contained by sending garbage in its name."""
        audit = AuditService(session)
        for _ in range(10):
            await audit.record(Event(EventType.SIGNATURE_INVALID, agent_did=risk_agent.did,
                                     reason="BAD_SIGNATURE"))
            await audit.record(Event(EventType.CONTROL_PLANE_REPLAY_DETECTED,
                                     agent_did=risk_agent.did))
        run = await detector.run_once()
        assert run.alerts and all(a["attributed"] is False for a in run.alerts)
        assert (await trust.assess(risk_agent.did)).score == 100
        assert run.contained == []

    async def test_a_denial_burst_degrades_to_reduced_and_updates_the_ledger(
        self, aem, session, detector, trust, issued_credential, risk_agent
    ):
        for _ in range(get_settings().anomaly_denial_burst_count):
            await aem.enforce(subject_did=risk_agent.did, tool_name="get_payroll_record",
                              arguments={"customer_id": "customer-007"},
                              purpose="loan_assessment")
        run = await detector.run_once()
        rules = sorted(a["rule"] for a in run.alerts)
        assert rules == ["DENIAL_BURST", "SCOPE_VIOLATION"]
        assessment = await trust.assess(risk_agent.did)
        assert assessment.level == TrustLevel.REDUCED
        state = await SessionStateSynchronizer(session).fact(risk_agent.did)
        assert state["state"] == "REDUCED_TRUST"

    async def test_trust_collapse_contains_only_the_offending_agent(
        self, aem, session, detector, issued_credential, risk_agent, fraud_agent, pdp
    ):
        for _ in range(get_settings().anomaly_denial_burst_count):
            await aem.enforce(subject_did=risk_agent.did, tool_name="get_payroll_record",
                              arguments={"customer_id": "customer-007"},
                              purpose="loan_assessment")
        await AuditService(session).record(Event(
            EventType.APPROVAL_REPLAY_REJECTED, agent_did=risk_agent.did))
        run = await detector.run_once()

        assert [r.agent_did for r in run.contained] == [risk_agent.did]
        report = run.contained[0]
        assert report.trigger == IncidentTrigger.AUTOMATED.value
        await session.refresh(risk_agent)
        await session.refresh(fraud_agent)
        assert risk_agent.status == AgentStatus.SUSPENDED
        assert fraud_agent.status == AgentStatus.ACTIVE       # untouched
        assert report.unaffected_active_agents >= 1
        denied = await pdp.decide(credit_read(risk_agent.did))
        assert denied.decision is Decision.DENY

    async def test_auto_containment_can_be_switched_off(
        self, session, keystore, issued_credential, risk_agent
    ):
        settings = get_settings().model_copy(update={"auto_containment_enabled": False})
        await TrustEngine(session, settings).record_signal(risk_agent.did, "X", 50)
        await AuditService(session).record(Event(
            EventType.APPROVAL_REPLAY_REJECTED, agent_did=risk_agent.did))
        run = await AnomalyDetector(session, keystore, settings).run_once()
        assert any(a["rule"] == "TRUST_COLLAPSE" for a in run.alerts)
        assert run.contained == []


# --------------------------------------------------------------------------
class TestSessionAuthority:
    async def test_containment_stops_the_agent_on_every_path(
        self, session, aem, authority, issued_credential, risk_agent, jit_service,
        issued_mandate, registered_risk_agent
    ):
        report = await authority.contain(
            risk_agent.did, justification="exfiltration suspected in SOC triage",
            opened_by="did:poc:administrator:identity-authority")
        actions = report.actions
        assert actions["session_state"]["state"] == "TERMINATED_IMMEDIATE_SECURITY_LOCKOUT"
        assert actions["identity"] == "SUSPENDED"
        assert actions["jit_grants_revoked"] == [issued_mandate.grant_id]
        assert actions["ans"] == "REVOKED"
        assert actions["credentials_revoked"] == []          # opt-in only

        blocked = await aem.enforce(
            subject_did=risk_agent.did, tool_name="get_credit_profile",
            arguments={"customer_id": "customer-007"}, purpose="loan_assessment")
        assert blocked.executed is False

    async def test_impact_is_frozen_into_the_incident(
        self, authority, issued_credential, risk_agent
    ):
        report = await authority.contain(
            risk_agent.did, justification="credential misuse under review",
            opened_by="did:poc:administrator:identity-authority")
        incident = await authority.get_incident(report.incident_id)
        creds = incident["containment"]["impact"]["reachable"]["active_credentials"]
        assert [c["credential_id"] for c in creds] == [issued_credential.credential_id]

    async def test_credentials_are_revoked_only_when_asked(
        self, session, authority, issued_credential, risk_agent, verifier
    ):
        report = await authority.contain(
            risk_agent.did, justification="key compromise confirmed by SOC",
            opened_by="did:poc:administrator:identity-authority", revoke_credentials=True)
        assert len(report.actions["credentials_revoked"]) == 1

    async def test_containing_twice_is_a_conflict(self, authority, risk_agent):
        await authority.contain(risk_agent.did, justification="first containment",
                                opened_by="ops-a")
        with pytest.raises(ConflictError):
            await authority.contain(risk_agent.did, justification="second containment",
                                    opened_by="ops-a")

    async def test_a_justification_is_required(self, authority, risk_agent):
        with pytest.raises(ValidationError):
            await authority.contain(risk_agent.did, justification="", opened_by="ops-a")

    async def test_children_are_contained_with_their_parent(
        self, session, registry, agent_spec, authority, risk_agent
    ):
        child = await registry.create_agent(agent_spec("child-of-risk"))
        child.parent_agent_id = risk_agent.id
        await registry.set_status(child.did, AgentStatus.ACTIVE)
        await session.flush()
        report = await authority.contain(risk_agent.did, justification="parent compromised",
                                         opened_by="ops-a")
        assert report.cascaded == [child.did]
        await session.refresh(child)
        assert child.status == AgentStatus.SUSPENDED

    async def test_reinstatement_requires_a_different_person(self, session, authority, risk_agent):
        report = await authority.contain(risk_agent.did, justification="suspicious activity",
                                         opened_by="ops-a")
        with pytest.raises(ConflictError, match="separation of duties"):
            await authority.reinstate(report.incident_id, reinstated_by="ops-a",
                                      review="reviewed logs; false positive from a test")
        refused = (await session.execute(select(SecurityAlert))).scalars().all()
        assert refused == []   # refusal is audited, not alerted

    async def test_reinstatement_requires_a_review(self, authority, risk_agent):
        report = await authority.contain(risk_agent.did, justification="suspicious activity",
                                         opened_by="ops-a")
        with pytest.raises(ConflictError, match="review"):
            await authority.reinstate(report.incident_id, reinstated_by="ops-b", review="ok")

    async def test_reinstatement_restores_access_and_retires_signals(
        self, session, authority, trust, pdp, issued_credential, risk_agent
    ):
        await trust.record_signal(risk_agent.did, "CREDENTIAL_REPLAY", 70)
        report = await authority.contain(risk_agent.did, justification="trust collapsed",
                                         opened_by="ops-a")
        assert (await pdp.decide(credit_read(risk_agent.did))).decision is Decision.DENY
        result, change = await authority.reinstate(
            report.incident_id, reinstated_by="ops-b",
            review="Reviewed the audit trail: the replays came from a misconfigured retry loop.")
        assert change.state == SessionState.ACTIVE
        assert result["signals_retired"] == 1
        await session.refresh(risk_agent)
        assert risk_agent.status == AgentStatus.ACTIVE
        assert (await pdp.decide(credit_read(risk_agent.did))).decision is Decision.ALLOW

    async def test_a_terminated_agent_cannot_be_reinstated(
        self, registry, authority, risk_agent
    ):
        report = await authority.contain(risk_agent.did, justification="key exfiltrated",
                                         opened_by="ops-a")
        await registry.terminate(risk_agent.did)
        with pytest.raises(ConflictError, match="TERMINATED"):
            await authority.reinstate(report.incident_id, reinstated_by="ops-b",
                                      review="terminated agents stay terminated forever")

    async def test_the_sss_version_strictly_increases(self, session, risk_agent):
        sss = SessionStateSynchronizer(session)
        a = await sss.set_state(risk_agent.did, SessionState.REDUCED_TRUST,
                                reason="x", changed_by="t")
        b = await sss.set_state(risk_agent.did, SessionState.ACTIVE, reason="y", changed_by="t")
        assert b.version == a.version + 1

    async def test_a_push_failure_is_reported_and_the_ledger_still_enforces(
        self, session, pdp, issued_credential, risk_agent
    ):
        settings = get_settings().model_copy(update={"redis_url": "redis://127.0.0.1:1/0"})
        sss = SessionStateSynchronizer(session, settings)
        change = await sss.set_state(
            risk_agent.did, SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT,
            reason="test", changed_by="t")
        push = await sss.publish(change)
        assert push["delivered"] is False
        assert (await pdp.decide(credit_read(risk_agent.did))).decision is Decision.DENY


# --------------------------------------------------------------------------
class TestSecurityAPI:
    async def test_reads_refuse_anonymous_callers(self, client):
        for path in ("/api/v1/security/trust", "/api/v1/security/alerts",
                     "/api/v1/security/incidents"):
            response = await client.get(path)
            assert response.status_code == 401, path

    async def test_the_identity_administrator_can_contain_over_http(
        self, admin_post, risk_agent
    ):
        response = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did,
            "justification": "contained from the SOC console during triage"})
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["actions"]["identity"] == "SUSPENDED"
        assert "sss_push" in body

    async def test_the_policy_administrator_may_not_contain(self, admin_post, risk_agent):
        response = await admin_post("/api/v1/security/incidents", {
            "agent_did": risk_agent.did, "justification": "not my role to do this"},
            principal="did:poc:administrator:platform-security")
        assert response.status_code == 403, response.text

    async def test_an_agent_may_not_contain_another_agent(
        self, agent_post, risk_agent, fraud_agent
    ):
        response = await agent_post("/api/v1/security/incidents", risk_agent.did, {
            "agent_did": fraud_agent.did, "justification": "agents do not run the SOC"})
        assert response.status_code == 403, response.text


# --------------------------------------------------------------------------
class TestDetectorDoesNotReplayHistory:
    """REGRESSION. The first live start read the entire historical audit
    trail -- months of DELIBERATE gate denials -- as fresh behaviour and
    automatically contained a healthy agent. Two layers now prevent it."""

    async def test_a_detector_switched_on_late_watches_from_that_moment(
        self, aem, detector, trust, issued_credential, risk_agent
    ):
        for _ in range(6):
            await aem.enforce(subject_did=risk_agent.did, tool_name="get_payroll_record",
                              arguments={"customer_id": "customer-007"},
                              purpose="loan_assessment")
        start = await detector.start_from_head()
        assert start is not None and start > 0
        run = await detector.run_once()
        assert run.alerts == []
        assert (await trust.assess(risk_agent.did)).score == 100

    async def test_start_from_head_never_moves_an_existing_cursor(self, detector, risk_agent):
        await detector.run_once()                     # creates the cursor
        assert await detector.start_from_head() is None

    async def test_events_older_than_the_signal_lifetime_raise_nothing(
        self, session, detector, trust, risk_agent
    ):
        from sqlalchemy import update as sql_update

        from app.db.models.audit import AuditEvent
        await AuditService(session).record(Event(
            EventType.APPROVAL_REPLAY_REJECTED, agent_did=risk_agent.did))
        old = datetime.now(timezone.utc) - timedelta(
            seconds=get_settings().trust_signal_ttl_seconds + 60)
        await session.execute(sql_update(AuditEvent).where(
            AuditEvent.event_type == EventType.APPROVAL_REPLAY_REJECTED).values(occurred_at=old))
        run = await detector.run_once()
        assert run.alerts == [] and run.stale_skipped == 1
        assert (await trust.assess(risk_agent.did)).score == 100

    async def test_a_signal_expires_relative_to_the_behaviour_not_the_detection(
        self, session, trust, risk_agent
    ):
        observed = datetime.now(timezone.utc) - timedelta(hours=1)
        await trust.record_signal(risk_agent.did, "SCOPE_VIOLATION", 15, observed_at=observed)
        signal = (await session.execute(select(TrustSignal))).scalar_one()
        assert signal.expires_at == observed + timedelta(
            seconds=get_settings().trust_signal_ttl_seconds)


class TestLocalSessionView:
    """The receiving end of the SSS push, as each agent runtime holds it."""

    def test_a_lockout_and_its_reversal_apply_in_version_order(self):
        from app.sessions.subscriber import LOCKOUT, LocalSessionView
        view = LocalSessionView()
        assert view.apply({"agent_did": "a", "state": LOCKOUT, "version": 2})
        assert view.is_locked("a")
        assert not view.apply({"agent_did": "a", "state": "ACTIVE", "version": 1})  # stale
        assert view.is_locked("a")
        assert view.apply({"agent_did": "a", "state": "ACTIVE", "version": 3})
        assert not view.is_locked("a")

    def test_malformed_messages_change_nothing(self):
        from app.sessions.subscriber import LocalSessionView
        view = LocalSessionView()
        assert not view.apply({"state": "TERMINATED_IMMEDIATE_SECURITY_LOCKOUT"})
        assert view.received == 0

    async def test_a_published_change_reaches_a_subscriber(self, session, risk_agent):
        import asyncio

        from app.sessions.subscriber import LocalSessionView, subscribe
        settings = get_settings().model_copy(update={"sss_channel": "agentic-iam:sss:test"})
        view, stop = LocalSessionView(), asyncio.Event()
        task = asyncio.create_task(subscribe(settings, view, stop))
        await asyncio.sleep(0.5)
        sss = SessionStateSynchronizer(session, settings)
        change = await sss.set_state(risk_agent.did,
                                     SessionState.TERMINATED_IMMEDIATE_SECURITY_LOCKOUT,
                                     reason="t", changed_by="t")
        push = await sss.publish(change)
        for _ in range(30):
            if view.is_locked(risk_agent.did):
                break
            await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(task, timeout=5)
        if not push["delivered"]:
            pytest.skip(f"Redis not reachable for the push test: {push}")
        assert view.is_locked(risk_agent.did)


class TestDisabledDetectionIsNotReplayed:
    """REGRESSION. The gate harness runs with detection off because the gates
    attack as risk-001 on purpose. Restoring the normal profile resumed the
    old cursor and contained risk-001 for traffic it was never meant to see."""

    async def attack(self, aem, risk_agent):
        for _ in range(6):
            await aem.enforce(subject_did=risk_agent.did, tool_name="get_payroll_record",
                              arguments={"customer_id": "customer-007"},
                              purpose="loan_assessment")

    async def test_a_window_with_detection_off_is_not_analysed_later(
        self, aem, detector, trust, issued_credential, risk_agent
    ):
        await detector.run_once()                 # an existing, live cursor
        await detector.suspend()                  # API started with detection off
        await self.attack(aem, risk_agent)        # gate traffic while off
        assert await detector.start_from_head() is not None   # detection back on
        run = await detector.run_once()
        assert run.alerts == []
        assert (await trust.assess(risk_agent.did)).score == 100

    async def test_a_suspended_cursor_never_processes_on_its_own(
        self, aem, detector, issued_credential, risk_agent
    ):
        await detector.suspend()
        await self.attack(aem, risk_agent)
        assert (await detector.run_once()).alerts == []

    async def test_a_crash_is_not_a_suspension_and_keeps_its_cursor(
        self, aem, detector, trust, issued_credential, risk_agent
    ):
        await detector.run_once()                 # live cursor, then "crash"
        await self.attack(aem, risk_agent)        # behaviour during the outage
        assert await detector.start_from_head() is None       # cursor kept
        run = await detector.run_once()
        assert {a["rule"] for a in run.alerts} >= {"SCOPE_VIOLATION", "DENIAL_BURST"}

    async def test_switching_detection_off_is_audited(self, session, detector):
        from app.db.models.audit import AuditEvent
        await detector.suspend()
        events = (await session.execute(select(AuditEvent).where(
            AuditEvent.event_type == EventType.ANOMALY_DETECTOR_DISABLED))).scalars().all()
        assert len(events) == 1


def test_the_suite_never_pushes_on_the_live_sss_channel():
    """REGRESSION (Phase 12). Test containments reached live agents' local
    session views because both used the default channel."""
    from app.core.config import Settings
    assert get_settings().sss_channel != Settings.model_fields["sss_channel"].default
