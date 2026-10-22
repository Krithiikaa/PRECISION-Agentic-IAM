"""The control-plane authentication MECHANISM, tested on its own.

The security matrix in test_control_plane_security_matrix.py asserts the
outcomes the spec requires. This file asserts the properties those outcomes
depend on -- what is signed, what the signature binds, and what the ledger
guarantees. If one of these breaks, the matrix could still pass while the
protection is hollow.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.controlplane.authenticator import ControlPlaneAuthenticator
from app.controlplane.client import canonical_body, control_plane_headers
from app.controlplane.principals import (
    KNOWN_ROLES,
    ControlPlanePrincipalRegistry,
    UnknownRoleError,
)
from app.controlplane.proof import (
    PROOF_PURPOSE,
    AuthReason,
    ControlPlanePayload,
    body_digest,
    timestamp_is_fresh,
)
from app.core.config import Settings, get_settings
from app.identity.signer import Signer

pytestmark = pytest.mark.integration


HEARTBEAT = "/api/v1/ans/heartbeat"


@pytest.fixture
def authenticate(session, keystore):
    """Run the authenticator directly, with genuinely signed headers."""
    async def run(principal_did, *, body=None, path=HEARTBEAT, method="POST",
                  operation="ans_heartbeat", kid=None, nonce=None, moment=None,
                  headers=None, sent_body=None, signing_kid=None):
        payload = canonical_body(body)
        built = headers if headers is not None else control_plane_headers(
            Signer(keystore), principal_did=principal_did,
            # `signing_kid` lets a test CLAIM a DID it holds no key for -- the
            # attacker's position. `kid` is what the caller advertises.
            kid=signing_kid or kid or f"{principal_did}#key-1",
            method=method, path=path,
            body=payload, nonce=nonce, moment=moment,
        )
        if signing_kid is not None:
            built["X-CP-Key-Id"] = kid or f"{principal_did}#key-1"
        return await ControlPlaneAuthenticator(session, get_settings()).authenticate(
            headers=built, method=method, path=path,
            body=canonical_body(sent_body) if sent_body is not None else payload,
            operation=operation, target=principal_did,
        )
    return run


class TestWhatIsSigned:
    def test_the_payload_binds_principal_operation_body_and_freshness(self):
        payload = ControlPlanePayload.build(
            principal="did:poc:agent:risk-001", method="post",
            path=HEARTBEAT, body=b'{"did":"x"}',
        )
        document = payload.to_dict()
        assert set(document) == {
            "principal", "method", "path", "body_sha256",
            "nonce", "timestamp", "proofPurpose",
        }
        # Uppercased so `post` and `POST` cannot produce two distinct proofs
        # for the same request.
        assert document["method"] == "POST"
        assert document["proofPurpose"] == PROOF_PURPOSE

    def test_the_proof_purpose_separates_it_from_every_other_proof(self):
        """Domain separation, stated as a test rather than a comment.

        This system has four Ed25519-over-canonical-JSON proof types. Because
        the purpose is INSIDE the signed bytes, a signature made for one can
        never verify as another.
        """
        from app.ans.proof import PROOF_PURPOSE as ANS_PURPOSE
        from app.credentials.vc import (
            CREDENTIAL_PROOF_PURPOSE,
            PRESENTATION_PROOF_PURPOSE,
        )

        purposes = {PROOF_PURPOSE, ANS_PURPOSE,
                    CREDENTIAL_PROOF_PURPOSE, PRESENTATION_PROOF_PURPOSE}
        assert len(purposes) == 4

    def test_canonicalisation_is_order_independent(self):
        """The agent and the server must agree regardless of field order."""
        a = ControlPlanePayload(principal="did:poc:agent:a", method="POST",
                                path="/x", body_sha256="d", nonce="n", timestamp="t")
        b = ControlPlanePayload(timestamp="t", nonce="n", body_sha256="d",
                                path="/x", method="POST", principal="did:poc:agent:a")
        assert a.signing_bytes() == b.signing_bytes()

    def test_an_empty_body_still_has_a_digest(self):
        """A bodyless POST is still bound; it is not exempt from the proof."""
        assert body_digest(b"") == body_digest(None)
        assert len(body_digest(b"")) == 64

    def test_freshness_is_bounded_in_both_directions(self):
        """A proof timestamped in the FUTURE is as suspicious as an old one.

        Accepting it would hand an attacker a proof valid for as long as they
        chose to post-date it.
        """
        now = datetime.now(timezone.utc)
        future = (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        past = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        assert timestamp_is_fresh(future, now=now, window_seconds=300)[0] is False
        assert timestamp_is_fresh(past, now=now, window_seconds=300)[0] is False
        assert timestamp_is_fresh(now.isoformat().replace("+00:00", "Z"),
                                  now=now, window_seconds=300)[0] is True


class TestBinding:
    async def test_a_valid_proof_authenticates(self, authenticate, risk_agent):
        result = await authenticate(risk_agent.did, body={"did": risk_agent.did})
        assert result.authenticated is True
        assert result.reason == AuthReason.VALID
        assert result.principal.type == "agent"
        assert result.principal.roles == ()

    async def test_a_swapped_body_is_refused(self, authenticate, risk_agent):
        """Sign one body, send another. This is the heartbeat DID-swap attack.

        An attacker who controls attacker-x could otherwise sign a proof for
        its own DID and post a body naming risk-001.
        """
        result = await authenticate(
            risk_agent.did,
            body={"did": risk_agent.did, "active_tasks": 0},
            sent_body={"did": "did:poc:agent:victim-001", "active_tasks": 99},
        )
        assert result.authenticated is False
        assert result.reason == AuthReason.SIGNATURE_INVALID

    async def test_the_signature_covers_the_path(self, session, keystore, risk_agent):
        signed_for = HEARTBEAT
        presented_at = f"/api/v1/ans/unregister/{risk_agent.did}"
        body = canonical_body({"did": risk_agent.did})
        headers = control_plane_headers(
            Signer(keystore), principal_did=risk_agent.did,
            kid=f"{risk_agent.did}#key-1", method="POST", path=signed_for, body=body,
        )
        result = await ControlPlaneAuthenticator(session, get_settings()).authenticate(
            headers=headers, method="POST", path=presented_at, body=body,
            operation="ans_deregister", target=risk_agent.did,
        )
        assert result.authenticated is False
        assert result.reason == AuthReason.SIGNATURE_INVALID

    async def test_the_signature_covers_the_method(self, session, keystore, risk_agent):
        body = canonical_body({"did": risk_agent.did})
        headers = control_plane_headers(
            Signer(keystore), principal_did=risk_agent.did,
            kid=f"{risk_agent.did}#key-1", method="POST", path=HEARTBEAT, body=body,
        )
        result = await ControlPlaneAuthenticator(session, get_settings()).authenticate(
            headers=headers, method="DELETE", path=HEARTBEAT, body=body,
            operation="ans_heartbeat", target=risk_agent.did,
        )
        assert result.authenticated is False

    async def test_a_key_id_the_caller_chose_is_not_honoured(
        self, authenticate, risk_agent, fraud_agent
    ):
        """A caller may TELL us which key it used; it does not get to pick one."""
        result = await authenticate(risk_agent.did, body={"did": risk_agent.did},
                                    kid=f"{fraud_agent.did}#key-1")
        assert result.authenticated is False
        assert result.reason == AuthReason.SIGNATURE_INVALID


class TestReplayLedger:
    async def test_a_nonce_is_single_use(self, session, keystore, risk_agent):
        body = canonical_body({"did": risk_agent.did})
        headers = control_plane_headers(
            Signer(keystore), principal_did=risk_agent.did,
            kid=f"{risk_agent.did}#key-1", method="POST", path=HEARTBEAT, body=body,
        )
        auth = ControlPlaneAuthenticator(session, get_settings())
        first = await auth.authenticate(headers=headers, method="POST", path=HEARTBEAT,
                                        body=body, operation="ans_heartbeat",
                                        target=risk_agent.did)
        assert first.authenticated is True

        second = await auth.authenticate(headers=headers, method="POST", path=HEARTBEAT,
                                         body=body, operation="ans_heartbeat",
                                         target=risk_agent.did)
        assert second.authenticated is False
        assert second.reason == AuthReason.NONCE_REPLAYED

    async def test_a_rejected_attempt_does_not_burn_the_nonce(
        self, session, keystore, risk_agent
    ):
        """An attacker must not be able to spend a legitimate agent's nonces.

        Only an ACCEPTED proof consumes one. If failures burned nonces, an
        attacker who could guess or observe them could lock an agent out of the
        registry by replaying garbage.
        """
        nonce = "a-nonce-worth-keeping"
        body = canonical_body({"did": risk_agent.did})
        forged = control_plane_headers(
            Signer(keystore), principal_did=risk_agent.did,
            kid=f"{risk_agent.did}#key-1", method="POST", path=HEARTBEAT, body=body,
            nonce=nonce,
        )
        forged["X-CP-Signature"] = "AAAA"          # not a valid signature

        auth = ControlPlaneAuthenticator(session, get_settings())
        bad = await auth.authenticate(headers=forged, method="POST", path=HEARTBEAT,
                                      body=body, operation="ans_heartbeat",
                                      target=risk_agent.did)
        assert bad.authenticated is False

        good = control_plane_headers(
            Signer(keystore), principal_did=risk_agent.did,
            kid=f"{risk_agent.did}#key-1", method="POST", path=HEARTBEAT, body=body,
            nonce=nonce,
        )
        result = await auth.authenticate(headers=good, method="POST", path=HEARTBEAT,
                                         body=body, operation="ans_heartbeat",
                                         target=risk_agent.did)
        assert result.authenticated is True

    async def test_the_ledger_records_refusals_as_well_as_acceptances(
        self, session, authenticate, risk_agent
    ):
        from sqlalchemy import select

        from app.db.models.controlplane import ControlPlaneProof

        await authenticate(risk_agent.did, body={"did": risk_agent.did})
        await authenticate("did:poc:agent:ghost-999", body={"did": "x"},
                           signing_kid=risk_agent.active_key.kid)

        rows = (await session.execute(select(ControlPlaneProof))).scalars().all()
        assert {r.accepted for r in rows} == {True, False}
        # The body is never stored; only its digest.
        assert all(len(r.body_sha256) == 64 for r in rows)

    async def test_no_secret_is_written_to_the_ledger(
        self, session, authenticate, risk_agent
    ):
        from sqlalchemy import select

        from app.db.models.controlplane import ControlPlaneProof

        await authenticate(risk_agent.did, body={"did": risk_agent.did,
                                                 "secret": "hunter2"})
        row = (await session.execute(select(ControlPlaneProof))).scalars().one()
        assert "hunter2" not in str(row.__dict__)


class TestPrincipalResolution:
    async def test_an_agent_carries_no_control_plane_roles(
        self, authenticate, risk_agent
    ):
        """There is no configuration that grants an agent administrative rights."""
        result = await authenticate(risk_agent.did, body={"did": risk_agent.did})
        assert result.principal.roles == ()

    async def test_an_unknown_did_does_not_resolve(self, authenticate, risk_agent):
        result = await authenticate("did:poc:agent:ghost-999", body={},
                                    signing_kid=risk_agent.active_key.kid)
        assert result.authenticated is False
        assert result.reason == AuthReason.PRINCIPAL_UNKNOWN

    async def test_a_dead_identity_cannot_speak_to_the_control_plane(
        self, authenticate, keystore, registry, risk_agent
    ):
        """A terminated agent must not be able to keep itself alive.

        The proof is built while the agent is still healthy and presented after
        termination -- the captured-proof case, and the one that matters. A
        signature that was genuine when it was made must stop working the
        moment the identity does.
        """
        body = canonical_body({"did": risk_agent.did})
        headers = control_plane_headers(
            Signer(keystore), principal_did=risk_agent.did,
            kid=risk_agent.active_key.kid, method="POST", path=HEARTBEAT, body=body,
        )
        await registry.terminate(risk_agent.did, "COMPROMISED")

        result = await authenticate(risk_agent.did, body={"did": risk_agent.did},
                                    headers=headers)
        assert result.authenticated is False
        assert result.reason == AuthReason.PRINCIPAL_NOT_ELIGIBLE

    async def test_a_did_of_no_recognised_kind_is_unknown(self, authenticate,
                                                          risk_agent):
        """An issuer DID is a real identity -- and not a control-plane principal."""
        result = await authenticate("did:poc:organization:bank-demo", body={},
                                    signing_kid=risk_agent.active_key.kid)
        assert result.authenticated is False
        assert result.reason == AuthReason.PRINCIPAL_UNKNOWN

    async def test_an_administrator_carries_its_granted_roles(
        self, authenticate, control_plane, policy_admin_did
    ):
        result = await authenticate(policy_admin_did, body={},
                                    operation="policy_activate")
        assert result.authenticated is True
        assert result.principal.type == "administrator"
        assert set(result.principal.roles) == {"policy_admin", "registry_admin"}

    async def test_a_suspended_administrator_is_refused(
        self, session, authenticate, control_plane, policy_admin_did
    ):
        from app.db.models.controlplane import PrincipalStatus

        principal = await control_plane.get_by_did(policy_admin_did)
        principal.status = PrincipalStatus.SUSPENDED
        await session.flush()

        result = await authenticate(policy_admin_did, body={},
                                    operation="policy_activate")
        assert result.authenticated is False
        assert result.reason == AuthReason.PRINCIPAL_NOT_ELIGIBLE


class TestPrincipalRegistry:
    async def test_administrators_get_their_own_key_and_did_document(
        self, control_plane, keystore, policy_admin_did
    ):
        principal = await control_plane.get_by_did(policy_admin_did)
        assert keystore.exists(principal.kid)
        assert principal.did_document["id"] == policy_admin_did
        # An administrator AUTHENTICATES; it does not ASSERT claims. Listing it
        # under assertionMethod would suggest it could sign credentials.
        assert "assertionMethod" not in principal.did_document
        assert principal.did_document["authentication"] == [principal.kid]

    async def test_no_administrator_holds_an_issuer_or_agent_key(
        self, control_plane, issuers, risk_agent, policy_admin_did
    ):
        """Separation of duties, asserted rather than assumed."""
        principal = await control_plane.get_by_did(policy_admin_did)
        issuer_keys = {i.kid for i in await issuers.list_issuers()}
        assert principal.kid not in issuer_keys
        assert principal.kid != risk_agent.active_key.kid

    async def test_bootstrap_is_idempotent(self, control_plane):
        before = {p.did for p in await control_plane.list_principals()}
        await control_plane.ensure_configured_principals()
        assert {p.did for p in await control_plane.list_principals()} == before

    async def test_roles_are_reconciled_from_configuration(
        self, session, control_plane, policy_admin_did
    ):
        """Revoking a privilege is a configuration change, not a database edit."""
        principal = await control_plane.get_by_did(policy_admin_did)
        principal.roles = ["policy_admin", "registry_admin", "identity_admin"]
        await session.flush()

        await control_plane.ensure_configured_principals()
        refreshed = await control_plane.get_by_did(policy_admin_did)
        assert refreshed.roles == ["policy_admin", "registry_admin"]
        assert refreshed.did_document["administratorMetadata"]["grantedRoles"] == [
            "policy_admin", "registry_admin",
        ]

    async def test_an_unknown_role_is_refused_at_bootstrap(self, session, keystore):
        """A typo must be an error, not a principal that silently does nothing."""
        settings = Settings(
            control_plane_administrators="typo-admin:Typo:policy-admin",
        )
        registry = ControlPlanePrincipalRegistry(session, keystore, settings)
        with pytest.raises(UnknownRoleError):
            await registry.ensure_configured_principals()

    async def test_a_principal_with_no_roles_is_kept_not_defaulted(
        self, session, keystore
    ):
        """No roles means no privileges -- never "assume the usual ones"."""
        settings = Settings(control_plane_administrators="watcher:Watcher")
        registry = ControlPlanePrincipalRegistry(session, keystore, settings)
        created = (await registry.ensure_configured_principals())[0]
        assert created.roles == []

    def test_every_configured_role_is_a_known_role(self):
        for _slug, _name, roles in get_settings().administrator_definitions:
            assert set(roles) <= KNOWN_ROLES


class TestFailClosedConfiguration:
    def test_control_plane_authentication_cannot_be_configured_off(self):
        """A switch that turns a proof requirement into a no-op is a bypass."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Settings(control_plane_authentication_required=False)
