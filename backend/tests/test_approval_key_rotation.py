"""Phase 5.5 -- rotating the approval-signing key.

THE PHASE 5 GAP. `ensure()` refused to regenerate the key, because doing so
would have invalidated every artifact already issued. That instinct was right
and the conclusion was wrong: a signing key that can never change is a key you
can never respond to a suspicion about.

WHAT ROTATION HAS TO GET RIGHT, in both directions at once:

    artifact A, signed by key 1, before rotation  ->  STILL VERIFIES
    artifact B, signed by key 2, after rotation   ->  VERIFIES
    a NEW artifact claiming key 1 after retirement -> REFUSED
    a kid nobody registered                        -> REFUSED

Getting only the first right means "we cannot rotate without an outage".
Getting only the third right means "rotating destroys the audit trail". Both are
asserted below, on real Ed25519 signatures from a real KeyStore.

ROTATION IS NOT REVOCATION. Rotation retires a key and keeps its history valid.
Revocation says the key was never trustworthy and drops that history too. They
are separate operations with separate states, because conflating them forces a
choice between those two failures.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import get_settings
from app.core.errors import ConflictError
from app.db.models.hitl import ApprovalDecision, SigningKeyStatus
from app.hitl.artifact import ApprovalBinding, ArtifactReason, verify_artifact
from app.hitl.service import ApprovalService

pytestmark = pytest.mark.integration


class _Approver:
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
def binding(risk_agent):
    from app.authorization.contracts import AuthorizationRequest, Resource, Subject

    def make(application_id="loan-7842", **overrides):
        request = AuthorizationRequest(
            subject=Subject(did=risk_agent.did),
            action="approve_loan",
            resource=Resource(type="loan_applications", id=application_id),
            purpose="loan_decision",
            **overrides,
        )
        return ApprovalBinding.from_request(request)

    return make


@pytest.fixture
def sign_one(approval_service, approver):
    """Request and approve one loan, returning the signed record."""
    async def run(binding):
        record = await approval_service.request_approval(
            binding=binding, presentation={}, reason="SENSITIVE_ACTION_REQUIRES_HUMAN")
        return await approval_service.decide(
            record=record, approver=approver, decision=ApprovalDecision.APPROVED)
    return run


async def _verify(authority, record):
    principal = await authority.require()
    return verify_artifact(
        record.artifact,
        authority_document=principal.did_document,
        expected_binding=ApprovalBinding(**record.binding),
        expected_domain=get_settings().approval_domain,
        authority_keys=await authority.key_register(),
    )


class TestTheKeyRegister:
    async def test_the_first_key_is_registered_as_generation_one(
        self, approval_authority
    ):
        keys = await approval_authority.keys()
        assert len(keys) == 1
        assert keys[0].generation == 1
        assert keys[0].status is SigningKeyStatus.ACTIVE
        assert keys[0].retired_at is None

    async def test_the_register_never_holds_private_material(
        self, approval_authority
    ):
        """`keystore_ref` names WHERE the key lives. The key itself does not
        leave the KeyStore, so it cannot leave through here either."""
        import base64

        key = (await approval_authority.keys())[0]
        document = key.to_dict()
        assert document["private_key"] == "NEVER EXPOSED - held by the KeyStore"

        # The real assertion: the actual private key bytes appear nowhere in
        # the register row, in any encoding a leak would take.
        from cryptography.hazmat.primitives import serialization

        private = approval_authority.keystore._load_private_key(  # noqa: SLF001
            key.kid)
        secret = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        serialised = str(document) + str({
            c.name: getattr(key, c.name) for c in key.__table__.columns
        })
        assert base64.b64encode(secret).decode() not in serialised
        assert secret.hex() not in serialised
        # And the public key IS there, so the test is not passing vacuously.
        assert key.public_key_multibase in serialised

    async def test_signing_resolves_the_active_key_and_takes_no_key_id(
        self, approval_service
    ):
        """`_sign` has no parameter through which a caller could name a key.

        That absence is what makes "a retired key cannot issue" structural
        rather than a rule somebody has to remember.
        """
        import inspect

        parameters = list(inspect.signature(ApprovalService._sign).parameters)
        assert parameters == ["self", "record", "approver", "recorded", "now"]


class TestRotation:
    async def test_an_artifact_signed_before_rotation_still_verifies(
        self, approval_authority, approval_service, sign_one, binding
    ):
        """§9. The property that makes rotation possible at all."""
        before = await sign_one(binding("loan-7842"))
        assert (await _verify(approval_authority, before)).valid is True

        await approval_authority.rotate(reason="scheduled rotation")

        report = await _verify(approval_authority, before)
        assert report.valid is True, report.reason
        assert report.signing_key.endswith("#key-1")

    async def test_an_artifact_signed_after_rotation_verifies(
        self, approval_authority, sign_one, binding
    ):
        await approval_authority.rotate(reason="scheduled rotation")
        after = await sign_one(binding("loan-1001"))

        report = await _verify(approval_authority, after)
        assert report.valid is True, report.reason
        assert report.signing_key.endswith("#key-2")

    async def test_both_generations_verify_side_by_side(
        self, approval_authority, sign_one, binding
    ):
        """§9 in full: key A active, artifact A, rotate, key B active,
        artifact B -- and BOTH verify."""
        artifact_a = await sign_one(binding("loan-7842"))
        await approval_authority.rotate(reason="scheduled rotation")
        artifact_b = await sign_one(binding("loan-1001"))

        assert (await _verify(approval_authority, artifact_a)).valid is True
        assert (await _verify(approval_authority, artifact_b)).valid is True
        assert (artifact_a.artifact["proof"]["verificationMethod"]
                != artifact_b.artifact["proof"]["verificationMethod"])

    async def test_the_retired_key_cannot_issue_a_new_artifact(
        self, approval_authority, approval_service, binding, approver
    ):
        """The other half of §9. A key that was retired at T cannot have signed
        something created after T -- so an artifact claiming it is refused,
        while everything it really signed is untouched."""
        from app.hitl.artifact import proof_options_for, signing_bytes
        from app.identity.signer import Signer

        retired_kid = (await approval_authority.require_active_key()).kid
        await approval_authority.rotate(reason="suspected exposure")

        record = await approval_service.request_approval(
            binding=binding("loan-1001"), presentation={}, reason="x")
        record = await approval_service.decide(
            record=record, approver=approver, decision=ApprovalDecision.APPROVED)

        # Re-sign the SAME document with the retired key. The key material
        # still exists; what has changed is that it is no longer authorised.
        unsigned = {k: v for k, v in record.artifact.items() if k != "proof"}
        options = proof_options_for(unsigned, retired_kid)
        signature = Signer(approval_service.keystore).sign(
            retired_kid, signing_bytes(unsigned, options))
        forged = {**unsigned,
                  "proof": {**options, "signatureValue": signature.signature_b64}}

        principal = await approval_authority.require()
        report = verify_artifact(
            forged, authority_document=principal.did_document,
            expected_binding=ApprovalBinding(**record.binding),
            expected_domain=get_settings().approval_domain,
            authority_keys=await approval_authority.key_register(),
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.KEY_RETIRED

    async def test_the_retired_key_is_still_published(self, approval_authority):
        """A verifier needs the public key of whichever generation signed the
        artifact in front of it."""
        await approval_authority.rotate(reason="scheduled rotation")
        principal = await approval_authority.require()
        methods = {m["id"] for m in principal.did_document["verificationMethod"]}
        assert len(methods) == 2
        assert principal.did_document["serviceMetadata"][
            "activeVerificationMethod"] == principal.kid

    async def test_exactly_one_key_is_active_after_rotation(self, approval_authority):
        await approval_authority.rotate(reason="scheduled rotation")
        keys = await approval_authority.keys()
        active = [k for k in keys if k.status is SigningKeyStatus.ACTIVE]
        assert len(active) == 1
        assert active[0].generation == 2
        retired = [k for k in keys if k.status is SigningKeyStatus.RETIRED]
        assert len(retired) == 1 and retired[0].retired_at is not None

    async def test_rotation_is_audited_without_exposing_the_key(
        self, session, approval_authority
    ):
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        await approval_authority.rotate(reason="scheduled rotation",
                                        actor="did:poc:administrator:identity-authority")
        rows = (await session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "APPROVAL_KEY_ROTATED")
        )).scalars().all()
        assert len(rows) == 1
        metadata = rows[0].event_metadata
        assert metadata["retired_kid"].endswith("#key-1")
        assert metadata["active_kid"].endswith("#key-2")
        assert metadata["private_key_exposed"] is False
        assert metadata["actor"] == "did:poc:administrator:identity-authority"

    async def test_two_concurrent_rotations_produce_one_new_key(
        self, session, engine, approval_authority, keystore
    ):
        """The retirement is the atomic step.

        Two operators rotating at the same moment must produce ONE rotation and
        one refusal -- never two keys that both believe they are active, which
        would mean two keys able to sign and no way to say which was supposed
        to. A single conditional UPDATE decides, on real database connections.
        """
        import asyncio

        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.hitl.authority import ApprovalAuthority

        await session.commit()
        maker = async_sessionmaker(bind=engine, expire_on_commit=False)

        async def rotate(label):
            async with maker() as own:
                authority = ApprovalAuthority(own, keystore, get_settings())
                try:
                    await authority.rotate(reason=label)
                    await own.commit()
                    return "rotated"
                except Exception as exc:                       # noqa: BLE001
                    await own.rollback()
                    return type(exc).__name__

        outcomes = await asyncio.gather(rotate("a"), rotate("b"))
        assert outcomes.count("rotated") == 1, outcomes

        async with maker() as own:
            authority = ApprovalAuthority(own, keystore, get_settings())
            keys = await authority.keys()
            active = [k for k in keys if k.status is SigningKeyStatus.ACTIVE]
        assert len(keys) == 2
        assert len(active) == 1 and active[0].generation == 2


class TestUnknownAndRevokedKeys:
    async def test_an_unregistered_key_is_refused(
        self, approval_authority, sign_one, binding
    ):
        record = await sign_one(binding("loan-7842"))
        principal = await approval_authority.require()
        register = await approval_authority.key_register()
        register.pop(record.artifact["proof"]["verificationMethod"])

        report = verify_artifact(
            record.artifact, authority_document=principal.did_document,
            expected_binding=ApprovalBinding(**record.binding),
            expected_domain=get_settings().approval_domain,
            authority_keys=register,
        )
        assert report.valid is False
        assert report.reason == ArtifactReason.KEY_UNKNOWN

    async def test_revocation_invalidates_the_history_rotation_preserves(
        self, approval_authority, sign_one, binding
    ):
        """The distinction, asserted on the same artifact.

        After rotation it verifies. After the same key is REVOKED it does not:
        a compromised key's history is precisely what cannot be relied on.
        """
        record = await sign_one(binding("loan-7842"))
        kid = record.artifact["proof"]["verificationMethod"]

        await approval_authority.rotate(reason="scheduled rotation")
        assert (await _verify(approval_authority, record)).valid is True

        await approval_authority.revoke_key(kid, reason="key material exposed")
        report = await _verify(approval_authority, record)
        assert report.valid is False
        assert report.reason == ArtifactReason.KEY_REVOKED

    async def test_the_active_key_cannot_be_revoked_directly(
        self, approval_authority
    ):
        """Revoking it would leave the authority unable to sign anything."""
        active = await approval_authority.require_active_key()
        with pytest.raises(ConflictError) as raised:
            await approval_authority.revoke_key(active.kid, reason="oops")
        assert "Rotate first" in str(raised.value)

    async def test_a_revoked_key_is_unpublished(self, approval_authority):
        kid = (await approval_authority.require_active_key()).kid
        await approval_authority.rotate(reason="scheduled rotation")
        await approval_authority.revoke_key(kid, reason="exposed")
        principal = await approval_authority.require()
        published = {m["id"] for m in principal.did_document["verificationMethod"]}
        assert kid not in published


class TestTheSigningKeyCheckIsReported:
    async def test_the_signing_key_check_appears_in_the_report(
        self, approval_authority, sign_one, binding
    ):
        """Same discipline as every other check: never a bare boolean."""
        record = await sign_one(binding("loan-7842"))
        report = await _verify(approval_authority, record)
        names = [c.name for c in report.checks]
        assert names == ["present", "structure", "proof_purpose", "authority",
                         "signing_key", "verification_method", "signature",
                         "decision", "validity_window", "domain", "binding",
                         "approvers"]
        detail = next(c for c in report.checks if c.name == "signing_key").detail
        assert "ACTIVE" in detail


class TestNoOtherPrincipalHoldsTheKey:
    """§10. Who signs, and who demonstrably does not."""

    async def test_the_new_key_is_not_any_agent_or_issuer_key(
        self, approval_authority, risk_agent, issuers, session
    ):
        from sqlalchemy import select

        from app.db.models.agent import AgentKey
        from app.db.models.credential import IssuerIdentity

        await approval_authority.rotate(reason="scheduled rotation")
        authority_kids = {k.kid for k in await approval_authority.keys()}

        agent_kids = {
            k.kid for k in (await session.execute(select(AgentKey))).scalars().all()
        }
        issuer_kids = {
            i.kid for i in (await session.execute(select(IssuerIdentity))).scalars().all()
        }
        assert authority_kids.isdisjoint(agent_kids)
        assert authority_kids.isdisjoint(issuer_kids)

    async def test_the_approval_authority_holds_no_control_plane_roles(
        self, approval_authority
    ):
        """Signing approvals must never imply authority over policy."""
        principal = await approval_authority.require()
        assert list(principal.roles) == []
