"""Rotating the key that signs mandates.

The property under test is the one that makes rotation usable at all: a key
that stops signing must keep VERIFYING what it already signed. Get that wrong
in either direction and you have either "we cannot rotate without an outage" or
"a retired key keeps working".

Rotation and revocation are deliberately different operations with different
consequences, and the tests assert the difference rather than assuming it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.errors import ConflictError, NotFoundError
from app.db.models.hitl import SigningKeyStatus
from app.identity.signer import Signer
from app.jit.grant import (
    GrantReason,
    build_grant,
    new_grant_id,
    new_nonce,
    sign_grant,
    verify_grant,
)

pytestmark = pytest.mark.integration

DOMAIN = "agentic-iam-aem"


async def _sign_with(jit_authority, keystore, binding, kid, *, moment=None):
    moment = moment or datetime.now(timezone.utc)
    document = build_grant(
        grant_id=new_grant_id(), binding=binding, issued_at=moment,
        not_before=moment, expires_at=moment + timedelta(seconds=600),
        max_uses=1, nonce=new_nonce(), domain=DOMAIN,
        authority_did=jit_authority.did, issuing_request_id="authz-test",
        justification={},
    )
    return sign_grant(document, Signer(keystore), kid, moment=moment)


async def _verify(grant, jit_authority, binding, **kwargs):
    principal = await jit_authority.get()
    return verify_grant(
        grant, authority_document=principal.did_document,
        expected_binding=binding, expected_domain=DOMAIN,
        authority_keys=await jit_authority.key_register(),
        resource_id="customer-007", **kwargs,
    )


class TestRegister:
    async def test_the_authority_starts_with_one_active_key(self, jit_authority):
        keys = await jit_authority.keys()
        assert len(keys) == 1
        assert keys[0].generation == 1
        assert keys[0].status is SigningKeyStatus.ACTIVE

    async def test_ensure_is_idempotent(self, jit_authority):
        """A restart must not silently produce a new signing key.

        One that did would be indistinguishable from a compromise.
        """
        before = await jit_authority.require_active_key()
        await jit_authority.ensure()
        after = await jit_authority.require_active_key()
        assert before.kid == after.kid

    async def test_the_register_exposes_no_private_material(self, jit_authority):
        for key in await jit_authority.keys():
            payload = key.to_dict()
            assert payload["private_key"] == "NEVER EXPOSED - held by the KeyStore"
            assert "private" not in payload.get("public_key_multibase", "").lower()
            assert not any(
                k for k in payload
                if "secret" in k.lower() or k == "private_key_b64"
            )

    async def test_the_did_document_publishes_the_key(self, jit_authority):
        principal = await jit_authority.get()
        document = principal.did_document
        active = await jit_authority.require_active_key()
        assert active.kid in document["assertionMethod"]
        assert document["serviceMetadata"]["activeVerificationMethod"] == active.kid

    async def test_the_authority_holds_no_control_plane_roles(self, jit_authority):
        """Signing mandates confers no authority over anything else."""
        principal = await jit_authority.get()
        assert list(principal.roles or []) == []


class TestRotation:
    async def test_rotation_creates_a_second_generation(self, jit_authority):
        first = await jit_authority.require_active_key()
        await jit_authority.rotate(reason="scheduled hygiene")
        second = await jit_authority.require_active_key()
        assert second.generation == 2
        assert second.kid != first.kid

    async def test_the_retired_key_is_retired_not_deleted(self, jit_authority):
        first = await jit_authority.require_active_key()
        await jit_authority.rotate(reason="scheduled hygiene")
        keys = {k.kid: k for k in await jit_authority.keys()}
        assert keys[first.kid].status is SigningKeyStatus.RETIRED
        assert keys[first.kid].retired_at is not None

    async def test_exactly_one_key_is_ever_active(self, jit_authority):
        await jit_authority.rotate(reason="one")
        await jit_authority.rotate(reason="two")
        active = [k for k in await jit_authority.keys()
                  if k.status is SigningKeyStatus.ACTIVE]
        assert len(active) == 1
        assert active[0].generation == 3

    async def test_history_stays_verifiable_after_rotation(
        self, jit_authority, keystore, jit_binding
    ):
        """THE POINT OF ROTATION. A mandate signed by generation 1 still
        verifies once generation 2 has taken over."""
        binding = jit_binding()
        first = await jit_authority.require_active_key()
        old_grant = await _sign_with(jit_authority, keystore, binding, first.kid)

        assert (await _verify(old_grant, jit_authority, binding)).valid

        await jit_authority.rotate(reason="rotate")

        report = await _verify(old_grant, jit_authority, binding)
        assert report.valid, report.reason
        assert report.signing_key == first.kid

    async def test_the_new_key_signs_new_mandates(
        self, jit_authority, keystore, jit_binding
    ):
        binding = jit_binding()
        await jit_authority.rotate(reason="rotate")
        second = await jit_authority.require_active_key()
        grant = await _sign_with(jit_authority, keystore, binding, second.kid)
        report = await _verify(grant, jit_authority, binding)
        assert report.valid, report.reason
        assert report.signing_key == second.kid

    async def test_a_retired_key_cannot_issue_anything_new(
        self, jit_authority, keystore, jit_binding
    ):
        """A grant dated AFTER the retirement, claiming the retired key.

        The mandates it really did sign are dated before the retirement and are
        untouched -- that is precisely the distinction.
        """
        binding = jit_binding()
        first = await jit_authority.require_active_key()
        await jit_authority.rotate(reason="rotate")

        later = datetime.now(timezone.utc) + timedelta(seconds=30)
        grant = await _sign_with(jit_authority, keystore, binding, first.kid,
                                 moment=later)
        report = await _verify(grant, jit_authority, binding)
        assert not report.valid
        assert report.reason == GrantReason.KEY_RETIRED

    async def test_signing_resolves_the_active_row_not_a_supplied_id(
        self, jit_authority
    ):
        """There is no parameter for a caller to pass the wrong key id to.

        That is what makes "a retired key cannot issue" structural rather than
        a rule somebody has to remember.
        """
        import inspect

        signature = inspect.signature(jit_authority.require_active_key)
        assert list(signature.parameters) == []

    async def test_an_unknown_key_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        binding = jit_binding()
        active = await jit_authority.require_active_key()
        grant = await _sign_with(jit_authority, keystore, binding, active.kid)
        grant["proof"]["verificationMethod"] = f"{jit_authority.did}#key-99"
        report = await _verify(grant, jit_authority, binding)
        assert not report.valid
        assert report.reason == GrantReason.KEY_UNKNOWN

    async def test_rotation_is_audited_without_exposing_the_key(
        self, jit_authority, session
    ):
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        await jit_authority.rotate(reason="audited rotation")
        result = await session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "JIT_KEY_ROTATED")
        )
        events = list(result.scalars().all())
        assert len(events) == 1
        metadata = events[0].event_metadata
        assert metadata["private_key_exposed"] is False
        assert metadata["retired_kid"] and metadata["active_kid"]
        assert metadata["retired_kid"] != metadata["active_kid"]

    async def test_rotation_republishes_the_did_document_with_both_keys(
        self, jit_authority
    ):
        """A verifier needs the public key of whichever generation signed."""
        first = await jit_authority.require_active_key()
        await jit_authority.rotate(reason="rotate")
        second = await jit_authority.require_active_key()
        principal = await jit_authority.get()
        published = {m["id"] for m in principal.did_document["verificationMethod"]}
        assert {first.kid, second.kid} <= published


class TestRotationRobustness:
    """Two failures found by running the gate twice, and fixed.

    Both are about a register and a KeyStore that have drifted apart -- which
    happens whenever the database is rebuilt while key files persist on disk.
    """

    def test_a_generation_is_recovered_from_the_key_id(self):
        """Backfill must not register `#key-8` as generation 1.

        Doing so makes the NEXT rotation compute `#key-2` and collide with
        material already on disk, which is precisely the failure this recovers
        from.
        """
        from app.jit.authority import _generation_of

        assert _generation_of("did:poc:service:jit-authority#key-8") == 8
        assert _generation_of("did:poc:service:jit-authority#key-1") == 1
        # An unnumbered kid is the original form, which IS generation 1.
        assert _generation_of("did:poc:service:jit-authority#keys") == 1

    async def test_rotation_skips_a_generation_whose_material_exists(
        self, jit_authority, keystore
    ):
        """Orphaned key files must not block rotation.

        Generations only have to be increasing and unique, not contiguous.
        Refusing to rotate at all would block an operator at exactly the moment
        they cannot afford it.
        """
        active = await jit_authority.require_active_key()
        # Occupy the generation rotation would otherwise take.
        blocked = f"{jit_authority.did}#key-{active.generation + 1}"
        keystore.generate_key(blocked)

        result = await jit_authority.rotate(reason="skip the occupied slot")
        new_kid = result["active"]["kid"]
        assert new_kid != blocked
        assert (await jit_authority.require_active_key()).kid == new_kid

    async def test_a_failed_rotation_leaves_the_old_key_ACTIVE(
        self, jit_authority, keystore, monkeypatch
    ):
        """THE BUG THIS TEST EXISTS FOR.

        Rotation used to retire the outgoing key BEFORE discovering the new one
        could not be created, leaving the authority with no ACTIVE key at all:
        unable to sign, and unable to rotate again either, because rotation
        starts by resolving an active key. A self-inflicted outage reached
        through a refusal that was itself correct.

        The authority must still be able to sign after a rotation fails.
        """
        before = await jit_authority.require_active_key()

        def refuse(kid):
            raise RuntimeError("keystore is unavailable")

        monkeypatch.setattr(jit_authority.keystore, "generate_key", refuse)
        with pytest.raises(RuntimeError):
            await jit_authority.rotate(reason="this will fail")

        after = await jit_authority.require_active_key()
        assert after.kid == before.kid
        assert after.status is SigningKeyStatus.ACTIVE


class TestRevocationIsNotRotation:
    async def test_revoking_a_key_invalidates_its_history(
        self, jit_authority, keystore, jit_binding
    ):
        """DESTRUCTIVE ON PURPOSE, and the opposite of rotation.

        A compromised key's history is exactly what cannot be relied on.
        """
        binding = jit_binding()
        first = await jit_authority.require_active_key()
        grant = await _sign_with(jit_authority, keystore, binding, first.kid)
        assert (await _verify(grant, jit_authority, binding)).valid

        await jit_authority.rotate(reason="rotate before revoking")
        await jit_authority.revoke_key(first.kid, reason="believed compromised")

        report = await _verify(grant, jit_authority, binding)
        assert not report.valid
        assert report.reason == GrantReason.KEY_REVOKED

    async def test_a_revoked_key_is_unpublished(self, jit_authority):
        first = await jit_authority.require_active_key()
        await jit_authority.rotate(reason="rotate")
        await jit_authority.revoke_key(first.kid, reason="compromised")
        principal = await jit_authority.get()
        published = {m["id"] for m in principal.did_document["verificationMethod"]}
        assert first.kid not in published

    async def test_revoking_twice_is_refused(self, jit_authority):
        first = await jit_authority.require_active_key()
        await jit_authority.rotate(reason="rotate")
        await jit_authority.revoke_key(first.kid, reason="compromised")
        with pytest.raises(ConflictError):
            await jit_authority.revoke_key(first.kid, reason="again")

    async def test_revoking_an_unknown_key_is_refused(self, jit_authority):
        with pytest.raises(NotFoundError):
            await jit_authority.revoke_key("did:poc:service:jit-authority#key-42",
                                           reason="nonexistent")

    async def test_revocation_is_audited(self, jit_authority, session):
        from sqlalchemy import select

        from app.db.models.audit import AuditEvent

        first = await jit_authority.require_active_key()
        await jit_authority.rotate(reason="rotate")
        await jit_authority.revoke_key(first.kid, reason="compromised")
        result = await session.execute(
            select(AuditEvent).where(AuditEvent.event_type == "JIT_KEY_REVOKED")
        )
        events = list(result.scalars().all())
        assert len(events) == 1
        assert events[0].event_metadata["private_key_exposed"] is False
        assert "STOP verifying" in events[0].event_metadata["historical_grants"]


class TestKeySeparation:
    async def test_the_jit_authority_is_a_distinct_principal(
        self, jit_authority, approval_authority
    ):
        assert jit_authority.did != approval_authority.did
        assert jit_authority.did.endswith("jit-authority")

    async def test_rotating_one_authority_does_not_touch_the_other(
        self, jit_authority, approval_authority
    ):
        """They are separate registers, and a rotation of one is not the other's."""
        approval_before = await approval_authority.require_active_key()
        await jit_authority.rotate(reason="jit only")
        approval_after = await approval_authority.require_active_key()
        assert approval_before.kid == approval_after.kid

    async def test_neither_authority_can_sign_for_the_other(
        self, jit_authority, approval_authority, keystore, jit_binding
    ):
        """The approval key produces a document the JIT verifier refuses.

        This is the test that makes key separation a property rather than an
        intention.
        """
        binding = jit_binding()
        approval_key = await approval_authority.require_active_key()
        now = datetime.now(timezone.utc)
        document = build_grant(
            grant_id=new_grant_id(), binding=binding, issued_at=now, not_before=now,
            expires_at=now + timedelta(seconds=300), max_uses=1, nonce=new_nonce(),
            domain=DOMAIN, authority_did=jit_authority.did,
            issuing_request_id="authz-test", justification={},
        )
        # Signed by the WRONG authority's key, but claiming the right issuer.
        forged = sign_grant(document, Signer(keystore), approval_key.kid, moment=now)
        report = await _verify(forged, jit_authority, binding)
        assert not report.valid
        # The kid is not in the JIT register at all.
        assert report.reason == GrantReason.KEY_UNKNOWN
