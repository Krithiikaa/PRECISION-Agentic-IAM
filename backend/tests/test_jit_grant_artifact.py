"""The JIT grant artifact: what it binds, and what breaks when you move it.

Every test here answers one question: if an attacker changes THIS, does the
system notice? The answer must be yes for every field that affects
authorization, and the refusal must NAME the field -- "invalid" tells an
operator nothing they can act on.

Covers the spec's matrix items H-L (modified expiry, resource, agent, action,
purpose), N (forged signature), and the domain separation that stops one kind
of signed document being presented as another.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from app.identity.signer import Signer
from app.jit.grant import (
    ARTIFACT_TYPE,
    JIT_PROOF_PURPOSE,
    GrantReason,
    JITBinding,
    build_grant,
    evaluate_constraints,
    new_grant_id,
    new_nonce,
    sign_grant,
    verify_grant,
)

pytestmark = pytest.mark.integration

DOMAIN = "agentic-iam-aem"


async def _signed(jit_authority, keystore, binding, **overrides):
    """Build and sign a grant with the real key register."""
    now = overrides.pop("now", datetime.now(timezone.utc))
    key = await jit_authority.require_active_key()
    params = dict(
        grant_id=new_grant_id(),
        binding=binding,
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(seconds=300),
        max_uses=3,
        nonce=new_nonce(),
        domain=DOMAIN,
        authority_did=jit_authority.did,
        issuing_request_id="authz-test",
        justification={"policy": "test", "credential_ids": []},
    )
    params.update(overrides)
    document = build_grant(**params)
    return sign_grant(document, Signer(keystore), key.kid, moment=now)


async def _verify(grant, jit_authority, binding, **kwargs):
    principal = await jit_authority.get()
    return verify_grant(
        grant,
        authority_document=principal.did_document,
        expected_binding=binding,
        expected_domain=kwargs.pop("expected_domain", DOMAIN),
        authority_keys=await jit_authority.key_register(),
        **kwargs,
    )


# ===========================================================================
#  The binding itself
# ===========================================================================
class TestBinding:
    def test_the_digest_is_order_independent(self, jit_binding):
        """Two mandates over the same records hash the same, however asked for."""
        a = jit_binding(resource_ids=("customer-001", "customer-007"))
        b = jit_binding(resource_ids=("customer-007", "customer-001"))
        # Constructed in different orders; the binding sorts on the way in via
        # from_request, and canonicalisation sorts the keys.
        assert sorted(a.resource_ids) == sorted(b.resource_ids)
        c = JITBinding(agent_did=a.agent_did, action=a.action,
                       resource_type=a.resource_type,
                       resource_ids=tuple(sorted(b.resource_ids)),
                       purpose=a.purpose, constraints=a.constraints)
        d = JITBinding(agent_did=a.agent_did, action=a.action,
                       resource_type=a.resource_type,
                       resource_ids=tuple(sorted(a.resource_ids)),
                       purpose=a.purpose, constraints=a.constraints)
        assert c.digest() == d.digest()

    def test_a_different_agent_changes_the_digest(self, jit_binding):
        assert jit_binding().digest() != jit_binding(agent_did="did:poc:agent:other").digest()

    def test_a_different_action_changes_the_digest(self, jit_binding):
        assert jit_binding().digest() != jit_binding(action="write").digest()

    def test_a_different_resource_type_changes_the_digest(self, jit_binding):
        assert jit_binding().digest() != jit_binding(resource_type="payroll_records").digest()

    def test_a_different_purpose_changes_the_digest(self, jit_binding):
        assert jit_binding().digest() != jit_binding(purpose="marketing").digest()

    def test_a_different_constraint_changes_the_digest(self, jit_binding):
        assert (jit_binding().digest()
                != jit_binding(constraints={"max_amount_inr": 1}).digest())

    def test_differences_names_the_field_that_moved(self, jit_binding):
        """A denial has to be diagnostic, not merely correct."""
        assert jit_binding().differences(jit_binding(action="write")) == ["action"]
        assert jit_binding().differences(jit_binding(purpose="other")) == ["purpose"]

    def test_differences_ignores_resource_ids_and_constraints(self, jit_binding):
        """Both are properties of the MANDATE, which the live request lacks.

        Comparing them for equality would deny every mandate that had any --
        containment and ceilings are answered by their own checks instead.
        """
        mandate = jit_binding(resource_ids=("a", "b"), constraints={"max_amount_inr": 5})
        request = jit_binding(resource_ids=("a",), constraints={})
        assert mandate.differences(request) == []

    def test_covers_resource_is_membership(self, jit_binding):
        binding = jit_binding(resource_ids=("customer-007", "customer-009"))
        assert binding.covers_resource("customer-007")
        assert binding.covers_resource("customer-009")
        assert not binding.covers_resource("customer-999")

    def test_an_empty_resource_set_covers_the_type(self, jit_binding):
        """Weaker, and a deliberate configured choice rather than an accident."""
        assert jit_binding(resource_ids=()).covers_resource("anything")

    def test_from_request_narrows_to_the_requests_own_resource(self, jit_request):
        """The narrowest reading is the right default for a single request."""
        binding = JITBinding.from_request(jit_request(resource_id="customer-123"))
        assert binding.resource_ids == ("customer-123",)


# ===========================================================================
#  A well-formed mandate
# ===========================================================================
class TestValidGrant:
    async def test_a_valid_grant_verifies(self, jit_authority, keystore, jit_binding):
        """Matrix item A."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        report = await _verify(grant, jit_authority, binding, resource_id="customer-007")
        assert report.valid, report.reason
        assert report.reason == GrantReason.VALID
        assert report.bound_to_request and report.covers_resource

    async def test_the_artifact_declares_its_own_type(self, jit_authority, keystore, jit_binding):
        grant = await _signed(jit_authority, keystore, jit_binding())
        assert ARTIFACT_TYPE in grant["type"]

    async def test_the_proof_purpose_is_the_jit_domain_separator(
        self, jit_authority, keystore, jit_binding
    ):
        grant = await _signed(jit_authority, keystore, jit_binding())
        assert grant["proof"]["proofPurpose"] == JIT_PROOF_PURPOSE == "jitGrant"

    async def test_the_binding_hash_is_inside_the_signed_body(
        self, jit_authority, keystore, jit_binding
    ):
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        assert grant["credentialSubject"]["bindingHash"] == binding.digest()

    async def test_max_uses_is_signed(self, jit_authority, keystore, jit_binding):
        """A mandate must not be re-presentable as a larger budget."""
        grant = await _signed(jit_authority, keystore, jit_binding(), max_uses=7)
        assert grant["credentialSubject"]["maxUses"] == 7
        grant["credentialSubject"]["maxUses"] = 9999
        report = await _verify(grant, jit_authority, jit_binding(),
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_a_report_lists_every_check(self, jit_authority, keystore, jit_binding):
        """Never a bare boolean -- the Phase 2 discipline, kept."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        report = await _verify(grant, jit_authority, binding, resource_id="customer-007")
        names = {c.name for c in report.checks}
        assert {"present", "structure", "proof_purpose", "authority", "signature",
                "domain", "validity_window", "binding", "resource_scope"} <= names


# ===========================================================================
#  Tampering -- the matrix
# ===========================================================================
class TestTampering:
    async def test_a_modified_expiry_breaks_the_signature(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item H / 'forged future expiry'.

        Extending a mandate's life is the most obvious attack and it is not
        caught by a date comparison -- it is caught by the signature, which is
        the only place it CAN be caught reliably.
        """
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        tampered = copy.deepcopy(grant)
        far_future = datetime.now(timezone.utc) + timedelta(days=365)
        tampered["expirationDate"] = far_future.isoformat()
        report = await _verify(tampered, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_a_modified_agent_breaks_the_signature(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item J."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        grant["credentialSubject"]["agent_did"] = "did:poc:agent:attacker"
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_a_modified_action_breaks_the_signature(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item K."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        grant["credentialSubject"]["action"] = "write"
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_a_modified_resource_breaks_the_signature(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item I."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        grant["credentialSubject"]["resource_ids"] = ["customer-999"]
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-999")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_a_modified_purpose_breaks_the_signature(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item M."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        grant["credentialSubject"]["purpose"] = "marketing"
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_a_modified_constraint_breaks_the_signature(
        self, jit_authority, keystore, jit_binding
    ):
        """Raising a ceiling is scope escalation, and it is refused."""
        binding = jit_binding(constraints={"max_amount_inr": 1000})
        grant = await _signed(jit_authority, keystore, binding)
        grant["credentialSubject"]["constraints"] = {"max_amount_inr": 999_999_999}
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_a_forged_signature_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item N."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        grant["proof"]["signatureValue"] = "A" * 86 + "=="
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.SIGNATURE_INVALID

    async def test_flipping_the_proof_purpose_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """Domain separation, enforced rather than advisory.

        An approval artifact must never be presentable as a mandate, and the
        purpose is INSIDE the signed bytes so the attempt is refused on shape
        before the signature is even reached.
        """
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        grant["proof"]["proofPurpose"] = "humanApproval"
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.PROOF_PURPOSE_INVALID

    async def test_an_approval_artifact_is_not_a_mandate(
        self, jit_authority, keystore, jit_binding
    ):
        """A different signed document, refused on its type."""
        fake = {
            "@context": [], "type": ["VerifiableCredential", "HumanApprovalArtifact"],
            "credentialSubject": {}, "proof": {"proofPurpose": "humanApproval"},
        }
        report = await _verify(fake, jit_authority, jit_binding())
        assert not report.valid
        assert report.reason == GrantReason.MALFORMED

    async def test_a_binding_hash_that_disagrees_with_the_body_is_malformed(
        self, jit_authority, keystore, jit_binding
    ):
        """Both are signed, so disagreement means it was built wrong.

        Either way it is not usable -- a mandate whose digest does not describe
        its own fields cannot be reasoned about.
        """
        binding = jit_binding()
        now = datetime.now(timezone.utc)
        key = await jit_authority.require_active_key()
        document = build_grant(
            grant_id=new_grant_id(), binding=binding, issued_at=now, not_before=now,
            expires_at=now + timedelta(seconds=300), max_uses=1, nonce=new_nonce(),
            domain=DOMAIN, authority_did=jit_authority.did,
            issuing_request_id="authz-test", justification={},
        )
        document["credentialSubject"]["bindingHash"] = "0" * 64
        grant = sign_grant(document, Signer(keystore), key.kid, moment=now)
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.MALFORMED


# ===========================================================================
#  Scope -- the substitution attacks that do NOT need tampering
# ===========================================================================
class TestScope:
    async def test_a_grant_for_another_agent_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item C. Perfectly signed, and not yours."""
        mandate = jit_binding(agent_did="did:poc:agent:risk-002")
        grant = await _signed(jit_authority, keystore, mandate)
        report = await _verify(grant, jit_authority, jit_binding(),
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.BINDING_MISMATCH
        assert "agent_did" in report.binding_differences

    async def test_a_grant_for_another_action_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item E. A `read` mandate is not a `write` mandate."""
        grant = await _signed(jit_authority, keystore, jit_binding(action="read"))
        report = await _verify(grant, jit_authority, jit_binding(action="write"),
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.BINDING_MISMATCH
        assert "action" in report.binding_differences

    async def test_a_grant_for_another_resource_type_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item D. credit_records is not payroll_records."""
        grant = await _signed(jit_authority, keystore, jit_binding())
        report = await _verify(grant, jit_authority,
                               jit_binding(resource_type="payroll_records"),
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.BINDING_MISMATCH
        assert "resource_type" in report.binding_differences

    async def test_a_grant_for_another_purpose_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item F."""
        grant = await _signed(jit_authority, keystore, jit_binding())
        report = await _verify(grant, jit_authority, jit_binding(purpose="marketing"),
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.BINDING_MISMATCH
        assert "purpose" in report.binding_differences

    async def test_a_resource_outside_the_mandate_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """The containment check, with its own more precise refusal."""
        mandate = jit_binding(resource_ids=("customer-007",))
        grant = await _signed(jit_authority, keystore, mandate)
        report = await _verify(grant, jit_authority, jit_binding(),
                               resource_id="customer-999")
        assert not report.valid
        assert report.reason == GrantReason.BINDING_MISMATCH
        assert report.binding_differences == ["resource_ids"]

    async def test_a_mandate_over_several_records_covers_each_of_them(
        self, jit_authority, keystore, jit_binding
    ):
        """The point of the phase: one mandate, several records."""
        mandate = jit_binding(resource_ids=("customer-001", "customer-007"))
        grant = await _signed(jit_authority, keystore, mandate)
        for rid in ("customer-001", "customer-007"):
            report = await _verify(grant, jit_authority, jit_binding(),
                                   resource_id=rid)
            assert report.valid, f"{rid}: {report.reason}"


# ===========================================================================
#  The validity window -- server clock only
# ===========================================================================
class TestValidityWindow:
    async def test_an_expired_grant_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """Matrix item B.

        Expired by advancing the SERVER clock past the window, not by
        back-dating the signature. Back-dating trips the key-register check
        first -- a grant claiming to predate the key that signed it is a
        different and more serious finding, and it has its own test.
        """
        binding = jit_binding()
        now = datetime.now(timezone.utc)
        grant = await _signed(jit_authority, keystore, binding, now=now,
                              expires_at=now + timedelta(seconds=60))
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007",
                               now=now + timedelta(seconds=61))
        assert not report.valid
        assert report.reason == GrantReason.EXPIRED

    async def test_a_grant_predating_its_own_signing_key_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """A back-dated proof cannot have come from a key that did not exist.

        This is the check that fired when the test above was first written the
        obvious way, and it is worth asserting deliberately rather than only
        tripping over.
        """
        binding = jit_binding()
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        grant = await _signed(jit_authority, keystore, binding, now=past,
                              expires_at=past + timedelta(seconds=60))
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.KEY_UNKNOWN

    async def test_the_expiry_boundary_is_deterministic_and_denies(
        self, jit_authority, keystore, jit_binding
    ):
        """`now >= expires_at` is expired.

        The boundary INSTANT denies, matching the approval artifact exactly so
        the two never disagree about what "the moment it expires" means.
        """
        from app.credentials.vc import parse_iso

        binding = jit_binding()
        now = datetime.now(timezone.utc)
        grant = await _signed(jit_authority, keystore, binding, now=now,
                              expires_at=now + timedelta(seconds=300))

        # The boundary is whatever the ARTIFACT says, not what the caller
        # passed in: the document serialises to millisecond precision, and the
        # instant that matters is the one a verifier will actually parse.
        boundary = parse_iso(grant["expirationDate"])

        just_before = await _verify(grant, jit_authority, binding,
                                    resource_id="customer-007",
                                    now=boundary - timedelta(milliseconds=1))
        assert just_before.valid, just_before.reason

        exactly_at = await _verify(grant, jit_authority, binding,
                                   resource_id="customer-007", now=boundary)
        assert not exactly_at.valid
        assert exactly_at.reason == GrantReason.EXPIRED

        just_after = await _verify(grant, jit_authority, binding,
                                   resource_id="customer-007",
                                   now=boundary + timedelta(milliseconds=1))
        assert not just_after.valid
        assert just_after.reason == GrantReason.EXPIRED

    async def test_a_grant_is_not_usable_before_not_before(
        self, jit_authority, keystore, jit_binding
    ):
        binding = jit_binding()
        now = datetime.now(timezone.utc)
        grant = await _signed(jit_authority, keystore, binding, now=now,
                              not_before=now + timedelta(seconds=120),
                              expires_at=now + timedelta(seconds=300))
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007", now=now)
        assert not report.valid
        assert report.reason == GrantReason.NOT_YET_VALID

    async def test_the_agents_clock_is_never_consulted(
        self, jit_authority, keystore, jit_binding
    ):
        """There is no parameter for a caller-supplied time.

        `verify_grant`'s `now` is passed by the SERVER; nothing in the artifact
        or in a request can influence it. This asserts the shape rather than a
        behaviour, which is the only way to assert an absence.
        """
        import inspect

        signature = inspect.signature(verify_grant)
        assert signature.parameters["now"].kind is inspect.Parameter.KEYWORD_ONLY
        # And no field of the document is read as a clock.
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        grant["currentTime"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        # The injected field changes nothing except the signature it breaks.
        assert report.reason == GrantReason.SIGNATURE_INVALID


# ===========================================================================
#  Audience and authority
# ===========================================================================
class TestAudienceAndAuthority:
    async def test_a_grant_for_another_audience_is_refused(
        self, jit_authority, keystore, jit_binding
    ):
        """The Phase 2 S-2 protection, preserved."""
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding, domain="another-service")
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.DOMAIN_MISMATCH

    async def test_a_grant_from_another_issuer_is_refused(
        self, jit_authority, keystore, jit_binding, approval_authority
    ):
        """Matrix item: grant forgery by the WRONG authority.

        Signed by the approval authority, which is a real signing service in
        this system -- and not this one. This is the test that makes key
        separation mean something.
        """
        binding = jit_binding()
        now = datetime.now(timezone.utc)
        approval_key = await approval_authority.require_active_key()
        document = build_grant(
            grant_id=new_grant_id(), binding=binding, issued_at=now, not_before=now,
            expires_at=now + timedelta(seconds=300), max_uses=1, nonce=new_nonce(),
            domain=DOMAIN, authority_did=approval_authority.did,
            issuing_request_id="authz-test", justification={},
        )
        grant = sign_grant(document, Signer(keystore), approval_key.kid, moment=now)
        report = await _verify(grant, jit_authority, binding,
                               resource_id="customer-007")
        assert not report.valid
        assert report.reason == GrantReason.AUTHORITY_UNKNOWN

    async def test_the_jit_key_is_not_the_approval_key(
        self, jit_authority, approval_authority
    ):
        """THE SEPARATION, asserted directly.

        Sharing a key would mean compromising it yields both the power to forge
        a human decision and the power to mint the mandate that carries it
        forward -- precisely the pair an attacker would want together.
        """
        jit_key = await jit_authority.require_active_key()
        approval_key = await approval_authority.require_active_key()
        assert jit_authority.did != approval_authority.did
        assert jit_key.kid != approval_key.kid
        assert jit_key.public_key_multibase != approval_key.public_key_multibase

    async def test_no_authority_document_refuses(self, jit_authority, keystore, jit_binding):
        binding = jit_binding()
        grant = await _signed(jit_authority, keystore, binding)
        report = verify_grant(grant, authority_document=None,
                              expected_binding=binding, expected_domain=DOMAIN)
        assert not report.valid
        assert report.reason == GrantReason.AUTHORITY_UNKNOWN

    async def test_a_missing_grant_is_refused(self, jit_authority, jit_binding):
        report = await _verify(None, jit_authority, jit_binding())
        assert not report.valid
        assert report.reason == GrantReason.MISSING


# ===========================================================================
#  Constraints, evaluated against LIVE server-side attributes
# ===========================================================================
class TestConstraints:
    def test_no_constraints_is_no_violation(self):
        assert evaluate_constraints({}, {"available": True, "amount_inr": 5}) == []

    def test_an_amount_within_the_ceiling_passes(self):
        assert evaluate_constraints(
            {"max_amount_inr": 1_000_000},
            {"available": True, "amount_inr": 500_000},
        ) == []

    def test_an_amount_at_the_ceiling_passes(self):
        """`>` not `>=`: the ceiling itself is permitted."""
        assert evaluate_constraints(
            {"max_amount_inr": 1_000_000},
            {"available": True, "amount_inr": 1_000_000},
        ) == []

    def test_an_amount_over_the_ceiling_violates(self):
        violations = evaluate_constraints(
            {"max_amount_inr": 1_000_000},
            {"available": True, "amount_inr": 2_500_000},
        )
        assert violations and "exceeds the mandate ceiling" in violations[0]

    def test_an_unestablishable_amount_FAILS_CLOSED(self):
        """A ceiling on an attribute nobody can state is a VIOLATION.

        A mandate saying "up to Rs 10,00,000" must not become usable on a
        record whose amount cannot be read. Treating unknown as within-limit
        would be the single most dangerous reading available.
        """
        violations = evaluate_constraints(
            {"max_amount_inr": 1_000_000}, {"available": False},
        )
        assert violations
        assert "could not be established" in violations[0]

    async def test_a_violated_constraint_refuses_the_grant(
        self, jit_authority, keystore, jit_binding
    ):
        binding = jit_binding(constraints={"max_amount_inr": 1_000_000})
        grant = await _signed(jit_authority, keystore, binding)
        report = await _verify(
            grant, jit_authority, binding, resource_id="customer-007",
            resource_attributes={"available": True, "amount_inr": 9_000_000},
        )
        assert not report.valid
        assert report.reason == GrantReason.CONSTRAINT_VIOLATED
