"""The route security inventory (Phase 10).

WHAT THIS FILE IS. A declared, reviewable list of every route this service
serves and the authentication it requires — checked against the application's
actual route table on every run.

WHY IT EXISTS. Phase 9 probed the running system and found ten unauthenticated
endpoints disclosing the audit trail, the credential inventory, the approval
queue, human identities and loan records. The fix was to guard them. The
*durable* fix is this file: a route added later with no guard and no entry
here fails a test, by name, the day it appears. Nobody has to remember.

THE PUBLIC LIST IS AN ALLOW-LIST, NOT A RECORD. A route is public only
because it is written below with a reason. Deleting a guard does not make a
route public; it makes this file fail.

---------------------------------------------------------------------------
WHY EACH PUBLIC ROUTE IS PUBLIC
---------------------------------------------------------------------------

Liveness probes answer before anything else is up, including the identity
provider, so requiring authentication would make them useless for the thing
they exist for. They disclose no record.

DID documents are PUBLIC KEY MATERIAL. Publishing them is the point of a DID:
a verifier that cannot fetch the key cannot check the signature. The same is
true of the approval-authority and JIT key registers — they carry public
halves, and they exist so a third party can verify an artifact this system
signed without asking this system's permission.

The protected-resource metadata document is required by RFC 9728 to be
reachable by a client that has no token yet; its entire job is telling that
client where to get one.

`/mcp` authenticates with an OAuth bearer token rather than a control-plane
proof — a different mechanism, not a missing one. Its refusals are asserted
in test_mcp_security.py.
"""
from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

import app.controlplane.guard as guard_module
from app.controlplane.contracts import ControlPlaneClass
from app.controlplane.guard import OPERATIONS

pytestmark = pytest.mark.integration


# --- the allow-list -------------------------------------------------------
PUBLIC_ROUTES: dict[str, str] = {
    "/health": "liveness probe; answers before the stack is up, discloses nothing",
    "/ready": "readiness probe; same reasoning",
    "/api/v1/a2a/health": "liveness probe for the A2A surface",
    "/api/v1/hitl/health": "liveness probe for the HITL surface",
    "/api/v1/hitl/config":
        "the OIDC discovery parameters a browser needs to START a login "
        "(issuer, client id, endpoints). Guarding it made sign-in require a "
        "token, which locked every human out of the console after Phase 10. "
        "The console is a public PKCE client: nothing here is secret",
    "/api/v1/authorize/health": "liveness probe for the policy engine",
    "/.well-known/oauth-protected-resource":
        "RFC 9728 requires this reachable WITHOUT a token: it tells a client "
        "where to get one",
    "/mcp": "OAuth 2.1 resource server; authenticated by bearer token instead",
    "/api/v1/agents/{agent_id}/did-document":
        "a DID document is published public-key material, by design",
    "/api/v1/agents/did/{did}/did-document":
        "the same DID document, resolved by DID instead of by row id; public "
        "for the same reason",
    "/api/v1/credentials/issuers/{did}/did-document":
        "an issuer's DID document; a verifier must be able to fetch the "
        "issuing key to check a credential it was handed",
    "/api/v1/hitl/authority/keys":
        "the approval authority's PUBLIC key register; a third party must be "
        "able to verify an approval artifact without this system's permission",
    "/api/v1/jit/keys":
        "the JIT authority's PUBLIC key register; a mandate is verifiable by "
        "whoever is handed it, which requires the public half",
    "/api/v1/hitl/me":
        "returns the caller's own identity; an unauthenticated caller has "
        "none, so it discloses nothing",
    "/api/v1/credentials/challenge":
        "issues a verifier challenge. Public because a holder must be able to "
        "obtain one before it can prove anything; the challenge is "
        "unpredictable, single-use and bound to its verifier (Phase 10 "
        "replay protection), so handing one out grants nothing",
}

# Routes that mutate but authenticate by a different mechanism, or are
# stateless verification that changes nothing and reveals nothing.
EXEMPT_MUTATIONS: dict[str, str] = {
    "/api/v1/credentials/verify": "stateless verification of a supplied document",
    "/api/v1/credentials/verify-presentation": "stateless verification",
    "/api/v1/identity/verify": "stateless signature verification",
    "/mcp": "OAuth 2.1 resource server",
}


def _is_guard(fn) -> bool:
    return (
        getattr(fn, "__module__", "") == guard_module.__name__
        and "ControlPlaneGuard" in getattr(fn, "__qualname__", "")
    )


def _guarded(dependant, depth: int = 0) -> bool:
    if depth > 6:
        return False
    if _is_guard(getattr(dependant, "call", None)):
        return True
    return any(
        _guarded(sub, depth + 1)
        for sub in (getattr(dependant, "dependencies", []) or [])
    )


def _routes():
    from app.main import create_app

    return [r for r in create_app().routes if isinstance(r, APIRoute)]


class TestEverySensitiveReadIsGuarded:
    """THE REGRESSION GUARD FOR THE PHASE 9 HIGH FINDING."""

    def test_the_route_table_is_non_trivial(self):
        """Guards the test. If the table were empty every assertion below
        would pass vacuously and this file would be worthless."""
        assert len(_routes()) > 50

    def test_no_unlisted_get_route_is_unauthenticated(self):
        """A GET is either guarded, or written in PUBLIC_ROUTES with a reason.

        There is no third option, and that is the whole point: adding a
        sensitive read without a guard fails here by name.
        """
        unlisted = [
            r.path for r in _routes()
            if "GET" in r.methods
            and not _guarded(r.dependant)
            and r.path not in PUBLIC_ROUTES
        ]
        assert not unlisted, (
            "these GET routes are unauthenticated and not on the public "
            "allow-list:\n  " + "\n  ".join(sorted(unlisted))
            + "\n\nGuard them, or add them to PUBLIC_ROUTES with the reason "
              "they are safe to serve anonymously."
        )

    def test_no_mutating_route_is_unauthenticated(self):
        mutating = [
            r.path for r in _routes()
            if (r.methods - {"GET", "HEAD", "OPTIONS"})
            and not _guarded(r.dependant)
            and r.path not in EXEMPT_MUTATIONS
        ]
        assert not mutating, (
            "these state-changing routes are unauthenticated:\n  "
            + "\n  ".join(sorted(mutating))
        )

    def test_the_public_allow_list_has_no_stale_entries(self):
        """A route that was made public, then guarded, then left on this list
        is a lie in a security document. It also hides the next mistake: an
        entry nobody checks is an entry nobody notices being wrong."""
        served = {r.path for r in _routes()}
        stale = sorted(set(PUBLIC_ROUTES) - served)
        assert not stale, f"PUBLIC_ROUTES names routes that do not exist: {stale}"

    def test_every_public_entry_states_a_reason(self):
        for path, reason in PUBLIC_ROUTES.items():
            assert len(reason) > 25, (
                f"{path} is on the public allow-list without a real reason"
            )

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v1/audit",
            "/api/v1/agents",
            "/api/v1/credentials",
            "/api/v1/hitl/approvals",
            "/api/v1/hitl/humans",
            "/api/v1/loans",
            "/api/v1/policies",
            "/api/v1/authorize/decisions",
            "/api/v1/jit",
            "/api/v1/a2a/transactions",
        ],
    )
    def test_each_endpoint_phase_9_found_open_is_now_guarded(self, path):
        """Named one by one. The sweep above says SOMETHING regressed; these
        say WHICH, and they are the exact endpoints the Phase 9 probe found
        serving an anonymous caller."""
        route = next((r for r in _routes() if r.path == path), None)
        assert route is not None, f"{path} is no longer served"
        assert _guarded(route.dependant), f"{path} is unauthenticated again"


class TestTheOperationCatalogueIsCoherent:
    """Rego matches on the operation NAME, so a typo fails closed with
    UNKNOWN_CONTROL_PLANE_OPERATION. These catch the typo at test time."""

    def test_every_guarded_route_names_a_declared_operation(self):
        """A guard built with an operation that is not in OPERATIONS would
        deny every request at runtime. Better to fail here."""
        unknown = []
        for route in _routes():
            for dep in route.dependant.dependencies:
                call = getattr(dep, "call", None)
                if not _is_guard(call):
                    continue
                operation = getattr(getattr(getattr(call, "guard", None), "operation", None), "name", None)
                if operation is not None and operation not in OPERATIONS:
                    unknown.append(f"{route.path} -> {operation!r}")
        assert not unknown, f"guards naming undeclared operations: {unknown}"

    def test_the_phase_10_read_operations_exist(self):
        expected = {
            "identity_read", "credential_read", "audit_read",
            "approval_read", "grant_read", "policy_read", "loan_read",
        }
        assert expected <= set(OPERATIONS)

    def test_read_operations_are_classified_as_authorized_not_merely_authenticated(
        self,
    ):
        """AUTHENTICATED_READ would mean any principal that can prove an
        identity reads everything. For the audit trail and a loan file that
        is the wrong answer, so these must require a ROLE."""
        for name in (
            "identity_read", "credential_read", "audit_read",
            "approval_read", "grant_read", "policy_read", "loan_read",
        ):
            assert OPERATIONS[name].classification is ControlPlaneClass.AUTHORIZED_READ

    def test_no_operation_is_declared_but_unreachable(self):
        """An operation nobody mounts is dead weight that still appears in
        the policy set, inviting a rule to be written for a door that does
        not exist."""
        mounted = set()
        for route in _routes():
            for dep in route.dependant.dependencies:
                call = getattr(dep, "call", None)
                if _is_guard(call):
                    op = getattr(getattr(getattr(call, "guard", None), "operation", None), "name", None)
                    if op:
                        mounted.add(op)
        # Only assert for the Phase 10 reads; earlier phases have operations
        # reached through paths this introspection does not walk.
        phase10 = {
            "identity_read", "credential_read", "audit_read",
            "approval_read", "grant_read", "policy_read", "loan_read",
        }
        unmounted = sorted(phase10 - mounted)
        assert not unmounted, f"declared but mounted nowhere: {unmounted}"


async def test_the_login_bootstrap_is_reachable_without_a_token(client):
    """REGRESSION. A login cannot require a login."""
    response = await client.get("/api/v1/hitl/config")
    assert response.status_code == 200
    body = response.json()
    assert body["flow"] == "authorization_code+pkce"
    assert "secret" not in str(body).lower()
