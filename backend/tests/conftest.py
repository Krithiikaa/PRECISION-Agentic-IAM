"""Test fixtures.

Tests run against a REAL PostgreSQL database (agentic_iam_test), not an
in-memory substitute, because persistence across restarts is one of the
properties being asserted.
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid

# Environment must be set before app.core.config caches its Settings.
#
# This ASSIGNS rather than setdefault()s: a developer who has sourced .env has
# DATABASE_URL pointing at the development database, and this suite calls
# drop_all(). Using setdefault here silently pointed the tests at the
# development database and destroyed its contents on every run.
DEFAULT_TEST_DB = "postgresql+psycopg://iam:iam@localhost:5433/agentic_iam_test"
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_DB)
os.environ["ENV"] = "test"
os.environ["KEYSTORE_DIR"] = tempfile.mkdtemp(prefix="iam-test-keystore-")

# Belt and braces: a destructive suite must never point at a database whose
# name does not mark it as disposable, however it was configured.
_DB_NAME = os.environ["DATABASE_URL"].rsplit("/", 1)[-1].split("?")[0]
if not _DB_NAME.endswith("_test"):
    raise RuntimeError(
        f"Refusing to run: the test suite drops every table, and the target "
        f"database {_DB_NAME!r} is not named '*_test'. Set TEST_DATABASE_URL "
        f"to a disposable database."
    )

import psycopg  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.agents.registry import AgentRegistry, AgentSpec  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.db.models import Base  # noqa: E402
from app.db.models.agent import AgentType  # noqa: E402
from app.identity.keys import EncryptedFileKeyStore, InMemoryKeyStore  # noqa: E402

TEST_DB_URL = os.environ["DATABASE_URL"]


def _ensure_test_database() -> None:
    """Create the test database if it does not exist."""
    dsn = TEST_DB_URL.replace("postgresql+psycopg://", "postgresql://")
    admin_dsn, _, dbname = dsn.rpartition("/")
    with psycopg.connect(f"{admin_dsn}/postgres", autocommit=True) as conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (dbname,)
        ).fetchone()
        if not exists:
            conn.execute(f'CREATE DATABASE "{dbname}"')


@pytest_asyncio.fixture(scope="session")
async def engine():
    try:
        _ensure_test_database()
    except psycopg.OperationalError as exc:
        pytest.skip(f"PostgreSQL is not reachable at {TEST_DB_URL}: {exc}")
    engine = create_async_engine(TEST_DB_URL, pool_pre_ping=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session(engine):
    """A session per test, with every table truncated afterwards."""
    maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with maker() as session:
        yield session
        await session.rollback()
    async with engine.begin() as conn:
        from sqlalchemy import text

        tables = ", ".join(f'"{t.name}"' for t in reversed(Base.metadata.sorted_tables))
        await conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))


@pytest.fixture
def keystore(tmp_path):
    """A real encrypted-file keystore, isolated per test."""
    return EncryptedFileKeyStore(tmp_path / "keystore", get_settings().keystore_master_key)


@pytest.fixture
def memory_keystore():
    return InMemoryKeyStore()


@pytest.fixture
def registry(session, keystore):
    return AgentRegistry(session, keystore, get_settings())


# --- Phase 2: credential fixtures ------------------------------------------
@pytest_asyncio.fixture
async def issuers(session, keystore):
    """The configured issuing authorities, each with its own Ed25519 key."""
    from app.credentials.issuer_registry import IssuerRegistry

    registry = IssuerRegistry(session, keystore, get_settings())
    await registry.ensure_configured_issuers()
    return registry


@pytest.fixture
def issuer_did():
    return "did:poc:organization:bank-demo"


@pytest.fixture
def compliance_issuer_did():
    return "did:poc:organization:compliance-authority"


@pytest.fixture
def credential_issuer(session, keystore, issuers):
    from app.credentials.issuer import CredentialIssuer

    return CredentialIssuer(session, keystore, get_settings())


@pytest.fixture
def verifier(session, keystore, issuers):
    from app.credentials.verifier import CredentialVerifier

    return CredentialVerifier(session, keystore, get_settings())


@pytest_asyncio.fixture
async def risk_agent(registry, agent_spec):
    """A real Phase 1 agent identity, reused as the credential subject."""
    return await registry.create_agent(agent_spec("risk-001"))


@pytest_asyncio.fixture
async def fraud_agent(registry, agent_spec):
    from app.db.models.agent import AgentType

    return await registry.create_agent(
        agent_spec("fraud-001", name="Fraud Detection Agent", agent_type=AgentType.FRAUD,
                   capabilities=["fraud_detection"])
    )


@pytest.fixture
def capability_claims():
    return {
        "capability": "credit_analysis",
        "allowed_actions": ["READ_CREDIT_PROFILE"],
        "allowed_resources": ["credit_records"],
        "purpose": "loan_assessment",
    }


@pytest_asyncio.fixture
async def issued_credential(credential_issuer, risk_agent, issuer_did, capability_claims):
    from app.credentials.issuer import IssueRequest

    return await credential_issuer.issue(
        IssueRequest(
            issuer_did=issuer_did,
            subject_did=risk_agent.did,
            credential_type="AgentCapabilityCredential",
            claims=capability_claims,
            ttl_seconds=3600,
        )
    )


@pytest.fixture
def agent_spec():
    def make(slug: str | None = None, **overrides) -> AgentSpec:
        defaults = dict(
            slug=slug or f"test-{uuid.uuid4().hex[:8]}",
            name="Credit Risk Analysis Agent",
            agent_type=AgentType.RISK,
            purpose="Analyse the financial risk of a loan application.",
            capabilities=["credit_analysis", "risk_analysis"],
            endpoint="http://localhost:9003",
        )
        defaults.update(overrides)
        return AgentSpec(**defaults)

    return make


# --- Phase 3: ANS fixtures --------------------------------------------------
@pytest.fixture
def ans_registry(session):
    from app.ans.registry import ANSRegistry

    return ANSRegistry(session, get_settings())


@pytest.fixture
def discovery(session, keystore):
    from app.ans.discovery import DiscoveryEngine

    return DiscoveryEngine(session, keystore, get_settings())


@pytest.fixture
def sign_registration(keystore):
    """Produce a genuinely signed registration payload for an agent.

    Uses the agent's real Phase 1 key from the keystore, so these tests
    exercise the same proof path a running agent uses.
    """
    from app.ans.proof import RegistrationPayload
    from app.identity.signer import Signer

    _UNSET = object()

    def make(agent, *, endpoint="http://localhost:9003", capabilities=_UNSET,
             organization=None, nonce=None, moment=None):
        # `capabilities=[]` must mean "sign an empty list" so the rejection path
        # can be tested; only an omitted argument falls back to the agent's own.
        if capabilities is _UNSET:
            capabilities = list(agent.capabilities or ["credit_analysis"])
        payload = RegistrationPayload.build(
            did=agent.did,
            endpoint=endpoint,
            capabilities=capabilities,
            organization=organization or agent.controller_did,
            nonce=nonce,
            moment=moment,
        )
        signature = Signer(keystore).sign(agent.active_key.kid, payload.signing_bytes())
        return payload, signature.signature_b64

    return make


@pytest_asyncio.fixture
async def registered_risk_agent(ans_registry, sign_registration, risk_agent):
    payload, signature = sign_registration(risk_agent)
    result = await ans_registry.register(payload, signature)
    assert result.accepted, result.detail
    return risk_agent


@pytest_asyncio.fixture
async def client(session, keystore):
    """HTTP client bound to the app, with DB and keystore overridden."""
    from app.api.deps import get_keystore
    from app.db.database import get_session
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_keystore] = lambda: keystore

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


# --- Phase 4: authorization fixtures ----------------------------------------
@pytest_asyncio.fixture(scope="session")
async def opa_ready():
    """Verify the REAL OPA runtime is up and load the policy set into it.

    If OPA is not running these tests SKIP LOUDLY with the reason and the command
    to fix it. They are never satisfied by a substitute: a fake policy engine
    would only prove that Python agrees with Python, which is exactly what
    Phase 4 must not do.

    Returns plain data, not a live client. The HTTP client is created and closed
    inside this fixture's own event loop; each test gets its own client from
    `opa_client` below, because an httpx client cannot be shared across loops.
    OPA keeps loaded modules for the life of the server, so pushing once per
    session is enough even though the database is truncated between tests.
    """
    from app.authorization.opa import OPAClient
    from app.authorization.pap import PolicyAdministrationPoint

    client = OPAClient(get_settings())
    try:
        health = await client.health()
        if not health["available"]:
            pytest.skip(
                f"OPA is not reachable at {health['url']}: {health['detail']}. "
                f"Start it with `docker compose up -d opa`. These tests "
                f"deliberately do not run against a stand-in policy engine."
            )
        pap = PolicyAdministrationPoint(None, get_settings(), client)  # type: ignore[arg-type]
        loaded = []
        for definition in pap.read_definitions():
            if definition.status == "ACTIVE":
                await client.put_policy(definition.module_id, definition.source)
                loaded.append(definition.policy_id)
        return {"url": health["url"], "loaded": loaded}
    finally:
        await client.aclose()


@pytest.fixture
def opa_client(opa_ready):
    """A per-test OPA client.

    Sync fixture on purpose: OPAClient opens and closes an HTTP connection per
    call, so there is nothing to tear down asynchronously and nothing bound to a
    particular event loop.
    """
    from app.authorization.opa import OPAClient

    return OPAClient(get_settings())


@pytest_asyncio.fixture
async def policies_loaded(session, opa_ready):
    """Load the declared policy set through the PAP, into this test's session.

    `opa_ready` pushes the modules into the shared OPA server once per session.
    The POLICY LIFECYCLE ROWS live in the database, which is truncated between
    tests, so anything asserting on `/api/v1/policies` or mutating a policy by
    id needs the records to exist here too.
    """
    from app.authorization.pap import PolicyAdministrationPoint

    pap = PolicyAdministrationPoint(session, get_settings())
    await pap.load_all()
    return pap


@pytest.fixture
def pdp(session, keystore, opa_client):
    from app.authorization.pdp import PolicyDecisionPoint

    return PolicyDecisionPoint(session, keystore, get_settings(), opa=opa_client)


@pytest_asyncio.fixture
async def aem(session, keystore, pdp):
    """The enforcement boundary, with the signing authorities bootstrapped.

    Both authorities are ensured here for the same reason `main.py` ensures
    them at startup: the AEM can escalate to an approval and can issue a
    mandate, and neither is signable without its authority existing. A fixture
    that produced an AEM which could not sign would fail in a way that looks
    like a signing bug rather than a missing bootstrap.
    """
    from app.enforcement.aem import AdapterEnforcementMiddleware
    from app.hitl.authority import ApprovalAuthority
    from app.jit.authority import JITAuthority

    await ApprovalAuthority(session, keystore, get_settings()).ensure()
    await JITAuthority(session, keystore, get_settings()).ensure()
    return AdapterEnforcementMiddleware(session, keystore, get_settings(), pdp=pdp)


@pytest.fixture
def authz_request():
    """Build an AuthorizationRequest with sensible defaults for a test."""
    from app.authorization.contracts import AuthorizationRequest, Resource, Subject

    def make(did: str, **overrides):
        params = dict(
            subject=Subject(did=did),
            action="read",
            resource=Resource(type="credit_records", id="customer-007"),
            purpose="loan_assessment",
        )
        if "resource_type" in overrides:
            params["resource"] = Resource(
                type=overrides.pop("resource_type"),
                id=overrides.pop("resource_id", "customer-007"),
            )
        params.update(overrides)
        return AuthorizationRequest(**params)

    return make


# --- Phase 4.5: control-plane fixtures --------------------------------------
@pytest_asyncio.fixture
async def control_plane(session, keystore):
    """The configured control-plane administrators, each with its own key."""
    from app.controlplane.principals import ControlPlanePrincipalRegistry

    registry = ControlPlanePrincipalRegistry(session, keystore, get_settings())
    await registry.ensure_configured_principals()
    return registry


@pytest.fixture
def policy_admin_did():
    return "did:poc:administrator:platform-security"


@pytest.fixture
def identity_admin_did():
    return "did:poc:administrator:identity-authority"


@pytest.fixture
def enforcement_did():
    return "did:poc:administrator:enforcement-gateway"


@pytest.fixture
def sign_control_plane(keystore):
    """Produce genuine control-plane proof headers for a principal.

    Signs with the principal's REAL key from the keystore, so these tests
    exercise the same proof path a running agent or operator uses. Nothing here
    is stubbed: an invalid signature in a test is an invalid signature to the
    server.
    """
    from app.controlplane.client import canonical_body, control_plane_headers
    from app.identity.signer import Signer

    def make(principal_did, *, method="POST", path, body=None, kid=None,
             nonce=None, moment=None):
        return control_plane_headers(
            Signer(keystore),
            principal_did=principal_did,
            kid=kid or f"{principal_did}#key-1",
            method=method, path=path, body=canonical_body(body),
            nonce=nonce, moment=moment,
        )

    return make


@pytest.fixture
def cp_post(client, sign_control_plane):
    """POST through the control-plane guard as a given principal.

    The body is serialised ONCE and those exact bytes are both hashed into the
    proof and sent, because the proof binds sha256(body). Re-serialising would
    change the digest.
    """
    from app.controlplane.client import canonical_body

    async def post(path, principal_did, body=None, **overrides):
        payload = canonical_body(body)
        headers = sign_control_plane(principal_did, method="POST", path=path,
                                     body=body, **overrides)
        return await client.post(path, content=payload,
                                 headers={**headers,
                                          "Content-Type": "application/json"})

    return post


# --- the ANS service, mounted for tests -------------------------------------
@pytest_asyncio.fixture
async def ans_client(session, keystore):
    from app.ans.service import router
    from app.api.deps import get_keystore
    from app.api.errors import install_error_handlers
    from app.db.database import get_session
    from fastapi import FastAPI

    # The router is mounted on a bare app so the test exercises the routes
    # without starting the background sweeper and prober tasks. The real
    # service's error handlers are installed from the same shared definition,
    # so the test sees the same status codes production does.
    app = FastAPI()
    install_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_keystore] = lambda: keystore

    async with AsyncClient(transport=ASGITransport(app=app),
                           base_url="http://ans.test") as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def ans_post(ans_client, sign_control_plane):
    """POST to the ANS as a signed control-plane principal.

    The body is serialised once and those exact bytes are both hashed into the
    proof and sent: the proof binds sha256(body).
    """
    from app.controlplane.client import canonical_body

    async def post(path, principal_did, body=None, **overrides):
        payload = canonical_body(body)
        headers = sign_control_plane(principal_did, method="POST", path=path,
                                     body=body, **overrides)
        return await ans_client.post(
            path, content=payload,
            headers={**headers, "Content-Type": "application/json"},
        )

    return post


# --- Phase 5: human identity and HITL fixtures ------------------------------
@pytest.fixture
def admin_post(client, sign_control_plane, control_plane, opa_ready):
    """POST as the MACHINE identity administrator.

    Depends on `control_plane` (so the administrator exists and holds a key)
    and `opa_ready` (because the guard asks the PDP, which asks OPA). Both are
    implicit on purpose: a test about credential issuance should not have to
    know that issuance is now authorized, only that it is done by someone.

    The S-7 mutations (agent creation, credential issuance and revocation)
    require an authorized principal from Phase 5 onwards. Most of this suite
    only needs *some* authorized caller, and the machine administrator needs no
    Keycloak -- so tests that are not about human identity stay infrastructure
    -light. The human path has its own tests.
    """
    from app.controlplane.client import canonical_body

    async def post(path, body=None, principal="did:poc:administrator:identity-authority"):
        payload = canonical_body(body)
        headers = sign_control_plane(principal, method="POST", path=path, body=body)
        return await client.post(path, content=payload,
                                 headers={**headers, "Content-Type": "application/json"})

    return post


@pytest.fixture
def agent_post(client, keystore, control_plane, opa_ready):
    """POST as an AGENT, signing with the agent's own registry-custodied key."""
    from app.controlplane.client import canonical_body, control_plane_headers
    from app.identity.signer import Signer

    async def post(path, agent_did, body=None, kid=None):
        payload = canonical_body(body)
        headers = control_plane_headers(
            Signer(keystore), principal_did=agent_did,
            kid=kid or f"{agent_did}#key-1", method="POST", path=path, body=payload,
        )
        return await client.post(path, content=payload,
                                 headers={**headers, "Content-Type": "application/json"})

    return post


@pytest.fixture(scope="session")
def keycloak_ready():
    """Verify the REAL Keycloak is up, and that its realm is the configured one.

    If Keycloak is not running these tests SKIP LOUDLY with the reason and the
    command to fix it. They are never satisfied by a substitute: a fake OIDC
    provider would only prove that Python agrees with Python, which is exactly
    what Phase 5 must not do.

    The issuer is checked as well as reachability -- a Keycloak serving a
    DIFFERENT issuer would make every token fail validation in a way that looks
    like a code fault.
    """
    import urllib.error
    import urllib.request

    settings = get_settings()
    url = settings.oidc_discovery_url
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            document = json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        pytest.skip(
            f"Keycloak is not reachable at {url}: {exc}. Start it with "
            f"`docker compose up -d keycloak`. These tests deliberately do not "
            f"run against a stand-in identity provider."
        )
    if document.get("issuer") != settings.keycloak_issuer:
        pytest.skip(
            f"Keycloak advertises issuer {document.get('issuer')!r} but this "
            f"application is configured for {settings.keycloak_issuer!r}. Every "
            f"token would be refused as ISSUER_INVALID."
        )
    return document


@pytest.fixture(scope="session")
def human_token(keycloak_ready):
    """Obtain a REAL access token from Keycloak, by direct grant.

    Genuine RS256 tokens from the real issuer with real realm roles -- not
    fixtures, and not signed by anything this repository controls. The browser
    uses Authorization Code + PKCE; direct grant is how a test drives the same
    realm without a browser, and the token it returns is byte-for-byte the kind
    the validator sees in production.
    """
    import urllib.parse
    import urllib.request

    settings = get_settings()
    cache: dict[str, str] = {}

    def get(username: str, password: str) -> str:
        if username in cache:
            return cache[username]
        data = urllib.parse.urlencode({
            "client_id": settings.oidc_client_id,
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        }).encode()
        with urllib.request.urlopen(settings.oidc_token_url, data, timeout=10) as response:
            cache[username] = json.loads(response.read())["access_token"]
        return cache[username]

    return get


@pytest.fixture
def loan_officer_token(human_token):
    return human_token("loan.officer", "loan-officer-demo")


@pytest.fixture
def second_loan_officer_token(human_token):
    """A SECOND, different loan officer (Phase 5.5).

    Dual control cannot be demonstrated with one account. Proving that the same
    human is refused the second sign-off is only meaningful next to a different
    human who is accepted, and both tokens have to come from the real Keycloak
    for either half to mean anything.
    """
    return human_token("loan.officer.2", "loan-officer-2-demo")


@pytest.fixture
def iam_admin_token(human_token):
    return human_token("iam.admin", "iam-admin-demo")


@pytest.fixture
def auditor_token(human_token):
    return human_token("auditor", "auditor-demo")


@pytest.fixture
def no_roles_token(human_token):
    """An authenticated human with NO roles.

    Exists so "authenticated but unauthorized" is a tested state rather than an
    assumed one.
    """
    return human_token("no.roles", "no-roles-demo")


@pytest.fixture
def human_post(client):
    """POST as an authenticated human, with a real OIDC bearer token."""
    async def post(path, token, body=None):
        return await client.post(path, json=body,
                                 headers={"Authorization": f"Bearer {token}"})

    return post


@pytest_asyncio.fixture
async def approval_authority(session, keystore):
    """The service principal that signs approval artifacts."""
    from app.hitl.authority import ApprovalAuthority

    authority = ApprovalAuthority(session, keystore, get_settings())
    await authority.ensure()
    return authority


@pytest.fixture
def loan_claims():
    """A capability credential scoped to loan applications."""
    return {
        "capability": "credit_analysis",
        "allowed_actions": ["APPROVE_LOAN"],
        "allowed_resources": ["loan_applications"],
        "purpose": "loan_decision",
    }


@pytest_asyncio.fixture
async def loan_credential(credential_issuer, risk_agent, issuer_did, loan_claims):
    from app.credentials.issuer import IssueRequest

    return await credential_issuer.issue(
        IssueRequest(
            issuer_did=issuer_did, subject_did=risk_agent.did,
            credential_type="AgentCapabilityCredential",
            claims=loan_claims, ttl_seconds=3600,
        )
    )


@pytest.fixture
def loan_request(risk_agent):
    """An authorization request for the high-value loan decision."""
    from app.authorization.contracts import AuthorizationRequest, Resource, Subject

    def make(**overrides):
        params = dict(
            subject=Subject(did=overrides.pop("did", risk_agent.did)),
            action="approve_loan",
            resource=Resource(type="loan_applications", id="loan-7842"),
            purpose="loan_decision",
        )
        if "resource_id" in overrides:
            params["resource"] = Resource(type="loan_applications",
                                          id=overrides.pop("resource_id"))
        params.update(overrides)
        return AuthorizationRequest(**params)

    return make


@pytest.fixture
def approval_service(session, keystore, approval_authority):
    """The approval service, wired to sign with the real key register."""
    from app.hitl.service import ApprovalService

    return ApprovalService(session, keystore, get_settings())


@pytest.fixture
def opa_data_loaded(opa_ready):
    """Ensure the amount thresholds are in the engine before an amount test.

    Policy fails CLOSED without them, so a test that ran against an engine
    missing this document would see LOAN_POLICY_UNCONFIGURED and look like a
    policy bug. Loading it here makes the dependency explicit.
    """
    return opa_ready


@pytest.fixture(autouse=True)
def _reset_loan_applications():
    """Restore the demo loan applications between tests.

    `approve_loan_application` genuinely mutates its record, which is what lets
    a negative test assert the resource was NOT touched. Shared mutable state
    across tests would make that assertion meaningless.
    """
    from app.enforcement.resources import reset_loan_applications

    reset_loan_applications()
    yield
    reset_loan_applications()


# --- Phase 6: JIT temporary access -----------------------------------------
@pytest_asyncio.fixture
async def jit_authority(session, keystore):
    """The service principal that signs JIT mandates.

    A DIFFERENT principal and a DIFFERENT key from the approval authority. A
    test asserts they are distinct, because sharing one would mean compromising
    it yields both the power to forge a human decision and the power to mint
    the mandate that carries it forward.
    """
    from app.jit.authority import JITAuthority

    authority = JITAuthority(session, keystore, get_settings())
    await authority.ensure()
    return authority


@pytest.fixture
def jit_service(session, keystore, jit_authority):
    """The mandate service, wired to sign with the real key register."""
    from app.jit.service import JITService

    return JITService(session, keystore, get_settings())


@pytest.fixture
def jit_binding(risk_agent):
    """A mandate scope over credit records, with sensible defaults.

    `read`/`credit_records` is the shipped JIT-eligible action, so a binding
    built here is one policy will actually issue against.
    """
    from app.jit.grant import JITBinding

    def make(**overrides):
        params = dict(
            agent_did=overrides.pop("agent_did", risk_agent.did),
            action="read",
            resource_type="credit_records",
            resource_ids=("customer-007",),
            purpose="loan_assessment",
            constraints={},
        )
        params.update(overrides)
        if isinstance(params["resource_ids"], list):
            params["resource_ids"] = tuple(params["resource_ids"])
        return JITBinding(**params)

    return make


@pytest_asyncio.fixture
async def issued_mandate(jit_service, jit_binding):
    """A signed, persisted mandate: 3 uses, 300 seconds.

    Issued DIRECTLY through the service rather than through the AEM, because
    most tests are about what a mandate IS and how it verifies, not about the
    issuance decision. The issuance-decision tests drive the AEM instead.
    """
    return await jit_service.issue(
        binding=jit_binding(),
        ttl_seconds=300,
        max_uses=3,
        issuing_request_id="authz-test-issuance",
        justification={"policy": "test", "decision_reason": "TEST", "credential_ids": []},
    )


@pytest.fixture
def jit_request(risk_agent):
    """An AuthorizationRequest a mandate over credit records would cover."""
    from app.authorization.contracts import AuthorizationRequest, Resource, Subject

    def make(**overrides):
        params = dict(
            subject=Subject(did=overrides.pop("did", risk_agent.did)),
            action="read",
            resource=Resource(type="credit_records",
                              id=overrides.pop("resource_id", "customer-007")),
            purpose="loan_assessment",
        )
        params.update(overrides)
        return AuthorizationRequest(**params)

    return make


@pytest_asyncio.fixture
async def jit_policy_loaded(opa_ready):
    """Push the JIT configuration document into the running OPA.

    Policy fails CLOSED without it, so a test that ran against an engine
    missing this document would see JIT_POLICY_UNCONFIGURED everywhere and look
    like a policy bug. Loading it here makes the dependency explicit, exactly
    as `opa_data_loaded` does for the loan thresholds.
    """
    from app.authorization.opa import OPAClient
    from app.authorization.pap import PolicyAdministrationPoint

    pap = PolicyAdministrationPoint(None, get_settings())
    client = OPAClient(get_settings())
    try:
        for definition in pap.read_data_definitions():
            if definition.status == "ACTIVE":
                await client.put_data(definition.path, definition.document)
    finally:
        await client.aclose()
    return True


# --- Phase 7: secure A2A transactions --------------------------------------
@pytest_asyncio.fixture
async def payments_agent(registry, agent_spec):
    """The RECEIVING agent: the one that carries out payment instructions.

    A real Phase 1 identity with its own key, because receiver binding is
    enforced by requiring the submitter to hold THIS agent's private key.
    """
    from app.db.models.agent import AgentType

    return await registry.create_agent(
        agent_spec(
            "payments-001",
            name="Payment Execution Agent",
            agent_type=AgentType.DECISION,
            purpose="Execute payment instructions sent by other agents.",
            capabilities=["payment_execution"],
            endpoint="http://localhost:9008",
        )
    )


@pytest.fixture
def payment_claims():
    """A capability credential scoped to payment instructions.

    Note what it names: the RESOURCE and the PURPOSE. `a2a/transaction.rego`
    matches on those and on the credential being valid -- never on an agent
    DID, which would be the hardcoded authorization the spec forbids.
    """
    return {
        "capability": "payment_execution",
        "allowed_actions": ["EXECUTE_PAYMENT"],
        "allowed_resources": ["payment_instructions"],
        "purpose": "payment_settlement",
    }


@pytest_asyncio.fixture
async def payment_credential(credential_issuer, risk_agent, issuer_did, payment_claims):
    """The SENDER's credential. A2A authorizes the sender, never the receiver."""
    from app.credentials.issuer import IssueRequest

    return await credential_issuer.issue(
        IssueRequest(
            issuer_did=issuer_did, subject_did=risk_agent.did,
            credential_type="AgentCapabilityCredential",
            claims=payment_claims, ttl_seconds=3600,
        )
    )


@pytest.fixture
def a2a_service(session):
    from app.protocols.a2a.service import A2ATransactionService

    return A2ATransactionService(session, get_settings())


@pytest.fixture
def a2a_envelope(keystore, risk_agent, payments_agent):
    """Build a GENUINELY SIGNED envelope with the sender's real Phase 1 key.

    Nothing here is stubbed: an invalid signature in a test is an invalid
    signature to the server, and the same `build_signed_transaction` the
    agent runtime and the gate use produces it.

    `tamper` applies a mutation AFTER signing, which is exactly the attack --
    every field in the envelope is covered by the signature, so any mutation
    must invalidate it.
    """
    from app.identity.signer import Signer
    from app.protocols.a2a.client import build_signed_transaction

    def make(*, sender=None, sender_kid=None, receiver=None, action="execute_payment",
             resource_type="payment_instructions", resource_id="pay-3310",
             purpose="payment_settlement", amount_inr=50_000, currency="INR",
             payload=None, transaction_id=None, ttl_seconds=300, nonce=None,
             moment=None, credential_ids=None, approval_id=None,
             jit_grant_id=None, correlation_id=None, domain=None, tamper=None,
             signing_agent=None):
        sender_agent = signing_agent or risk_agent
        envelope = build_signed_transaction(
            Signer(keystore),
            sender_did=sender or risk_agent.did,
            sender_kid=sender_kid or sender_agent.active_key.kid,
            receiver_did=receiver or payments_agent.did,
            action=action, resource_type=resource_type, resource_id=resource_id,
            purpose=purpose,
            domain=domain or get_settings().a2a_domain,
            payload=payload if payload is not None else {"note": "demo"},
            amount_inr=amount_inr, currency=currency,
            transaction_id=transaction_id, ttl_seconds=ttl_seconds, nonce=nonce,
            moment=moment, credential_ids=credential_ids,
            approval_id=approval_id, jit_grant_id=jit_grant_id,
            correlation_id=correlation_id,
        )
        if tamper is not None:
            tamper(envelope)
        return envelope

    return make


@pytest_asyncio.fixture
async def a2a_aem(session, keystore, pdp):
    """The enforcement boundary, with every signing authority bootstrapped.

    Both authorities are ensured for the reason the Phase 6 fixture ensures
    them: the A2A path can escalate to an approval, and an AEM that could not
    sign one would fail in a way that looks like a signing bug rather than a
    missing bootstrap.
    """
    from app.enforcement.aem import AdapterEnforcementMiddleware
    from app.hitl.authority import ApprovalAuthority
    from app.jit.authority import JITAuthority

    await ApprovalAuthority(session, keystore, get_settings()).ensure()
    await JITAuthority(session, keystore, get_settings()).ensure()
    return AdapterEnforcementMiddleware(session, keystore, get_settings(), pdp=pdp)


@pytest_asyncio.fixture
async def a2a_policy_loaded(opa_ready):
    """Push the A2A configuration document into the running OPA.

    Policy fails CLOSED without it, so a test running against an engine
    missing this document would see A2A_POLICY_UNCONFIGURED everywhere and
    look like a policy bug. Loading it here makes the dependency explicit,
    exactly as `jit_policy_loaded` and `opa_data_loaded` do.
    """
    from app.authorization.opa import OPAClient
    from app.authorization.pap import PolicyAdministrationPoint

    pap = PolicyAdministrationPoint(None, get_settings())
    client = OPAClient(get_settings())
    try:
        for definition in pap.read_data_definitions():
            if definition.status == "ACTIVE":
                await client.put_data(definition.path, definition.document)
    finally:
        await client.aclose()
    return True


@pytest_asyncio.fixture
async def submit_a2a(a2a_aem, payments_agent, payment_credential, a2a_policy_loaded):
    """Submit an envelope as the RECEIVER, the way the route does.

    Goes through `AEM.enforce_a2a` rather than HTTP so a test can drive the
    security properties without also standing up the control-plane guard --
    the guard has its own tests, and the receiver binding it enforces is
    asserted here too by passing a `submitted_by` that differs from the
    envelope's receiver.
    """
    async def submit(envelope, *, submitted_by=None, now=None):
        return await a2a_aem.enforce_a2a(
            envelope=envelope,
            submitted_by=submitted_by or payments_agent.did,
            now=now,
        )

    return submit


@pytest.fixture(autouse=True)
def _reset_payment_instructions():
    """Restore the demo instructions between tests.

    `execute_payment_instruction` genuinely mutates its record and counts
    executions, which is what lets a negative test assert no money moved and
    a concurrency test assert it moved exactly once. Shared mutable state
    across tests would make both assertions meaningless.
    """
    from app.enforcement.resources import reset_payment_instructions

    reset_payment_instructions()
    yield
    reset_payment_instructions()


@pytest.fixture
def payment_officer_token(human_token):
    return human_token("payment.officer", "payment-officer-demo")


@pytest.fixture
def second_payment_officer_token(human_token):
    """A SECOND, different payment officer (Phase 7).

    Dual control on a payment cannot be demonstrated with one account.
    Proving that the same human is refused the second sign-off is only
    meaningful next to a different human who is accepted.
    """
    return human_token("payment.officer.2", "payment-officer-2-demo")


@pytest_asyncio.fixture
def backdate_key(session):
    """Age an agent's signing key, so a STALE envelope can be tested at all.

    In a fresh test database every key was created seconds ago, so an
    envelope old enough to fail the freshness window is also older than its
    own key -- and the key-window check fires first with A2A_KEY_UNKNOWN.
    That ordering is CORRECT (a proof claiming to predate its key is a
    forgery signal), but it makes freshness unreachable without an agent
    that has existed for a while, which is the realistic case.
    """
    from datetime import timedelta

    async def age(agent, *, days: int = 2):
        key = agent.active_key
        key.created_at = key.created_at - timedelta(days=days)
        await session.flush()
        return key

    return age
