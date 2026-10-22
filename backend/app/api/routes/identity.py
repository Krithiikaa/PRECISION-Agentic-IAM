"""Identity Lab endpoints: sign and verify against real Ed25519 keys.

PHASE 4.5 -- S-6. `/sign` signs an ARBITRARY caller-supplied message with a
registry-custodied agent's private key. Unauthenticated, that is not merely a
weak endpoint: it is a universal bypass of everything built on agent DID
proofs. An attacker could ask this endpoint to sign a control-plane payload and
then present a genuine signature to the ANS heartbeat:

    GET  /api/v1/agents                 -> find risk-001
    POST /api/v1/agents/{id}/sign       -> sign the heartbeat payload
    POST /api/v1/ans/heartbeat          -> a proof that really does verify

So S-4 cannot be closed while this stays open, and it is protected here.

`/verify` is deliberately NOT protected: verification needs only a public key,
produces no state change, and is the operation a third party is supposed to be
able to perform independently.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app.api.deps import RegistryDep
from app.api.schemas import SignRequest, SignResponse, VerifyRequest, VerifyResponse
from app.controlplane.guard import ControlPlaneGuard, fixed

router = APIRouter(prefix="/api/v1/identity", tags=["identity"])


@router.post("/sign", response_model=SignResponse, dependencies=[Depends(
    ControlPlaneGuard("identity_sign", target=fixed("identity")))])
async def sign(did: str, body: SignRequest, registry: RegistryDep) -> SignResponse:
    return SignResponse(**await registry.sign_as_agent(did, body.message))


@router.post("/verify", response_model=VerifyResponse)
async def verify(body: VerifyRequest, registry: RegistryDep) -> VerifyResponse:
    """Verify a signature against the public key in the agent's DID Document.

    An invalid signature is a 200 response with valid=false, not an error:
    tampering is an expected outcome that must be recorded, not a crash.
    """
    result = await registry.verify_agent_signature(body.did, body.message, body.signature)
    return VerifyResponse(
        valid=result.valid,
        reason=result.reason,
        did=body.did,
        verification_method=result.verification_method,
        verified_at=datetime.now(timezone.utc).isoformat(),
    )
