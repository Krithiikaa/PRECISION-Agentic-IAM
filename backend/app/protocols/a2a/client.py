"""Producing an A2A envelope, from the sender's side.

ONE implementation, used by the agent runtime, the test suite and the gate
script. If each of those built its own envelope, a change to what is signed
would be caught only by whichever of them happened to be exercised -- the
same reasoning `app.controlplane.client` records.

The private key never leaves the KeyStore: this asks the Signer for a
signature over the canonical envelope and nothing more.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.protocols.a2a.envelope import (
    A2A_RESPONSE_PROOF_PURPOSE,
    build_envelope,
    build_response,
    new_nonce,
    new_transaction_id,
    sign_envelope,
)
from app.identity.signer import Signer


def build_signed_transaction(
    signer: Signer,
    *,
    sender_did: str,
    sender_kid: str,
    receiver_did: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    purpose: str,
    domain: str,
    payload: dict[str, Any] | None = None,
    amount_inr: int | None = None,
    currency: str | None = None,
    transaction_id: str | None = None,
    ttl_seconds: int = 300,
    nonce: str | None = None,
    moment: datetime | None = None,
    credential_ids: list[str] | None = None,
    approval_id: str | None = None,
    jit_grant_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Build and sign one transaction envelope.

    `transaction_id` is the SENDER'S idempotency key. Reusing it deliberately
    is how a sender retries -- after a lost response, or after the humans an
    escalation asked for have decided. Reusing it with DIFFERENT content is
    refused as `A2A_TRANSACTION_ID_REUSE`, so a retry has to be a retry.

    `ttl_seconds` is a request, not a decision: the server clamps it to
    `A2A_MAX_TTL_SECONDS` and refuses anything longer. A sender does not get
    to choose how long its own instruction stays presentable.
    """
    moment = moment or datetime.now(timezone.utc)
    envelope = build_envelope(
        transaction_id=transaction_id or new_transaction_id(),
        sender_did=sender_did,
        receiver_did=receiver_did,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        purpose=purpose,
        payload=payload,
        amount_inr=amount_inr,
        currency=currency,
        issued_at=moment,
        expires_at=moment + timedelta(seconds=ttl_seconds),
        nonce=nonce or new_nonce(),
        domain=domain,
        credential_ids=credential_ids,
        approval_id=approval_id,
        jit_grant_id=jit_grant_id,
        correlation_id=correlation_id,
    )
    return sign_envelope(envelope, signer, sender_kid, moment=moment)


def build_signed_response(
    signer: Signer,
    *,
    responder_did: str,
    responder_kid: str,
    original_sender_did: str,
    transaction_id: str,
    status: str,
    decision: str | None = None,
    reason: str | None = None,
    policy: str | None = None,
    authorization_request_id: str | None = None,
    result_sha256: str | None = None,
    approval_id: str | None = None,
    domain: str,
    moment: datetime | None = None,
) -> dict[str, Any]:
    """Build and sign the RECEIVER's answer.

    Signed for a reason that is easy to miss: without it a third party can
    fabricate "your payment succeeded", and the sender has no way to tell.
    The response carries its own proof purpose, so it can never be replayed
    as a request.
    """
    moment = moment or datetime.now(timezone.utc)
    document = build_response(
        transaction_id=transaction_id,
        sender_did=responder_did,
        receiver_did=original_sender_did,
        status=status,
        decision=decision,
        reason=reason,
        policy=policy,
        authorization_request_id=authorization_request_id,
        result_sha256=result_sha256,
        approval_id=approval_id,
        issued_at=moment,
        nonce=new_nonce(),
        domain=domain,
    )
    return sign_envelope(
        document, signer, responder_kid,
        purpose=A2A_RESPONSE_PROOF_PURPOSE, moment=moment,
    )
