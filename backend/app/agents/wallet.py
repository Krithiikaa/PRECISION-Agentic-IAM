"""The agent's credential wallet.

An agent *holds* credentials; it does not mint them. The wallet fetches what
the issuer has attested about this agent from the IAM registry, and produces
presentations signed with the agent's OWN Phase 1 Ed25519 key.

That key separation is the whole security argument: the agent can prove it is
the subject (holder proof), but it cannot forge what a trusted authority said
about it (issuer proof), because it has never held an issuer key.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.logging import get_logger
from app.credentials.presentation import attach_proof, build_unsigned_presentation
from app.credentials.vc import credential_claims, specific_type
from app.identity.signer import Signer

log = get_logger("agent.wallet")


@dataclass
class HeldCredential:
    credential_id: str
    credential_type: str
    issuer: str
    status: str
    expires_at: str
    seconds_remaining: int
    document: dict[str, Any]

    @property
    def claims(self) -> dict[str, Any]:
        return credential_claims(self.document)

    @property
    def capability(self) -> str | None:
        value = self.claims.get("capability")
        return value if isinstance(value, str) else None

    @property
    def usable(self) -> bool:
        """Locally usable: ACTIVE and not past its expiry.

        This is the holder's own housekeeping so it does not present something
        it already knows is dead. It is NOT a security check -- the verifier
        re-establishes every property independently, and a holder that lies
        here gains nothing.
        """
        return self.status == "ACTIVE" and self.seconds_remaining > 0

    def summary(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "credential_type": self.credential_type,
            "issuer": self.issuer,
            "status": self.status,
            "expires_at": self.expires_at,
            "seconds_remaining": self.seconds_remaining,
            "claims": self.claims,
            "usable": self.usable,
        }


class CredentialWallet:
    def __init__(
        self,
        *,
        iam: httpx.AsyncClient,
        holder_did: str,
        holder_kid: str,
        signer: Signer,
    ) -> None:
        self.iam = iam
        self.holder_did = holder_did
        self.holder_kid = holder_kid
        self.signer = signer
        self._credentials: list[HeldCredential] = []
        self.last_refreshed_at: datetime | None = None
        self.last_error: str | None = None

    # --- contents --------------------------------------------------------
    @property
    def credentials(self) -> list[HeldCredential]:
        return list(self._credentials)

    def attested_capabilities(self) -> list[str]:
        """Capabilities attested by a credential the holder believes is usable.

        Distinct from `AgentIdentity.capabilities`, which is only what the
        agent *declares* about itself. This list is what an issuer signed.
        """
        return sorted(
            {c.capability for c in self._credentials if c.usable and c.capability}
        )

    async def refresh(self) -> list[HeldCredential]:
        try:
            response = await self.iam.get(
                f"/api/v1/agents/did/{self.holder_did}/credentials",
                params={"include_document": "true"},
                timeout=10.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            # Report the failure; do not silently serve a stale wallet as fresh.
            self.last_error = f"{type(exc).__name__}: {exc}"
            log.warning("wallet_refresh_failed", holder=self.holder_did, error=self.last_error)
            return self.credentials

        self.last_error = None
        self._credentials = [
            HeldCredential(
                credential_id=entry["credential_id"],
                credential_type=entry["credential_type"],
                issuer=entry["issuer"],
                status=entry["status"],
                expires_at=entry["expires_at"],
                seconds_remaining=entry["seconds_remaining"],
                document=entry["credential"],
            )
            for entry in response.json()
            if entry.get("credential")
        ]
        self.last_refreshed_at = datetime.now(timezone.utc)
        return self.credentials

    def select(
        self,
        *,
        capability: str | None = None,
        credential_type: str | None = None,
        credential_ids: list[str] | None = None,
        usable_only: bool = True,
    ) -> list[HeldCredential]:
        selected = self._credentials
        if credential_ids:
            wanted = set(credential_ids)
            return [c for c in selected if c.credential_id in wanted]
        if usable_only:
            selected = [c for c in selected if c.usable]
        if credential_type:
            selected = [c for c in selected if c.credential_type == credential_type]
        if capability:
            selected = [c for c in selected if c.capability == capability]
        return selected

    # --- presentation ----------------------------------------------------
    def present(
        self,
        credentials: list[HeldCredential],
        *,
        challenge: str | None = None,
        domain: str | None = None,
    ) -> dict[str, Any]:
        """Build and sign a presentation with the agent's own key."""
        if not credentials:
            raise ValueError("Nothing to present: no matching credential in this wallet")
        unsigned = build_unsigned_presentation(
            holder_did=self.holder_did,
            holder_kid=self.holder_kid,
            credentials=[c.document for c in credentials],
            challenge=challenge,
            domain=domain,
        )
        signature = self.signer.sign(self.holder_kid, unsigned.payload)
        return attach_proof(unsigned, signature.signature_b64)

    def status(self) -> dict[str, Any]:
        return {
            "holder": self.holder_did,
            "count": len(self._credentials),
            "usable": sum(1 for c in self._credentials if c.usable),
            "attested_capabilities": self.attested_capabilities(),
            "last_refreshed_at": (
                self.last_refreshed_at.isoformat() if self.last_refreshed_at else None
            ),
            "last_error": self.last_error,
        }
