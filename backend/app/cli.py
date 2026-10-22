"""Operator CLI for the identity plane.

    python -m app.cli create-agent risk-001 "Credit Risk Analysis Agent" RISK \
        --capability credit_analysis --capability risk_analysis
    python -m app.cli list
    python -m app.cli did-document did:poc:agent:risk-001
    python -m app.cli sign did:poc:agent:risk-001 "I am the Risk Analysis Agent"
    python -m app.cli verify did:poc:agent:risk-001 "<message>" "<signature>"
"""
from __future__ import annotations

import asyncio
import json
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from app.agents.registry import AgentRegistry, AgentSpec
from app.core.config import get_settings
from app.credentials.issuer import CredentialIssuer, IssueRequest
from app.credentials.issuer_registry import IssuerRegistry
from app.credentials.status import CredentialStatusService
from app.credentials.verifier import CredentialVerifier
from app.db.database import dispose_engine, session_scope
from app.db.models.agent import AgentStatus, AgentType
from app.identity.keys import build_keystore

cli = typer.Typer(add_completion=False, help="Agentic IAM - identity plane CLI")
console = Console()


def _run(coro):
    async def wrapper():
        try:
            return await coro
        finally:
            await dispose_engine()

    return asyncio.run(wrapper())


async def _registry(session) -> AgentRegistry:
    settings = get_settings()
    return AgentRegistry(session, build_keystore(settings), settings)


@cli.command("create-agent")
def create_agent(
    slug: str,
    name: str,
    agent_type: AgentType,
    purpose: Annotated[str, typer.Option()] = "",
    capability: Annotated[list[str], typer.Option(help="Repeatable.")] = None,
    endpoint: Annotated[str, typer.Option()] = "",
    parent_did: Annotated[str, typer.Option()] = "",
    ttl_seconds: Annotated[int, typer.Option()] = 0,
) -> None:
    """Register an agent: DID + Ed25519 key pair + DID Document."""

    async def go():
        async with session_scope() as session:
            registry = await _registry(session)
            agent = await registry.create_agent(
                AgentSpec(
                    slug=slug,
                    name=name,
                    agent_type=agent_type,
                    purpose=purpose or None,
                    capabilities=capability or [],
                    endpoint=endpoint or None,
                    parent_did=parent_did or None,
                    ttl_seconds=ttl_seconds or None,
                )
            )
            key = agent.active_key
            console.print(f"[green]Registered[/green] {agent.name}")
            console.print(f"  DID                 {agent.did}")
            console.print(f"  Verification method {key.kid}")
            console.print(f"  Public key          {key.public_key_multibase}")
            console.print(f"  Status              {agent.status.value}")
            console.print("  Private key         held in keystore, never displayed")

    _run(go())


@cli.command("list")
def list_agents(capability: Annotated[str, typer.Option()] = "") -> None:
    """List registered agents."""

    async def go():
        async with session_scope() as session:
            registry = await _registry(session)
            agents = await registry.list_agents(capability=capability or None)
            table = Table(title=f"Registered agents ({len(agents)})")
            for column in ("DID", "Name", "Type", "Status", "Capabilities", "Public key"):
                table.add_column(column, overflow="fold")
            for agent in agents:
                key = agent.active_key
                table.add_row(
                    agent.did, agent.name, agent.agent_type.value, agent.status.value,
                    ", ".join(agent.capabilities or []),
                    (key.public_key_multibase[:16] + "...") if key else "-",
                )
            console.print(table)

    _run(go())


@cli.command("did-document")
def did_document(did: str) -> None:
    """Resolve and print an agent's DID Document."""

    async def go():
        async with session_scope() as session:
            registry = await _registry(session)
            console.print_json(json.dumps(await registry.resolve_did_document(did)))

    _run(go())


@cli.command("sign")
def sign(did: str, message: str) -> None:
    """Sign a message with an agent's key."""

    async def go():
        async with session_scope() as session:
            registry = await _registry(session)
            result = await registry.sign_as_agent(did, message)
            console.print_json(json.dumps(result))

    _run(go())


@cli.command("verify")
def verify(did: str, message: str, signature: str) -> None:
    """Verify a signature against the agent's published DID Document."""

    async def go():
        async with session_scope() as session:
            registry = await _registry(session)
            result = await registry.verify_agent_signature(did, message, signature)
            if result.valid:
                console.print(f"[bold green]VALID[/bold green]  {result.reason}")
            else:
                console.print(f"[bold red]INVALID[/bold red]  {result.reason}")
                raise typer.Exit(code=1)

    _run(go())


@cli.command("terminate")
def terminate(did: str, reason: Annotated[str, typer.Option()] = "OPERATOR_REQUEST") -> None:
    """Terminate an agent and destroy its signing key."""

    async def go():
        async with session_scope() as session:
            registry = await _registry(session)
            agent = await registry.terminate(did, reason)
            console.print(f"[yellow]{agent.did} -> {agent.status.value}[/yellow] ({reason})")

    _run(go())


@cli.command("audit")
def audit(
    agent_did: Annotated[str, typer.Option()] = "",
    limit: Annotated[int, typer.Option()] = 25,
) -> None:
    """Print recent audit events."""

    async def go():
        async with session_scope() as session:
            registry = await _registry(session)
            events = await registry.audit.query(agent_did=agent_did or None, limit=limit)
            table = Table(title=f"Audit events ({len(events)})")
            for column in ("Timestamp", "Event", "Agent DID", "Decision", "Reason"):
                table.add_column(column, overflow="fold")
            for event in reversed(events):
                table.add_row(
                    event["timestamp"], event["event_type"], event["agent_did"] or "-",
                    event["decision"] or "-", (event["reason"] or "-")[:60],
                )
            console.print(table)

    _run(go())


# --------------------------------------------------------------------------
# Phase 2: credentials
# --------------------------------------------------------------------------
@cli.command("issuers")
def issuers() -> None:
    """List credential-issuing authorities and their public keys."""

    async def go():
        async with session_scope() as session:
            settings = get_settings()
            registry = IssuerRegistry(session, build_keystore(settings), settings)
            table = Table(title="Credential issuers")
            for column in ("DID", "Name", "Status", "Verification method", "Public key"):
                table.add_column(column, overflow="fold")
            for issuer in await registry.list_issuers():
                table.add_row(issuer.did, issuer.name, issuer.status.value,
                              issuer.kid, issuer.public_key_multibase)
            console.print(table)

    _run(go())


@cli.command("issue-credential")
def issue_credential(
    subject: str,
    credential_type: str,
    claim: Annotated[list[str], typer.Option(help="key=value, repeatable. Lists: key=a,b")] = None,
    issuer: Annotated[str, typer.Option()] = "did:poc:organization:bank-demo",
    ttl: Annotated[int, typer.Option(help="Seconds until expiry.")] = 0,
) -> None:
    """Issue and sign a credential for an agent."""
    claims: dict = {}
    for entry in claim or []:
        key, _, value = entry.partition("=")
        claims[key] = value.split(",") if "," in value else value

    async def go():
        async with session_scope() as session:
            settings = get_settings()
            issuer_service = CredentialIssuer(session, build_keystore(settings), settings)
            record = await issuer_service.issue(
                IssueRequest(
                    issuer_did=issuer, subject_did=subject,
                    credential_type=credential_type, claims=claims,
                    ttl_seconds=ttl or None,
                )
            )
            console.print(f"[green]Issued[/green] {record.credential_type}")
            console.print(f"  Credential ID {record.credential_id}")
            console.print(f"  Issuer        {record.issuer_did}")
            console.print(f"  Subject       {record.subject_did}")
            console.print(f"  Expires       {record.expires_at.isoformat()}")
            console.print(f"  Proof         {record.proof['type']} by "
                          f"{record.proof['verificationMethod']}")

    _run(go())


@cli.command("credentials")
def list_credentials(subject: Annotated[str, typer.Option()] = "") -> None:
    """List issued credentials."""

    async def go():
        async with session_scope() as session:
            from app.db.repositories.credentials import CredentialRepository

            records = await CredentialRepository(session).list_credentials(
                subject_did=subject or None
            )
            table = Table(title=f"Credentials ({len(records)})")
            for column in ("Credential ID", "Type", "Subject", "Status", "Expires"):
                table.add_column(column, overflow="fold")
            for record in records:
                status = record.status_record.status.value if record.status_record else "?"
                table.add_row(record.credential_id, record.credential_type,
                              record.subject_did, status, record.expires_at.isoformat())
            console.print(table)

    _run(go())


@cli.command("verify-credential")
def verify_credential(
    credential_id: str,
    expected_subject: Annotated[str, typer.Option()] = "",
) -> None:
    """Verify a stored credential and print every check."""

    async def go():
        async with session_scope() as session:
            from app.db.repositories.credentials import CredentialRepository

            record = await CredentialRepository(session).get(credential_id)
            if record is None:
                console.print(f"[red]Unknown credential[/red] {credential_id}")
                raise typer.Exit(code=1)

            settings = get_settings()
            report = await CredentialVerifier(
                session, build_keystore(settings), settings
            ).verify(
                record.document, expected_subject=expected_subject or None, verifier="cli"
            )
            for check in report.checks:
                mark = "[green]PASS[/green]" if check.passed else "[red]FAIL[/red]"
                console.print(f"  {mark}  {check.name:<12} {check.detail}")
            if report.valid:
                console.print(f"\n[bold green]CREDENTIAL VALID[/bold green]  {report.reason}")
            else:
                console.print(f"\n[bold red]CREDENTIAL INVALID[/bold red]  {report.reason}")
                raise typer.Exit(code=1)

    _run(go())


@cli.command("revoke-credential")
def revoke_credential(
    credential_id: str,
    reason: Annotated[str, typer.Option()] = "OPERATOR_REQUEST",
) -> None:
    """Revoke a credential. Takes effect immediately for every verifier."""

    async def go():
        async with session_scope() as session:
            status = await CredentialStatusService(session).revoke(credential_id, reason)
            console.print(f"[yellow]{credential_id} -> {status['status']}[/yellow] ({reason})")

    _run(go())


if __name__ == "__main__":
    cli()
