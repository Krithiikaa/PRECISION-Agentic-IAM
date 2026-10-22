"""Protected tools and the enforcement grant.

THE SECURITY PROPERTY THIS FILE EXISTS FOR:

    Agent -> direct tool call -> protected resource        MUST BE IMPOSSIBLE

Not "discouraged". Not "against convention". Impossible, and testable.

How it is achieved: a protected tool refuses to execute unless it is handed an
`EnforcementGrant`, and only the AEM can mint one -- and only after the PDP
returned ALLOW. Calling a protected tool directly raises
`EnforcementBypassError` before any resource access happens.

A grant is bound to the request, the tool, the subject and the resource, and is
SINGLE-USE. So a grant cannot be:

    * fabricated            -- minting is a module-private operation
    * reused                -- consumed on first use
    * redirected            -- bound to one tool name and one resource id
    * borrowed              -- bound to the subject the PDP decided about

MCP NOTE (future): the adapter shape here -- named tool, JSON-schema parameters,
declared resource/action -- is deliberately MCP-compatible so a future MCP
gateway can front these same tools with the AEM still in the path:

    Agent -> MCP -> AEM -> PDP -> Tool

MCP itself is NOT implemented in Phase 4.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from app.agents.base import ToolSpec
from app.enforcement.resources import (
    CREDIT_RECORDS,
    LOAN_APPLICATIONS,
    PAYMENT_INSTRUCTIONS,
    PAYROLL_RECORDS,
    approve_loan_application,
    execute_payment_instruction,
    get_credit_record,
    get_payroll_record,
)


class EnforcementBypassError(PermissionError):
    """A protected tool was invoked without a valid enforcement grant.

    This is a hard failure, never a warning. Reaching it means something tried
    to skip the AEM/PDP path.
    """


class GrantAlreadyUsedError(EnforcementBypassError):
    """A single-use grant was presented twice."""


class AmbiguousEnforcementPath(RuntimeError):
    """Two protected tools claim the same (action, resource_type) pair.

    A construction error, surfaced loudly: an ambiguous enforcement path is
    one an attacker gets to choose between.
    """


# Module-private sentinel. A grant is only valid if it was constructed with
# this, which only `mint_grant` below possesses. Constructing EnforcementGrant
# directly from outside this module produces an object that will be rejected.
_MINT_TOKEN = object()


@dataclass
class EnforcementGrant:
    """Proof that the PDP allowed one specific invocation.

    Carries no authority of its own: it is evidence a decision was made, bound
    tightly enough that it cannot be applied to a different call.
    """

    request_id: str
    tool_name: str
    subject_did: str
    resource_type: str
    resource_id: str | None
    policy_ref: str | None
    _token: Any = field(repr=False, default=None)
    grant_id: str = field(default_factory=lambda: f"grant-{uuid.uuid4().hex[:16]}")
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    consumed: bool = False

    @property
    def authentic(self) -> bool:
        return self._token is _MINT_TOKEN

    def consume(self, *, tool_name: str, subject_did: str, resource_id: str | None) -> None:
        """Validate the binding and spend the grant. Raises on any mismatch."""
        if not self.authentic:
            raise EnforcementBypassError(
                "Enforcement grant was not issued by the AEM; refusing to execute."
            )
        if self.consumed:
            raise GrantAlreadyUsedError(
                f"Grant {self.grant_id} has already been used. Each PDP decision "
                f"authorises exactly one invocation."
            )
        if self.tool_name != tool_name:
            raise EnforcementBypassError(
                f"Grant {self.grant_id} authorises {self.tool_name!r}, "
                f"not {tool_name!r}."
            )
        if self.subject_did != subject_did:
            raise EnforcementBypassError(
                f"Grant {self.grant_id} was issued to a different subject."
            )
        if self.resource_id != resource_id:
            raise EnforcementBypassError(
                f"Grant {self.grant_id} authorises resource {self.resource_id!r}, "
                f"not {resource_id!r}."
            )
        self.consumed = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "subject": self.subject_did,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "policy": self.policy_ref,
            "issued_at": self.issued_at.isoformat(),
            "consumed": self.consumed,
        }


def mint_grant(
    *,
    request_id: str,
    tool_name: str,
    subject_did: str,
    resource_type: str,
    resource_id: str | None,
    policy_ref: str | None,
) -> EnforcementGrant:
    """Mint a grant. Called by the AEM only, and only after a PDP ALLOW."""
    return EnforcementGrant(
        request_id=request_id,
        tool_name=tool_name,
        subject_did=subject_did,
        resource_type=resource_type,
        resource_id=resource_id,
        policy_ref=policy_ref,
        _token=_MINT_TOKEN,
    )


@dataclass
class ProtectedTool:
    """A tool that can only be reached through the enforcement boundary."""

    spec: ToolSpec
    handler: Callable[..., Any]
    # Which argument names the resource instance, so the AEM can bind the
    # authorization request to a specific record rather than a whole table.
    resource_id_argument: str = "customer_id"

    async def __call__(self, *, _grant: EnforcementGrant | None = None, **kwargs: Any) -> Any:
        if _grant is None:
            raise EnforcementBypassError(
                f"{self.spec.name!r} is a protected tool and was called without an "
                f"enforcement grant. The only permitted path is "
                f"agent -> AEM -> PDP -> ALLOW -> tool."
            )
        _grant.consume(
            tool_name=self.spec.name,
            subject_did=_grant.subject_did,
            resource_id=kwargs.get(self.resource_id_argument),
        )
        result = self.handler(**kwargs)
        if isinstance(result, Awaitable):
            result = await result
        return result


class ProtectedToolRegistry:
    """The protected tools.

    NOTE what this is not: it is not the agent's `ToolRegistry`. Protected tools
    are never registered there, so an agent's LLM cannot see them in its prompt
    or select one directly. The agent reaches them only by asking the AEM.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ProtectedTool] = {}

    def register(self, tool: ProtectedTool) -> None:
        self._tools[tool.spec.name] = tool

    def get(self, name: str) -> ProtectedTool | None:
        return self._tools.get(name)

    def for_action(self, action: str, resource_type: str) -> ProtectedTool | None:
        """The tool that enforces one (action, resource_type) pair.

        PHASE 7 NEEDS THIS AND PHASE 4 DID NOT, for a reason worth stating.
        `AEM.enforce()` is called by something that names a tool and is then
        held to that tool's DECLARED action and resource -- so a caller cannot
        describe its own request flatteringly. An A2A transaction arrives the
        other way round: the action and resource are inside the SIGNED
        envelope, and the tool must be derived from them. If the tool name
        came from the caller, an envelope signed for `read` on
        `credit_records` could be executed through the payment tool.

        Returns None when no protected tool enforces that pair, which the AEM
        turns into a hard refusal rather than a fallback. An action with no
        enforcement path is not an action this system performs.
        """
        matches = [
            tool for tool in self._tools.values()
            if tool.spec.action == action and tool.spec.resource == resource_type
        ]
        if len(matches) > 1:
            # Two tools enforcing one pair would make the mapping ambiguous,
            # and an ambiguous enforcement path is one an attacker chooses.
            # Raised rather than resolved: this is a registry construction
            # error, and it should surface at build time.
            raise AmbiguousEnforcementPath(
                f"{len(matches)} protected tools declare "
                f"({action!r}, {resource_type!r}): "
                f"{sorted(t.spec.name for t in matches)}. One action on one "
                f"resource type must have exactly one enforcement path."
            )
        return matches[0] if matches else None

    def names(self) -> list[str]:
        return sorted(self._tools)

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": t.spec.name,
                "description": t.spec.description,
                "required_capability": t.spec.required_capability,
                "resource": t.spec.resource,
                "action": t.spec.action,
                "parameters": t.spec.parameters,
                "protected": True,
            }
            for t in self._tools.values()
        ]

    def __len__(self) -> int:
        return len(self._tools)


def _customer_parameter(description: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"customer_id": {"type": "string", "description": description}},
        "required": ["customer_id"],
    }


def build_default_registry() -> ProtectedToolRegistry:
    """The Phase 4 protected tools.

    `get_credit_profile` is the demonstration tool named in the spec. It is
    reachable by an agent holding a valid credit_analysis credential scoped to
    credit_records, for the loan_assessment purpose.

    `get_payroll_record` exists to be DENIED to that same agent. It is a real
    tool over a real resource; what stops it is policy, not its absence.

    `approve_loan_application` (Phase 5) is the human-approval demonstration.
    The same agent, holding a credential that DOES name `loan_applications`,
    still cannot reach it until a loan officer has approved that specific
    application -- and the approval is spent when it does.

    `execute_payment_instruction` (Phase 7) is the A2A demonstration, and the
    only tool reachable through `enforce_a2a`. It is never named by a caller:
    the AEM derives it from the (action, resource_type) pair inside the signed
    envelope, so an envelope cannot be executed through a tool it was not
    signed for.
    """
    registry = ProtectedToolRegistry()
    registry.register(
        ProtectedTool(
            spec=ToolSpec(
                name="get_credit_profile",
                description="Read a customer's credit profile for a loan assessment.",
                parameters=_customer_parameter("The customer whose credit profile to read"),
                required_capability="credit_analysis",
                resource=CREDIT_RECORDS,
                action="read",
            ),
            handler=get_credit_record,
        )
    )
    registry.register(
        ProtectedTool(
            spec=ToolSpec(
                name="approve_loan_application",
                description=(
                    "Record the decision on a high-value loan application. "
                    "Requires a human approval bound to this exact application."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "application_id": {
                            "type": "string",
                            "description": "The loan application to decide",
                        },
                        "decision_note": {
                            "type": "string",
                            "description": "Free-text note recorded with the decision",
                        },
                    },
                    "required": ["application_id"],
                },
                required_capability="credit_analysis",
                resource=LOAN_APPLICATIONS,
                action="approve_loan",
            ),
            handler=approve_loan_application,
            # The resource is a loan application, not a customer. Binding the
            # grant to the wrong argument would let an approval for one
            # application be spent on another.
            resource_id_argument="application_id",
        )
    )
    registry.register(
        ProtectedTool(
            spec=ToolSpec(
                name="execute_payment_instruction",
                description=(
                    "Execute a payment instruction sent by another agent. "
                    "Requires a verified A2A transaction and every human "
                    "approval the amount requires."
                ),
                parameters={
                    "type": "object",
                    "properties": {
                        "instruction_id": {
                            "type": "string",
                            "description": "The payment instruction to execute",
                        },
                        "expected_amount_inr": {
                            "type": "integer",
                            "description": (
                                "The amount the PDP authorized. The handler "
                                "refuses if the record no longer reads this."
                            ),
                        },
                        "narrative": {
                            "type": "string",
                            "description": "Free-text note recorded with the execution",
                        },
                    },
                    "required": ["instruction_id"],
                },
                required_capability="payment_execution",
                resource=PAYMENT_INSTRUCTIONS,
                action="execute_payment",
            ),
            handler=execute_payment_instruction,
            # The resource is an instruction, not a customer. Binding the
            # grant to the wrong argument would let a decision about one
            # payment be spent on another.
            resource_id_argument="instruction_id",
        )
    )
    registry.register(
        ProtectedTool(
            spec=ToolSpec(
                name="get_payroll_record",
                description="Read a customer's payroll record.",
                parameters=_customer_parameter("The customer whose payroll record to read"),
                required_capability="payroll_access",
                resource=PAYROLL_RECORDS,
                action="read",
            ),
            handler=get_payroll_record,
        )
    )
    return registry
