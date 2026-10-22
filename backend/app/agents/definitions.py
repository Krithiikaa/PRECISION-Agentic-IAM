"""The agent catalogue.

Phase 1 gives every agent in the architecture a real identity and a real
runtime. Their *specialised behaviour* is layered on in later phases:

  Phase 5  banking tools + the loan workflow
  Phase 7  A2A transactions (a sender instructs a receiver, signed)
  Phase 8  MCP tool calls through the gateway

Until then each agent runs the same generic AgentRuntime with its own
identity, its own key and its own system prompt. That is the honest state:
the runtime is real, the loan workflow is not built yet.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.db.models.agent import AgentType


@dataclass(frozen=True)
class AgentDefinition:
    slug: str
    name: str
    agent_type: AgentType
    purpose: str
    capabilities: tuple[str, ...]
    system_prompt: str
    port: int
    # Tools the agent will be granted from Phase 5/8. Declared here so the
    # capability model is visible now; the registry stays empty until then.
    planned_tools: tuple[str, ...] = field(default=())


AGENT_DEFINITIONS: dict[str, AgentDefinition] = {
    "coordinator-001": AgentDefinition(
        slug="coordinator-001",
        name="Loan Coordinator Agent",
        agent_type=AgentType.COORDINATOR,
        purpose="Coordinate the loan application workflow across specialist agents.",
        capabilities=("loan_workflow_coordination", "agent_discovery", "specialist_delegation"),
        system_prompt=(
            "You are the Loan Coordinator Agent for a retail bank. You decide which "
            "specialist agents a loan application requires, discover them through the "
            "Agent Naming Service, delegate work to them and assemble their findings. "
            "You never read customer banking records yourself; specialists do that. "
            "Be concise and decisive."
        ),
        port=9001,
    ),
    "kyc-001": AgentDefinition(
        slug="kyc-001",
        name="KYC Verification Agent",
        agent_type=AgentType.KYC,
        purpose="Verify applicant identity against KYC records.",
        capabilities=("kyc_verification", "kyc_record_read"),
        system_prompt=(
            "You are the KYC Verification Agent. You verify an applicant's identity "
            "using KYC records and report verification status, document completeness "
            "and any discrepancies. You do not assess credit or fraud risk."
        ),
        port=9002,
        planned_tools=("get_kyc_record",),
    ),
    "risk-001": AgentDefinition(
        slug="risk-001",
        name="Credit Risk Analysis Agent",
        agent_type=AgentType.RISK,
        purpose="Analyse the financial risk of a loan application.",
        capabilities=("credit_analysis", "financial_data_read", "risk_analysis"),
        system_prompt=(
            "You are the Credit Risk Analysis Agent. You interpret credit scores, "
            "debt-to-income ratios and loan history that have been computed for you, "
            "and you explain what they mean for lending risk. You never perform "
            "arithmetic yourself: the figures you are given are authoritative. "
            "You have no business reading payroll, HR or employee records."
        ),
        port=9003,
        planned_tools=("get_credit_profile", "get_financial_profile", "get_loan_history"),
    ),
    "fraud-001": AgentDefinition(
        slug="fraud-001",
        name="Fraud Detection Agent",
        agent_type=AgentType.FRAUD,
        purpose="Evaluate an application for suspicious patterns.",
        capabilities=("fraud_detection", "transaction_pattern_analysis"),
        system_prompt=(
            "You are the Fraud Detection Agent. You examine fraud history and "
            "transaction patterns for signals of application fraud, identity misuse "
            "or unusual behaviour, and you report a fraud signal level with reasons."
        ),
        port=9004,
        planned_tools=("get_fraud_history", "get_transaction_patterns"),
    ),
    # Two further risk agents. They exist so discovery has to actually choose
    # between real, equally-capable providers rather than resolving to the one
    # obvious answer. Their differences (credentials held, liveness, load) are
    # real and observed, not scripted.
    "risk-002": AgentDefinition(
        slug="risk-002",
        name="Credit Risk Analysis Agent (secondary)",
        agent_type=AgentType.RISK,
        purpose="Analyse the financial risk of a loan application.",
        capabilities=("credit_analysis", "financial_data_read", "risk_analysis"),
        system_prompt=(
            "You are a Credit Risk Analysis Agent. You interpret credit scores, "
            "debt-to-income ratios and loan history that have been computed for "
            "you, and you explain what they mean for lending risk. You never "
            "perform arithmetic yourself."
        ),
        port=9006,
        planned_tools=("get_credit_profile", "get_financial_profile", "get_loan_history"),
    ),
    "risk-003": AgentDefinition(
        slug="risk-003",
        name="Credit Risk Analysis Agent (tertiary)",
        agent_type=AgentType.RISK,
        purpose="Analyse the financial risk of a loan application.",
        capabilities=("credit_analysis", "risk_analysis"),
        system_prompt=(
            "You are a Credit Risk Analysis Agent. You interpret credit scores, "
            "debt-to-income ratios and loan history that have been computed for "
            "you, and you explain what they mean for lending risk. You never "
            "perform arithmetic yourself."
        ),
        port=9007,
        planned_tools=("get_credit_profile", "get_loan_history"),
    ),
    # Phase 7. The RECEIVER of agent-to-agent payment instructions.
    #
    # A distinct agent rather than a role on an existing one, because
    # receiver binding is enforced by requiring the submitter to hold THIS
    # agent's private key -- and a capability-based discovery flow needs a
    # distinct capability to discover it by.
    #
    # NOTE what it does NOT need: a credential over payment_instructions.
    # An A2A transaction authorizes the SENDER, so the receiver's own
    # capability never enters the decision. Giving it one would change
    # nothing, which is the confused-deputy property stated as a fact about
    # the configuration.
    "payments-001": AgentDefinition(
        slug="payments-001",
        name="Payment Execution Agent",
        agent_type=AgentType.DECISION,
        purpose="Execute payment instructions sent by other agents.",
        capabilities=("payment_execution", "settlement"),
        system_prompt=(
            "You are the Payment Execution Agent. You receive signed payment "
            "instructions from other agents and relay them to the IAM plane "
            "for verification and authorization. You never decide whether a "
            "payment may proceed and you never execute one yourself: you "
            "carry the instruction unchanged and report what was decided."
        ),
        port=9008,
        planned_tools=("execute_payment_instruction",),
    ),
    "decision-001": AgentDefinition(
        slug="decision-001",
        name="Loan Decision Agent",
        agent_type=AgentType.DECISION,
        purpose="Combine specialist findings into a final loan recommendation.",
        capabilities=("loan_decision", "risk_result_evaluation"),
        system_prompt=(
            "You are the Loan Decision Agent. You receive the findings of the KYC, "
            "risk and fraud specialists and produce a recommendation with reasons. "
            "You have no access to the banking database and must work only from the "
            "findings handed to you. The final eligibility outcome is determined by "
            "deterministic business rules, not by you; you explain and recommend."
        ),
        port=9005,
    ),
}


def get_definition(slug: str) -> AgentDefinition:
    if slug not in AGENT_DEFINITIONS:
        known = ", ".join(sorted(AGENT_DEFINITIONS))
        raise KeyError(f"Unknown agent slug {slug!r}. Known agents: {known}")
    return AGENT_DEFINITIONS[slug]
