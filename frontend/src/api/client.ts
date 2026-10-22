import type {
  Agent, ANSAgent, ApprovalRequest, CapabilityEntry, CredentialStatusInfo,
  CredentialSummary, DiscoveryOutcome, Issuer, PresentationReport,
  ResolvedAgent, VerifiableCredential, VerificationReport,
} from "../types";

// The ANS is a separate service on its own port. The console talks to it
// directly, exactly as the coordinator agent does.
const ANS = "http://localhost:8100";

// The human's OIDC token, attached to every call the console makes. Set by
// the login flow; null when nobody is signed in.
//
// NOTE what this does NOT do: it does not decide whether a call will succeed.
// The console attaches whatever token it has and the server decides. A UI that
// pre-judged permissions would be guessing at policy, and would drift from it.
let bearer: string | null = null;

export function setBearerToken(token: string | null): void {
  bearer = token;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail ?? body.error ?? detail;
    } catch {
      /* keep statusText */
    }
    // The server's refusals are structured: `{error, reason, detail}`. Surface
    // the REASON, because "HUMAN_MAY_NOT_APPROVE_THIS" tells an operator what
    // happened and "403 Forbidden" does not.
    if (detail && typeof detail === "object") {
      const structured = detail as { reason?: string; detail?: string; error?: string };
      detail = structured.reason
        ? `${structured.reason}${structured.detail ? ` - ${structured.detail}` : ""}`
        : (structured.detail ?? structured.error ?? response.statusText);
    }
    throw new Error(`${response.status}: ${detail}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  agents: () => request<Agent[]>("/api/v1/agents"),
  agent: (id: string) => request<Agent>(`/api/v1/agents/${id}`),
  issuers: () => request<Issuer[]>("/api/v1/credentials/issuers"),

  credentials: (subject?: string) =>
    request<CredentialSummary[]>(
      `/api/v1/credentials${subject ? `?subject=${encodeURIComponent(subject)}` : ""}`,
    ),

  credential: (credentialId: string) =>
    request<{ summary: CredentialSummary; credential: VerifiableCredential }>(
      `/api/v1/credentials/${credentialId}`,
    ),

  credentialStatus: (credentialId: string) =>
    request<CredentialStatusInfo>(`/api/v1/credentials/${credentialId}/status`),

  verify: (credential: VerifiableCredential, expectedSubject?: string) =>
    request<VerificationReport>("/api/v1/credentials/verify", {
      method: "POST",
      body: JSON.stringify({ credential, expected_subject: expectedSubject ?? null }),
    }),

  revoke: (credentialId: string, reason: string) =>
    request<CredentialStatusInfo>(`/api/v1/credentials/${credentialId}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  issue: (body: {
    issuer: string; subject: string; credential_type: string;
    claims: Record<string, unknown>; expires_in_seconds?: number;
  }) =>
    request<{ credential_id: string; credential: VerifiableCredential; summary: CredentialSummary }>(
      "/api/v1/credentials/issue",
      { method: "POST", body: JSON.stringify(body) },
    ),

  challenge: () =>
    request<{ challenge: string; single_use_enforced: boolean }>(
      "/api/v1/credentials/challenge",
    ),

  verifyPresentation: (presentation: unknown, expectedChallenge?: string) =>
    request<PresentationReport>("/api/v1/credentials/verify-presentation", {
      method: "POST",
      body: JSON.stringify({
        presentation, expected_challenge: expectedChallenge ?? null,
      }),
    }),

  // --- Phase 3: Agent Naming Service ---------------------------------------
  ansAgents: () => request<ANSAgent[]>(`${ANS}/api/v1/ans/agents`),

  ansCapabilities: () => request<CapabilityEntry[]>(`${ANS}/api/v1/ans/capabilities`),

  ansResolve: (did: string) =>
    request<ResolvedAgent>(`${ANS}/api/v1/ans/resolve/${did}`),

  ansHealth: (did: string) =>
    request<{ did: string; healthy: boolean; detail: string; latency_ms: number }>(
      `${ANS}/api/v1/ans/agents/${did}/health`,
    ),

  discover: (query: {
    capability?: string | null;
    required_credentials?: string[];
    organization?: string | null;
    require_healthy_endpoint?: boolean;
    requester_did?: string;
  }) =>
    request<DiscoveryOutcome>(`${ANS}/api/v1/ans/discover`, {
      method: "POST",
      body: JSON.stringify(query),
    }),

  // Ask the COORDINATOR AGENT to run the whole flow: resolve the capability
  // with its LLM, discover through the ANS, then verify the result. The
  // console does none of this itself.
  coordinate: (body: {
    task: string;
    capability?: string | null;
    required_credentials?: string[];
  }) =>
    request<Record<string, unknown>>("http://localhost:9001/coordinate", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // --- Phase 5: human-in-the-loop ------------------------------------------
  hitlConfig: () => request<import("../auth/oidc").HitlConfig>("/api/v1/hitl/config"),

  whoami: () => request<import("../auth/oidc").HumanIdentity>("/api/v1/hitl/me"),

  approvals: (status?: string) =>
    request<ApprovalRequest[]>(
      `/api/v1/hitl/approvals${status ? `?status=${status}` : ""}`,
    ),

  approval: (approvalId: string) =>
    request<ApprovalRequest>(`/api/v1/hitl/approvals/${approvalId}`),

  decideApproval: (approvalId: string, decision: "APPROVED" | "REJECTED", note?: string) =>
    request<ApprovalRequest>(`/api/v1/hitl/approvals/${approvalId}/decide`, {
      method: "POST",
      body: JSON.stringify({ decision, note: note || null }),
    }),

  hitlHealth: () =>
    request<{
      identity_provider: { available: boolean; detail: string };
      approval_authority: { did: string; present: boolean };
      approval_ttl_seconds: number;
    }>("/api/v1/hitl/health"),

  // Agent processes are reached directly: only the agent itself can produce a
  // holder proof, because only it has its own private key.
  presentFromAgent: (
    endpoint: string,
    body: { capability?: string; challenge?: string; domain?: string },
  ) =>
    request<{ presentation_id: string; presentation: unknown }>(`${endpoint}/present`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
};
