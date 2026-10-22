// Shapes returned by the backend. Nothing here is invented client-side.

export interface KeyInfo {
  kid: string;
  algorithm: string;
  public_key_multibase: string;
  keystore_backend: string;
  status: string;
}

export interface CredentialSummary {
  credential_id: string;
  credential_type: string;
  issuer: string;
  subject: string;
  status: string;
  issued_at: string;
  expires_at: string;
  seconds_remaining: number;
  claims?: Record<string, unknown>;
}

export interface Agent {
  id: string;
  did: string;
  name: string;
  agent_type: string;
  status: string;
  purpose: string | null;
  endpoint: string | null;
  capabilities: string[];
  controller_did: string;
  active_key: KeyInfo | null;
  credentials?: CredentialSummary[];
  created_at: string;
  last_activity_at: string | null;
}

export interface Issuer {
  did: string;
  name: string;
  slug: string;
  status: string;
  verification_method: string;
  public_key_multibase: string;
  algorithm: string;
}

export interface VerifiableCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: Record<string, unknown> & { id: string };
  credentialStatus?: { id: string; type: string };
  proof: {
    type: string;
    cryptosuite: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
  };
}

export interface CheckDetail {
  name: string;
  passed: boolean;
  detail: string;
}

export interface VerificationReport {
  valid: boolean;
  reason: string;
  credential_id: string | null;
  issuer: string | null;
  subject: string | null;
  credential_type: string | null;
  expires_at: string | null;
  status: string | null;
  checks: Record<string, boolean>;
  check_details: CheckDetail[];
  verified_at: string;
}

export interface PresentationReport {
  valid: boolean;
  reason: string;
  holder: string | null;
  presentation_id: string | null;
  check_details: CheckDetail[];
  credentials: VerificationReport[];
  verified_at: string;
}

export interface CredentialStatusInfo {
  credential_id: string;
  status: string;
  stored_status: string;
  issued_at: string;
  expires_at: string;
  seconds_remaining: number;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface TraceEvent {
  timestamp: string;
  event_type: string;
  agent_did: string | null;
  resource: string | null;
  action: string | null;
  decision: string | null;
  reason: string | null;
  metadata: Record<string, unknown>;
}

// --- Phase 3: Agent Naming Service -----------------------------------------

export type ANSStatus =
  | "STARTING" | "ACTIVE" | "BUSY" | "DEGRADED"
  | "STALE" | "OFFLINE" | "DRAINING" | "REVOKED" | "TERMINATED";

export interface MatchReason {
  name: string;
  passed: boolean;
  detail: string;
}

export interface ANSAgent {
  did: string;
  name: string;
  agent_type: string | null;
  endpoint: string;
  status: ANSStatus;
  organization: string | null;
  purpose: string | null;
  capabilities: string[];
  credentials: {
    credential_id: string;
    credential_type: string;
    status: string;
    expires_at: string | null;
  }[];
  last_seen: string | null;
  seconds_since_heartbeat: number | null;
  registered_at: string;
  active_tasks: number;
  health: { ok: boolean | null; latency_ms: number | null; checked_at: string | null };
  trust_score: number | null;
}

export interface DiscoveryCandidate extends ANSAgent {
  matched: boolean;
  reason_code: string;
  match_reasons: MatchReason[];
  score: number;
  rank: number | null;
}

export interface DiscoveryOutcome {
  request_id: string;
  query: Record<string, unknown>;
  results: DiscoveryCandidate[];
  rejected: DiscoveryCandidate[];
  candidate_count: number;
  matched_count: number;
  reason: string;
  selected: DiscoveryCandidate | null;
  ans_latency_ms: number;
}

export interface CapabilityEntry {
  capability: string;
  providers: number;
  active_providers: number;
  agents: string[];
}

export interface ResolvedAgent extends ANSAgent {
  did_document: Record<string, unknown> | null;
  identity_status: string;
}


// --- Phase 5: human-in-the-loop ---------------------------------------------
export type ApprovalPresentation = {
  agent: {
    did: string;
    name: string;
    type: string | null;
    status: string | null;
    verified_capabilities: string[];
  };
  action: { name: string; label: string; tool: string; description: string };
  resource: {
    type: string;
    label: string;
    id: string | null;
    detail: Record<string, unknown> & { available: boolean };
  };
  purpose: string;
  request_id: string;
  approval?: {
    required_approvals: number;
    dual_control: boolean;
    explanation: string;
  };
  policy: {
    decision: string;
    reason: string;
    policy: string | null;
    explanation: string;
  };
};

export type ApprovalSignoff = {
  sequence: number;
  subject: string;
  issuer: string;
  username: string | null;
  provider: string | null;
  roles: string[];
  decision: "APPROVED" | "REJECTED";
  decided_at: string;
};

export type ApprovalRequest = {
  approval_id: string;
  request_id: string;
  // Phase 5.5. How many DISTINCT humans policy asked for, how many have
  // signed, and who they were. A dual-control request sitting at 1 of 2 is
  // still PENDING, and without these the queue could not tell "nobody has
  // looked at it" from "one officer has signed and it is waiting for the
  // second".
  required_approvals: number;
  approvals_recorded: number;
  awaiting_approvals: number;
  dual_control: boolean;
  signoffs: ApprovalSignoff[];
  // WHAT was bound, not just its digest -- including the amount the approver
  // agreed to.
  binding: Record<string, unknown>;
  status:
    | "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "CANCELLED" | "CONSUMED";
  decision: "APPROVED" | "REJECTED" | null;
  agent_did: string;
  action: string;
  resource: { type: string; id: string | null };
  purpose: string;
  reason: string | null;
  presentation: ApprovalPresentation;
  requested_at: string;
  request_expires_at: string;
  decided_at: string | null;
  expires_at: string | null;
  consumed_at: string | null;
  first_viewed_at: string | null;
  approver: {
    subject: string;
    username: string | null;
    issuer: string;
    roles: string[];
  } | null;
  binding_sha256: string;
  domain: string;
  artifact: Record<string, unknown> | null;
  artifact_signed_by: string | null;
  session_id: string | null;
  decision_latency_ms: number | null;
};
