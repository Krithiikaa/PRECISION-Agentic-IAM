import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client";
import { Button, Field, Json, Panel, StatusPill } from "../../components/ui";
import type {
  CapabilityEntry, DiscoveryCandidate, DiscoveryOutcome, MatchReason, ResolvedAgent,
} from "../../types";

const CREDENTIAL_TYPES = [
  "ComplianceCredential",
  "AgentCapabilityCredential",
  "AgentRoleCredential",
];

/** Human labels for the checks the backend actually ran. */
const CHECK_LABELS: Record<string, string> = {
  capability: "Required capability",
  status: "Registry status",
  identity: "Identity is active",
  liveness: "Heartbeat is current",
  organization: "Organization",
  purpose: "Declared purpose",
  trust: "Trust score",
  endpoint_health: "Endpoint health",
};

function checkLabel(name: string): string {
  if (name.startsWith("credential:")) return `Credential: ${name.slice(11)}`;
  return CHECK_LABELS[name] ?? name;
}

function ReasonList({ reasons }: { reasons: MatchReason[] }) {
  return (
    <ul className="space-y-1">
      {reasons.map((reason) => (
        <li key={reason.name} className="flex items-start gap-2">
          <span
            className={`mt-0.5 shrink-0 text-xs ${reason.passed ? "text-emerald-400" : "text-rose-400"}`}
            aria-hidden
          >
            {reason.passed ? "✓" : "✕"}
          </span>
          <div className="min-w-0">
            <p className={`text-[11px] ${reason.passed ? "text-slate-300" : "text-rose-200"}`}>
              {checkLabel(reason.name)}
            </p>
            <p className="mono truncate text-[10px] text-slate-500" title={reason.detail}>
              {reason.detail}
            </p>
          </div>
        </li>
      ))}
    </ul>
  );
}

function CandidateCard({ candidate, onInspect }: {
  candidate: DiscoveryCandidate;
  onInspect: (did: string) => void;
}) {
  const matched = candidate.matched;
  return (
    <div
      className={`rounded border p-3 ${
        matched ? "border-emerald-600/30 bg-emerald-600/5" : "border-slate-800 bg-slate-900/40"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-xs font-medium text-slate-100">
            {candidate.rank ? `#${candidate.rank} ` : ""}{candidate.name}
          </p>
          <p className="mono truncate text-[10px] text-slate-500">{candidate.did}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {matched && (
            <span className="mono text-[10px] text-emerald-300">score {candidate.score}</span>
          )}
          <StatusPill status={candidate.status} />
        </div>
      </div>

      {!matched && (
        <p className="mono mt-2 rounded border border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[10px] text-rose-200">
          FILTERED · {candidate.reason_code}
        </p>
      )}

      <dl className="mt-2 grid grid-cols-2 gap-2">
        <Field label="Endpoint" value={candidate.endpoint} mono />
        <Field
          label="Heartbeat"
          value={
            candidate.seconds_since_heartbeat === null
              ? "—"
              : `${Math.round(candidate.seconds_since_heartbeat)}s ago`
          }
        />
        <Field label="Load" value={`${candidate.active_tasks} in flight`} />
        <Field
          label="Endpoint health"
          value={
            candidate.health.ok === null
              ? "not probed"
              : candidate.health.ok
                ? `healthy · ${candidate.health.latency_ms}ms`
                : "unhealthy"
          }
        />
      </dl>

      <div className="mt-2">
        <p className="mb-1 text-[10px] uppercase tracking-[0.12em] text-slate-500">
          {matched ? "Matched because" : "Rejected because"}
        </p>
        <ReasonList reasons={candidate.match_reasons} />
      </div>

      <div className="mt-2 flex gap-2">
        <Button onClick={() => onInspect(candidate.did)}>Inspect</Button>
      </div>
    </div>
  );
}

export function DiscoveryView() {
  const [capabilities, setCapabilities] = useState<CapabilityEntry[]>([]);
  const [capability, setCapability] = useState("credit_analysis");
  const [credential, setCredential] = useState("");
  const [requireHealthy, setRequireHealthy] = useState(false);
  const [outcome, setOutcome] = useState<DiscoveryOutcome | null>(null);
  const [resolved, setResolved] = useState<ResolvedAgent | null>(null);
  const [coordination, setCoordination] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadCapabilities = useCallback(async () => {
    try {
      const entries = await api.ansCapabilities();
      setCapabilities(entries);
      if (!entries.some((e) => e.capability === capability) && entries.length) {
        setCapability(entries[0].capability);
      }
      setError(null);
    } catch (e) {
      setError(`${(e as Error).message} — is the ANS running on :8100?`);
    }
  }, [capability]);

  useEffect(() => {
    loadCapabilities();
    const timer = setInterval(loadCapabilities, 15_000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function search() {
    setBusy("search");
    setError(null);
    setResolved(null);
    try {
      setOutcome(await api.discover({
        capability: capability || null,
        required_credentials: credential ? [credential] : [],
        require_healthy_endpoint: requireHealthy,
        requester_did: "did:poc:agent:coordinator-001",
      }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  /** Hand the whole job to the coordinator agent, LLM capability choice included. */
  async function askCoordinator() {
    setBusy("coordinate");
    setError(null);
    try {
      const result = await api.coordinate({
        task: "Analyze credit risk for USER-007.",
        required_credentials: credential ? [credential] : [],
      });
      setCoordination(result);
      setOutcome((result.discovery as DiscoveryOutcome) ?? null);
    } catch (e) {
      setError(`${(e as Error).message} — the coordinator agent must be reachable on :9001`);
    } finally {
      setBusy(null);
    }
  }

  async function inspect(did: string) {
    setBusy("inspect");
    try {
      setResolved(await api.ansResolve(did));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const noMatch = outcome && outcome.matched_count === 0;

  return (
    <div className="space-y-4">
      <Panel
        title="Discover an agent"
        subtitle="Queries the Agent Naming Service. Discovery is not authorization — the PDP arrives in Phase 4."
      >
        {error && (
          <p className="mb-3 rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
            {error}
          </p>
        )}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <label className="block">
            <span className="text-[10px] uppercase tracking-[0.12em] text-slate-500">
              Capability
            </span>
            <select
              value={capability}
              onChange={(e) => setCapability(e.target.value)}
              className="mono mt-1 w-full rounded border border-slate-800 bg-slate-950/60 px-2 py-1.5 text-xs text-slate-200"
            >
              {capabilities.map((entry) => (
                <option key={entry.capability} value={entry.capability}>
                  {entry.capability} ({entry.active_providers}/{entry.providers} active)
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="text-[10px] uppercase tracking-[0.12em] text-slate-500">
              Required credential
            </span>
            <select
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
              className="mono mt-1 w-full rounded border border-slate-800 bg-slate-950/60 px-2 py-1.5 text-xs text-slate-200"
            >
              <option value="">(none)</option>
              {CREDENTIAL_TYPES.map((type) => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
          </label>

          <label className="flex items-end gap-2 pb-1.5">
            <input
              type="checkbox"
              checked={requireHealthy}
              onChange={(e) => setRequireHealthy(e.target.checked)}
              className="h-3.5 w-3.5 accent-sky-500"
            />
            <span className="text-xs text-slate-300">Healthy endpoint only</span>
          </label>

          <div className="flex items-end gap-2">
            <Button variant="primary" onClick={search} disabled={busy !== null}>
              {busy === "search" ? "Searching…" : "Search"}
            </Button>
            <Button
              onClick={askCoordinator}
              disabled={busy !== null}
              title="The coordinator agent picks the capability with its LLM, then discovers"
            >
              {busy === "coordinate" ? "Coordinating…" : "Ask coordinator"}
            </Button>
          </div>
        </div>
      </Panel>

      {coordination && (
        <Panel
          title="Coordinator"
          subtitle="The coordinator holds no endpoint table; it resolved this at runtime"
          actions={<Button onClick={() => setCoordination(null)}>Dismiss</Button>}
        >
          <CoordinationSummary outcome={coordination} />
        </Panel>
      )}

      {outcome && (
        <Panel
          title={`Results — ${outcome.matched_count} of ${outcome.candidate_count} eligible`}
          subtitle={`request ${outcome.request_id} · ANS answered in ${outcome.ans_latency_ms}ms`}
        >
          {noMatch ? (
            <div className="rounded border border-amber-500/30 bg-amber-500/10 p-4">
              <p className="text-sm font-semibold text-amber-200">NO SUITABLE AGENT FOUND</p>
              <dl className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
                <Field label="Capability" value={capability} mono />
                <Field label="Required" value={credential || "—"} mono />
                <Field label="Candidates checked" value={String(outcome.candidate_count)} />
                <Field label="Eligible" value="0" />
              </dl>
              <p className="mt-2 text-[11px] text-amber-200/80">
                Reason: {outcome.reason}. No agent was substituted — the system fails
                honestly rather than routing work somewhere unsuitable.
              </p>
            </div>
          ) : (
            <div className="grid gap-3 lg:grid-cols-2">
              {outcome.results.map((candidate) => (
                <CandidateCard key={candidate.did} candidate={candidate} onInspect={inspect} />
              ))}
            </div>
          )}

          {outcome.rejected.length > 0 && (
            <div className="mt-4">
              <p className="mb-2 text-[10px] uppercase tracking-[0.12em] text-slate-500">
                Filtered out ({outcome.rejected.length})
              </p>
              <div className="grid gap-3 lg:grid-cols-2">
                {outcome.rejected.map((candidate) => (
                  <CandidateCard key={candidate.did} candidate={candidate} onInspect={inspect} />
                ))}
              </div>
            </div>
          )}
        </Panel>
      )}

      {resolved && (
        <Panel
          title={resolved.name}
          subtitle="Resolved through the ANS; the DID Document comes from the identity registry"
          actions={<Button onClick={() => setResolved(null)}>Close</Button>}
        >
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Field label="DID" value={resolved.did} mono />
            <Field label="Endpoint" value={resolved.endpoint} mono />
            <Field label="Registry status" value={<StatusPill status={resolved.status} />} />
            <Field label="Identity status" value={resolved.identity_status} />
            <Field label="Organization" value={resolved.organization ?? "—"} mono />
            <Field label="Registered" value={new Date(resolved.registered_at).toLocaleString()} />
            <Field label="Capabilities" value={resolved.capabilities.join(", ")} />
            <Field
              label="Trust score"
              value={resolved.trust_score ?? "not scored (Phase 10)"}
            />
            <Field
              label="Last heartbeat"
              value={
                resolved.seconds_since_heartbeat === null
                  ? "—"
                  : `${Math.round(resolved.seconds_since_heartbeat)}s ago`
              }
            />
          </dl>
          <div className="mt-3">
            <p className="mb-1 text-[10px] uppercase tracking-[0.12em] text-slate-500">
              Credentials indexed
            </p>
            {resolved.credentials.length === 0 ? (
              <p className="text-xs text-slate-500">none</p>
            ) : (
              <ul className="grid gap-1 sm:grid-cols-2">
                {resolved.credentials.map((c) => (
                  <li key={c.credential_id} className="flex items-center justify-between gap-2 rounded border border-slate-800 px-2 py-1">
                    <span className="truncate text-[11px] text-slate-300">{c.credential_type}</span>
                    <StatusPill status={c.status} />
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-1.5 text-[10px] text-slate-500">
              This index records what the agent claimed at registration. Discovery
              re-verifies every credential live, so a stale row cannot let a revoked
              credential through.
            </p>
          </div>
          <div className="mt-3">
            <p className="mb-1 text-[10px] uppercase tracking-[0.12em] text-slate-500">
              DID Document
            </p>
            <Json value={resolved.did_document} />
          </div>
        </Panel>
      )}
    </div>
  );
}

function CoordinationSummary({ outcome }: { outcome: Record<string, unknown> }) {
  const capability = outcome.capability as
    | { capability: string; rationale: string; llm?: { model: string; latency_ms: number } }
    | null;
  const selected = outcome.selected as { did: string; endpoint: string } | null;
  const verification = (outcome.verification ?? []) as MatchReason[];

  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Field label="Task" value={String(outcome.task)} />
        <Field label="Capability chosen" value={capability?.capability ?? "—"} mono />
        <Field label="Decided by" value={capability?.llm?.model ?? "caller"} mono />
        <Field label="Outcome" value={String(outcome.reason)} mono />
      </dl>
      {capability?.rationale && (
        <p className="text-[11px] italic text-slate-400">“{capability.rationale}”</p>
      )}
      {selected && (
        <dl className="grid grid-cols-2 gap-3">
          <Field label="Selected" value={selected.did} mono />
          <Field label="Endpoint (resolved at runtime)" value={selected.endpoint} mono />
        </dl>
      )}
      {verification.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] uppercase tracking-[0.12em] text-slate-500">
            Coordinator cross-checks the directory against the identity authority
          </p>
          <ReasonList reasons={verification} />
        </div>
      )}
      <p className="rounded border border-slate-700 bg-slate-800/40 px-2 py-1.5 text-[10px] text-slate-400">
        {String((outcome.authorization as { note: string })?.note ?? "")}
      </p>
    </div>
  );
}
