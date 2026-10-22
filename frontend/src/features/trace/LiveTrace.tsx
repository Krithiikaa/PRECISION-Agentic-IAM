import { useMemo, useState } from "react";
import { Button, Empty, Panel } from "../../components/ui";
import type { TraceEvent } from "../../types";

/**
 * The live IAM trace.
 *
 * Every line comes from GET /api/v1/events/stream, i.e. from the backend's real
 * event bus. When the backend does nothing, this panel shows nothing.
 */

const EVENT_STYLE: Record<string, { icon: string; tone: string }> = {
  CREDENTIAL_ISSUED: { icon: "🎫", tone: "text-sky-300" },
  CREDENTIAL_STORED: { icon: "💾", tone: "text-slate-400" },
  CREDENTIAL_PRESENTED: { icon: "🔐", tone: "text-sky-300" },
  CREDENTIAL_VERIFICATION_STARTED: { icon: "🔎", tone: "text-slate-400" },
  CREDENTIAL_VERIFIED: { icon: "✓", tone: "text-emerald-300" },
  CREDENTIAL_VERIFICATION_FAILED: { icon: "✕", tone: "text-rose-300" },
  CREDENTIAL_SIGNATURE_INVALID: { icon: "✕", tone: "text-rose-300" },
  CREDENTIAL_SUBJECT_MISMATCH: { icon: "✕", tone: "text-rose-300" },
  CREDENTIAL_ISSUER_UNKNOWN: { icon: "✕", tone: "text-rose-300" },
  CREDENTIAL_REVOKED: { icon: "⛔", tone: "text-rose-300" },
  CREDENTIAL_REVOKED_REJECTED: { icon: "⛔", tone: "text-rose-300" },
  CREDENTIAL_EXPIRED: { icon: "⏱", tone: "text-amber-300" },
  PRESENTATION_VERIFIED: { icon: "✓", tone: "text-emerald-300" },
  PRESENTATION_VERIFICATION_FAILED: { icon: "✕", tone: "text-rose-300" },
  AGENT_CREATED: { icon: "🤖", tone: "text-sky-300" },
  DID_ASSIGNED: { icon: "🆔", tone: "text-slate-300" },
  KEY_GENERATED: { icon: "🔑", tone: "text-slate-300" },
  DID_DOCUMENT_PUBLISHED: { icon: "📄", tone: "text-slate-300" },
  AGENT_ACTIVATED: { icon: "●", tone: "text-emerald-300" },
  AGENT_TERMINATED: { icon: "◼", tone: "text-rose-300" },
  SIGNATURE_CREATED: { icon: "✎", tone: "text-slate-300" },
  SIGNATURE_VERIFIED: { icon: "✓", tone: "text-emerald-300" },
  SIGNATURE_INVALID: { icon: "✕", tone: "text-rose-300" },
  AGENT_TASK_STARTED: { icon: "▶", tone: "text-slate-300" },
  AGENT_TASK_COMPLETED: { icon: "✓", tone: "text-emerald-300" },
  AGENT_TASK_FAILED: { icon: "✕", tone: "text-rose-300" },
  LLM_CALL: { icon: "🧠", tone: "text-violet-300" },
  ANS_AGENT_REGISTERED: { icon: "📗", tone: "text-sky-300" },
  ANS_AGENT_UPDATED: { icon: "📗", tone: "text-slate-400" },
  ANS_REGISTRATION_REJECTED: { icon: "⛔", tone: "text-rose-300" },
  ANS_SIGNATURE_INVALID: { icon: "✕", tone: "text-rose-300" },
  ANS_HEARTBEAT_RECEIVED: { icon: "·", tone: "text-slate-600" },
  ANS_AGENT_STALE: { icon: "⏳", tone: "text-amber-300" },
  ANS_AGENT_OFFLINE: { icon: "◼", tone: "text-rose-300" },
  ANS_AGENT_REVOKED: { icon: "⛔", tone: "text-rose-300" },
  ANS_AGENT_RESOLVED: { icon: "🧭", tone: "text-sky-300" },
  ANS_DISCOVERY_STARTED: { icon: "🔎", tone: "text-sky-300" },
  ANS_DISCOVERY_MATCH: { icon: "✓", tone: "text-emerald-300" },
  ANS_DISCOVERY_REJECTED: { icon: "✕", tone: "text-amber-300" },
  ANS_DISCOVERY_NO_MATCH: { icon: "∅", tone: "text-amber-300" },
  ANS_AGENT_SELECTED: { icon: "★", tone: "text-emerald-300" },
  COORDINATOR_CAPABILITY_RESOLVED: { icon: "🧭", tone: "text-violet-300" },
  COORDINATOR_DISCOVERY_COMPLETE: { icon: "✓", tone: "text-emerald-300" },
  COORDINATOR_DISCOVERY_FAILED: { icon: "✕", tone: "text-rose-300" },

  // Phase 4 - authorization and enforcement. These are real backend events
  // written to audit_events by the PDP and the AEM; nothing here is synthesised
  // in the browser.
  AUTHORIZATION_REQUESTED: { icon: "⚖", tone: "text-violet-300" },
  PIP_CONTEXT_COLLECTED: { icon: "🧩", tone: "text-slate-400" },
  PDP_EVALUATION: { icon: "⚖", tone: "text-violet-300" },
  OPA_DECISION: { icon: "📜", tone: "text-violet-300" },
  POLICY_ALLOW: { icon: "✓", tone: "text-emerald-300" },
  POLICY_DENY: { icon: "⛔", tone: "text-rose-300" },
  POLICY_HUMAN_APPROVAL_REQUIRED: { icon: "🙋", tone: "text-amber-300" },
  AUTHORIZATION_UNAVAILABLE: { icon: "⚠", tone: "text-rose-300" },
  AEM_INTERCEPT: { icon: "🛡", tone: "text-sky-300" },
  AEM_ALLOWED: { icon: "🔓", tone: "text-emerald-300" },
  AEM_BLOCKED: { icon: "🔒", tone: "text-rose-300" },
  AEM_BYPASS_ATTEMPT: { icon: "🚨", tone: "text-rose-300" },
  TOOL_EXECUTED: { icon: "🔧", tone: "text-emerald-300" },
  POLICY_LOADED: { icon: "📜", tone: "text-slate-400" },
  POLICY_ACTIVATED: { icon: "📜", tone: "text-emerald-300" },
  POLICY_DEACTIVATED: { icon: "📜", tone: "text-amber-300" },

  // Phase 4.5 - control-plane hardening. Authentication and authorization are
  // shown as SEPARATE events on purpose: "we could not tell who you are" and
  // "we know exactly who you are and you may not do that" are different
  // incidents, and an operator watching this stream needs to tell them apart
  // at a glance.
  CONTROL_PLANE_AUTHENTICATED: { icon: "🔑", tone: "text-sky-300" },
  CONTROL_PLANE_AUTHORIZED: { icon: "✓", tone: "text-emerald-300" },
  CONTROL_PLANE_REJECTED: { icon: "⛔", tone: "text-rose-300" },
  CONTROL_PLANE_DENIED: { icon: "⛔", tone: "text-rose-300" },
  CONTROL_PLANE_REPLAY_DETECTED: { icon: "🚨", tone: "text-rose-300" },
  CONTROL_PLANE_PRINCIPAL_REGISTERED: { icon: "🔑", tone: "text-slate-400" },
  ANS_HEARTBEAT_ACCEPTED: { icon: "♥", tone: "text-slate-400" },
  ANS_HEARTBEAT_REJECTED: { icon: "🚨", tone: "text-rose-300" },
  ANS_DEREGISTRATION_ACCEPTED: { icon: "↩", tone: "text-amber-300" },
  ANS_DEREGISTRATION_REJECTED: { icon: "🚨", tone: "text-rose-300" },
  AUTHORIZATION_API_REJECTED: { icon: "🚨", tone: "text-rose-300" },

  // Phase 5 - human-in-the-loop. Real backend events, in the order a loan
  // decision actually produces them:
  //
  //   AUTHORIZATION -> HUMAN_APPROVAL_REQUIRED
  //   HUMAN         -> approval requested
  //   HUMAN         -> officer authenticated
  //   HUMAN         -> approval viewed, then submitted
  //   AUTHORIZATION -> PDP RE-EVALUATION
  //   AUTHORIZATION -> ALLOW
  //   ENFORCEMENT   -> action executed
  //
  // Authentication and approval are separate icons on purpose: "Keycloak says
  // this is Priya" and "Priya approved this loan" are different facts.
  HUMAN_AUTHENTICATED: { icon: "👤", tone: "text-sky-300" },
  HUMAN_AUTHENTICATION_FAILED: { icon: "🚨", tone: "text-rose-300" },
  HUMAN_PRINCIPAL_REGISTERED: { icon: "👤", tone: "text-slate-400" },
  APPROVAL_REQUESTED: { icon: "🙋", tone: "text-amber-300" },
  APPROVAL_VIEWED: { icon: "👁", tone: "text-slate-400" },
  APPROVAL_APPROVED: { icon: "✓", tone: "text-emerald-300" },
  APPROVAL_REJECTED: { icon: "⛔", tone: "text-rose-300" },
  APPROVAL_EXPIRED: { icon: "⏱", tone: "text-amber-300" },
  APPROVAL_CANCELLED: { icon: "↩", tone: "text-slate-400" },
  APPROVAL_CONSUMED: { icon: "🔑", tone: "text-sky-300" },
  APPROVAL_REPLAY_REJECTED: { icon: "🚨", tone: "text-rose-300" },
  // The event that proves a human decision did not become an ALLOW on its own.
  AUTHORIZATION_REEVALUATED: { icon: "⚖", tone: "text-violet-300" },
};

function time(timestamp: string): string {
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime())
    ? timestamp
    : parsed.toISOString().slice(11, 23);
}

export function LiveTrace({ events, connected, onClear }: {
  events: TraceEvent[]; connected: boolean; onClear: () => void;
}) {
  const [filter, setFilter] = useState("");
  const [showHeartbeats, setShowHeartbeats] = useState(false);

  const shown = useMemo(() => {
    let list = events;
    // Heartbeats arrive every 15s per agent and drown everything else.
    if (!showHeartbeats) {
      list = list.filter((event) => event.event_type !== "ANS_HEARTBEAT_RECEIVED");
    }
    if (!filter) return list;
    const needle = filter.toLowerCase();
    return list.filter((event) =>
      `${event.event_type} ${event.agent_did ?? ""} ${event.reason ?? ""}`
        .toLowerCase()
        .includes(needle),
    );
  }, [events, filter, showHeartbeats]);

  return (
    <Panel
      title="Agentic IAM live trace"
      subtitle="Streamed from the backend event bus — nothing here is generated by the UI"
      actions={
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wide ${
              connected ? "text-emerald-400" : "text-rose-400"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-current" />
            {connected ? "live" : "disconnected"}
          </span>
          <Button onClick={onClear}>Clear</Button>
        </div>
      }
      className="h-full"
    >
      <input
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
        placeholder="Filter events…"
        className="w-full rounded border border-slate-800 bg-slate-950/60 px-2.5 py-1.5 text-xs
                   text-slate-200 placeholder:text-slate-600 focus:border-slate-600 focus:outline-none"
      />
      <label className="mb-3 mt-1.5 flex items-center gap-1.5 text-[10px] text-slate-500">
        <input
          type="checkbox"
          checked={showHeartbeats}
          onChange={(e) => setShowHeartbeats(e.target.checked)}
          className="h-3 w-3 accent-sky-500"
        />
        show ANS heartbeats
      </label>
      <div className="max-h-[calc(100vh-16rem)] space-y-1 overflow-y-auto pr-1">
        {shown.length === 0 ? (
          <Empty>
            {connected
              ? "Waiting for backend events. Issue or verify a credential to see the trace."
              : "Not connected to the event stream."}
          </Empty>
        ) : (
          shown.map((event, index) => {
            const style = EVENT_STYLE[event.event_type] ?? { icon: "·", tone: "text-slate-400" };
            return (
              <div
                key={`${event.timestamp}-${index}`}
                className="flex items-start gap-2 rounded px-1.5 py-1 hover:bg-slate-800/40"
              >
                <span className="mono shrink-0 text-[10px] text-slate-600">
                  {time(event.timestamp)}
                </span>
                <span className={`shrink-0 text-[11px] ${style.tone}`}>{style.icon}</span>
                <div className="min-w-0 flex-1">
                  <p className={`mono text-[11px] ${style.tone}`}>{event.event_type}</p>
                  {(event.agent_did || event.reason) && (
                    <p className="mono truncate text-[10px] text-slate-600">
                      {event.agent_did?.replace("did:poc:agent:", "") ?? ""}
                      {event.reason ? ` · ${event.reason}` : ""}
                    </p>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </Panel>
  );
}
