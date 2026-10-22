import { useCallback, useEffect, useState } from "react";
import { api } from "./api/client";
import { useEvents } from "./hooks/useEvents";
import { AgentsView } from "./features/agents/AgentsView";
import { CredentialsView } from "./features/credentials/CredentialsView";
import { DiscoveryView } from "./features/discovery/DiscoveryView";
import { IdentityVsCredential } from "./features/identity/IdentityVsCredential";
import { ApprovalsView } from "./features/hitl/ApprovalsView";
import { SignIn } from "./features/hitl/SignIn";
import { LiveTrace } from "./features/trace/LiveTrace";
import type { HumanIdentity } from "./auth/oidc";
import type { Agent } from "./types";

type Tab = "discovery" | "approvals" | "credentials" | "agents" | "concepts";

const TABS: { id: Tab; label: string }[] = [
  { id: "discovery", label: "Discovery" },
  { id: "approvals", label: "Approvals" },
  { id: "credentials", label: "Credentials" },
  { id: "agents", label: "Agents" },
  { id: "concepts", label: "Model" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("discovery");
  const [agents, setAgents] = useState<Agent[]>([]);
  const [identity, setIdentity] = useState<HumanIdentity | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const { events, connected, clear } = useEvents();

  const loadAgents = useCallback(async () => {
    try {
      setAgents(await api.agents());
      setApiError(null);
    } catch (e) {
      setApiError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    loadAgents();
  }, [loadAgents]);

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 bg-slate-900/60 px-5 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-sm font-semibold tracking-wide text-slate-100">
              AGENTIC BANKING CONTROL CENTER
            </h1>
            <p className="mt-0.5 text-[11px] text-slate-500">
              Phase 5.5 · discovery, credentials, authorization and human
              approval, with amount-based limits and dual control. JIT, A2A,
              MCP, sessions and the kill switch are later phases and are not
              implemented.
            </p>
          </div>
          <div className="flex items-center gap-3">
          <nav className="flex gap-1">
            {TABS.map((entry) => (
              <button
                key={entry.id}
                onClick={() => setTab(entry.id)}
                className={`rounded px-3 py-1.5 text-xs font-medium transition ${
                  tab === entry.id
                    ? "bg-slate-700/70 text-slate-100"
                    : "text-slate-500 hover:text-slate-300"
                }`}
              >
                {entry.label}
              </button>
            ))}
          </nav>
          <SignIn identity={identity} onIdentity={setIdentity} />
          </div>
        </div>
      </header>

      {apiError && (
        <p className="border-b border-rose-500/30 bg-rose-500/10 px-5 py-2 text-xs text-rose-200">
          Cannot reach the IAM API: {apiError}. Start it with{" "}
          <span className="mono">scripts/run_local.sh</span>.
        </p>
      )}

      <main className="grid gap-4 p-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          {tab === "discovery" && <DiscoveryView />}
          {tab === "approvals" && <ApprovalsView identity={identity} />}
          {tab === "credentials" && <CredentialsView agents={agents} />}
          {tab === "agents" && <AgentsView agents={agents} onRefresh={loadAgents} />}
          {tab === "concepts" && <IdentityVsCredential />}
        </div>
        <aside className="min-w-0">
          <LiveTrace events={events} connected={connected} onClear={clear} />
        </aside>
      </main>
    </div>
  );
}
