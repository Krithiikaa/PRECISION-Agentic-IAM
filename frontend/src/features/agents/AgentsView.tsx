import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client";
import { Button, Empty, Field, Panel, StatusPill } from "../../components/ui";
import type { Agent, PresentationReport } from "../../types";
import { CheckList } from "../credentials/VerificationFlow";

export function AgentsView({ agents, onRefresh }: { agents: Agent[]; onRefresh: () => void }) {
  const [selectedDid, setSelectedDid] = useState<string | null>(agents[0]?.did ?? null);
  const [detail, setDetail] = useState<Agent | null>(null);
  const [report, setReport] = useState<PresentationReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selected = agents.find((a) => a.did === selectedDid) ?? agents[0] ?? null;

  const loadDetail = useCallback(async () => {
    if (!selected) return;
    try {
      setDetail(await api.agent(selected.id));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [selected]);

  useEffect(() => {
    setReport(null);
    loadDetail();
  }, [loadDetail]);

  /**
   * Asks the AGENT PROCESS to present a credential.
   *
   * This request goes to the agent's own endpoint, not to the IAM API, because
   * only the agent holds the private key needed for a holder proof. The IAM API
   * then verifies what comes back.
   */
  async function presentAndVerify() {
    if (!selected?.endpoint) return;
    setBusy(true);
    setError(null);
    try {
      const { challenge } = await api.challenge();
      const presented = await api.presentFromAgent(selected.endpoint, {
        challenge,
        domain: "control-center",
      });
      setReport(await api.verifyPresentation(presented.presentation, challenge));
    } catch (e) {
      setError(
        `${(e as Error).message} — the agent process must be reachable at ${selected.endpoint}`,
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.5fr)]">
      <Panel title={`Agents (${agents.length})`} actions={<Button onClick={onRefresh}>Refresh</Button>}>
        {agents.length === 0 ? (
          <Empty>No agents registered.</Empty>
        ) : (
          <ul className="space-y-1.5">
            {agents.map((agent) => (
              <li key={agent.did}>
                <button
                  onClick={() => setSelectedDid(agent.did)}
                  className={`w-full rounded border px-2.5 py-2 text-left transition ${
                    agent.did === selected?.did
                      ? "border-sky-600/50 bg-sky-600/10"
                      : "border-slate-800 hover:border-slate-700 hover:bg-slate-800/40"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-xs text-slate-200">{agent.name}</span>
                    <StatusPill status={agent.status} />
                  </div>
                  <p className="mono mt-0.5 truncate text-[10px] text-slate-500">{agent.did}</p>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {detail ? (
        <div className="space-y-4">
          <Panel title={detail.name} subtitle={detail.purpose ?? undefined}
                 actions={<StatusPill status={detail.status} />}>
            <dl className="grid grid-cols-2 gap-3">
              <Field label="DID" value={detail.did} mono title={detail.did} />
              <Field label="Controller" value={detail.controller_did} mono />
              <Field label="Key algorithm" value={detail.active_key?.algorithm ?? "—"} />
              <Field
                label="Key custody"
                value={detail.active_key?.keystore_backend ?? "—"}
                title="external = the agent holds its own private key"
              />
              <Field label="Endpoint" value={detail.endpoint ?? "—"} mono />
              <Field
                label="Declared capabilities"
                value={detail.capabilities.join(", ") || "none"}
              />
            </dl>
            <div className="mt-3">
              <Field
                label="Public key (multibase)"
                value={detail.active_key?.public_key_multibase ?? "—"}
                mono
              />
              <p className="mt-2 text-[11px] text-slate-500">
                The private key is never returned by any endpoint — no response shape in
                this API can carry one.
              </p>
            </div>
          </Panel>

          <Panel
            title="Credentials held"
            subtitle="What a trusted authority has attested about this agent"
          >
            {!detail.credentials || detail.credentials.length === 0 ? (
              <Empty>This agent holds no credentials.</Empty>
            ) : (
              <ul className="grid gap-2 sm:grid-cols-2">
                {detail.credentials.map((credential) => (
                  <li
                    key={credential.credential_id}
                    className="rounded border border-slate-800 p-2.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-xs text-slate-200">
                        {credential.credential_type}
                      </span>
                      <StatusPill status={credential.status} />
                    </div>
                    <p className="mono mt-1 text-[10px] text-slate-500">
                      expires {new Date(credential.expires_at).toLocaleString()}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel
            title="Holder proof"
            subtitle="Ask the agent process to present its credentials, signed with its own key"
            actions={
              <Button variant="primary" onClick={presentAndVerify} disabled={busy}>
                {busy ? "Presenting…" : "Present & verify"}
              </Button>
            }
          >
            {error && (
              <p className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
                {error}
              </p>
            )}
            {!report && !error && (
              <Empty>
                The presentation is built and signed inside the agent process — the IAM API
                cannot do it, because it does not hold that agent's private key.
              </Empty>
            )}
            {report && (
              <div className="space-y-3">
                <div
                  className={`rounded border px-3 py-2 ${
                    report.valid
                      ? "border-emerald-500/30 bg-emerald-500/10"
                      : "border-rose-500/30 bg-rose-500/10"
                  }`}
                >
                  <p className={`text-sm font-semibold ${report.valid ? "text-emerald-300" : "text-rose-300"}`}>
                    {report.valid ? "✓ PRESENTATION VERIFIED" : "✕ PRESENTATION REJECTED"}
                  </p>
                  <p className="mono mt-0.5 text-[11px] text-slate-400">{report.reason}</p>
                </div>
                <CheckList checks={report.check_details} />
                {report.credentials.map((credential) => (
                  <div key={credential.credential_id ?? "?"} className="border-t border-slate-800 pt-3">
                    <p className="mono mb-1.5 text-[10px] text-slate-500">
                      {credential.credential_type} · {credential.credential_id}
                    </p>
                    <CheckList checks={credential.check_details} />
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      ) : (
        <Panel title="Agent detail">
          <Empty>Select an agent.</Empty>
        </Panel>
      )}
    </div>
  );
}
