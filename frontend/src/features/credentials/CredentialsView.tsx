import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client";
import { Button, Empty, Panel, StatusPill } from "../../components/ui";
import type { Agent, CredentialSummary, Issuer } from "../../types";
import { CredentialDetail } from "./CredentialDetail";

const DEMO_TTL_SECONDS = 15;

export function CredentialsView({ agents }: { agents: Agent[] }) {
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [creds, issuerList] = await Promise.all([api.credentials(), api.issuers()]);
      setCredentials(creds);
      setIssuers(issuerList);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load();
    // Statuses change with wall-clock time (expiry), so re-read periodically.
    const timer = setInterval(load, 10_000);
    return () => clearInterval(timer);
  }, [load]);

  async function issueShortLived() {
    const risk = agents.find((a) => a.did === "did:poc:agent:risk-001") ?? agents[0];
    if (!risk) return;
    setBusy(true);
    try {
      const result = await api.issue({
        issuer: "did:poc:organization:bank-demo",
        subject: risk.did,
        credential_type: "AgentCapabilityCredential",
        claims: {
          capability: "credit_analysis",
          allowed_actions: ["READ_CREDIT_PROFILE"],
          allowed_resources: ["credit_records"],
          purpose: "expiry_demo",
        },
        expires_in_seconds: DEMO_TTL_SECONDS,
      });
      await load();
      setSelected(result.credential_id);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const current = credentials.find((c) => c.credential_id === selected) ?? null;

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)]">
      <div className="space-y-4">
        <Panel
          title="Trust roots"
          subtitle="Issuing authorities. Each holds its own Ed25519 key; no agent has one."
        >
          {issuers.length === 0 ? (
            <Empty>No issuers registered.</Empty>
          ) : (
            <ul className="space-y-2">
              {issuers.map((issuer) => (
                <li key={issuer.did} className="rounded border border-slate-800 p-2.5">
                  <p className="text-xs font-medium text-slate-200">{issuer.name}</p>
                  <p className="mono mt-0.5 truncate text-[10px] text-slate-500">{issuer.did}</p>
                  <p className="mono mt-1 truncate text-[10px] text-slate-600">
                    {issuer.public_key_multibase}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title={`Credentials (${credentials.length})`}
          actions={
            <div className="flex gap-2">
              <Button onClick={load}>Refresh</Button>
              <Button
                onClick={issueShortLived}
                disabled={busy}
                title={`Issues a credential with a ${DEMO_TTL_SECONDS}s TTL so expiry can be watched`}
              >
                Issue {DEMO_TTL_SECONDS}s credential
              </Button>
            </div>
          }
        >
          {error && (
            <p className="mb-2 rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
              {error}
            </p>
          )}
          {credentials.length === 0 ? (
            <Empty>
              No credentials issued yet. Run <span className="mono">scripts/seed_credentials.py</span>.
            </Empty>
          ) : (
            <ul className="space-y-1.5">
              {credentials.map((credential) => {
                const active = credential.credential_id === selected;
                const subject = credential.subject?.replace("did:poc:agent:", "") ?? "—";
                return (
                  <li key={credential.credential_id}>
                    <button
                      onClick={() => setSelected(credential.credential_id)}
                      className={`w-full rounded border px-2.5 py-2 text-left transition ${
                        active
                          ? "border-sky-600/50 bg-sky-600/10"
                          : "border-slate-800 hover:border-slate-700 hover:bg-slate-800/40"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-xs text-slate-200">
                          {credential.credential_type}
                        </span>
                        <StatusPill status={credential.status} />
                      </div>
                      <p className="mono mt-0.5 truncate text-[10px] text-slate-500">
                        {subject} · {credential.credential_id.replace("urn:uuid:", "")}
                      </p>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </Panel>
      </div>

      <div>
        {current ? (
          <CredentialDetail summary={current} onChanged={load} />
        ) : (
          <Panel title="Credential detail">
            <Empty>Select a credential to inspect its claims, proof and verification.</Empty>
          </Panel>
        )}
      </div>
    </div>
  );
}
