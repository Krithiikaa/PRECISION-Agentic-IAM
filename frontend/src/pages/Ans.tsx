import { useState } from "react";
import { http, type Json } from "../api/client";
import { Badge, Button, Did, Load, Notice, PageHeader, Section, Select, Table, Updated } from "../components/ds";
import { ago } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

const ANS = "http://localhost:8100";
const ans = <T,>(path: string, init?: RequestInit) =>
  fetch(`${ANS}${path}`, { ...init, headers: { "content-type": "application/json" } }).then(async (r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json() as Promise<T>;
  });

export function Ans() {
  const who = useIdentity()?.subject;
  const registry = useResource(() => ans<Json[]>("/api/v1/ans/agents"), [], 15_000);
  const caps = useResource(() => ans<Json[]>("/api/v1/ans/capabilities"), [], 30_000);
  const history = useResource(() => http<Json[]>("/api/v1/audit?event_type=ANS_DISCOVERY_STARTED&limit=25"), [who], 30_000);
  const [capability, setCapability] = useState("credit_analysis");
  const [result, setResult] = useState<Json | null>(null);
  const [error, setError] = useState<string | null>(null);

  const discover = async () => {
    try { setResult(await ans<Json>("/api/v1/ans/discover", { method: "POST", body: JSON.stringify({ capability }) })); setError(null); }
    catch (e) { setError((e as Error).message); }
  };

  return (
    <>
      <PageHeader index="04" eyebrow="Agent Naming Service" title="Discovery is a directory," emphasis="not a permission."
                  actions={<Updated at={registry.updatedAt} onRefresh={registry.reload} />}>
        Agents register with a signed proof and heartbeat to stay discoverable. A discovered agent still has to be
        authorised by the PDP for every action, and the coordinator cross-checks every endpoint against the DID Document.
      </PageHeader>

      <div className="space-y-6">
        <Section title="Registry" hint="As the ANS sees it: liveness and endpoint, not identity status.">
          <Load r={registry} rows={8}>{(rows) => (
            <Table rows={rows} rowKey={(a) => a.did} columns={[
              { key: "agent", label: "Agent", render: (a) => <div><div className="font-medium">{a.name}</div><Did value={a.did} /></div> },
              { key: "status", label: "Status", render: (a) => <Badge>{a.status}</Badge> },
              { key: "beat", label: "Heartbeat", render: (a) => <span className={`text-[12px] ${a.seconds_since_heartbeat > 60 ? "text-warn" : "text-ink-2"}`}>{ago(a.last_seen)}</span> },
              { key: "health", label: "Endpoint probe", render: (a) => a.health ? <Badge tone={a.health.ok ? "ok" : "bad"}>{a.health.ok ? `OK ${a.health.latency_ms} ms` : "FAILED"}</Badge> : <span className="text-faint">—</span> },
              { key: "endpoint", label: "Endpoint", render: (a) => <span className="mono text-[12px] text-ink-2">{a.endpoint}</span> },
              { key: "caps", label: "Capabilities", render: (a) => <span className="text-[12px] text-muted">{a.capabilities.join(", ")}</span> },
            ]} />
          )}</Load>
        </Section>

        <div className="grid gap-6 xl:grid-cols-2">
          <Section title="Run a capability discovery" hint="The same query the coordinator makes.">
            <Load r={caps}>{(list) => (
              <div className="flex flex-wrap items-end gap-3">
                <div className="min-w-56 flex-1">
                  <Select label="Capability" value={capability} onChange={setCapability}>
                    {list.map((c) => <option key={c.capability} value={c.capability}>{c.capability} · {c.active_providers}/{c.providers} active</option>)}
                  </Select>
                </div>
                <Button variant="primary" onClick={discover}>Discover →</Button>
              </div>
            )}</Load>
            {error && <div className="mt-3"><Notice tone="bad">{error}</Notice></div>}
            {result && (
              <div className="mt-5 space-y-3 text-[13px]">
                <div className="flex flex-wrap gap-2">
                  <Badge tone={result.selected ? "ok" : "warn"}>{result.reason}</Badge>
                  <span className="text-muted">{result.matched_count}/{result.candidate_count} matched · {result.ans_latency_ms} ms</span>
                </div>
                {result.selected && <p>Selected: <Did value={result.selected.did} full /> at <span className="mono text-[12px]">{result.selected.endpoint}</span></p>}
                {[...result.results, ...result.rejected].map((c: Json) => (
                  <div key={c.did} className="rounded-lg border border-line px-3 py-2">
                    <div className="flex items-center gap-2"><Badge tone={c.matched ? "ok" : "neutral"}>{c.reason_code}</Badge><Did value={c.did} /></div>
                    <ul className="mt-1 text-[12px] text-muted">
                      {(c.match_reasons ?? []).map((m: Json) => <li key={m.name}>{m.passed ? "✓" : "✗"} {m.name}: {m.detail}</li>)}
                    </ul>
                  </div>
                ))}
                <Notice tone="info">This result authorises nothing. The selected agent's next request is still decided by the PDP.</Notice>
              </div>
            )}
          </Section>

          <Section title="Discovery history" hint="From the audit trail (ANS_DISCOVERY_STARTED).">
            <Load r={history}>{(rows) => rows.length ? (
              <ul className="divide-y divide-line text-[13px]">
                {rows.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center gap-2 py-2">
                    <Did value={e.agent_did} />
                    <span className="text-ink-2">{e.metadata?.capability ?? e.metadata?.task ?? "—"}</span>
                    <span className="ml-auto text-[11.5px] text-faint">{ago(e.timestamp)}</span>
                  </li>
                ))}
              </ul>) : <p className="text-[13px] text-muted">No discoveries recorded.</p>}</Load>
          </Section>
        </div>
      </div>
    </>
  );
}
