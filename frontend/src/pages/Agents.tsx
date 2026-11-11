import { useState } from "react";
import { http, type Json } from "../api/client";
import { Badge, Did, Kv, Load, PageHeader, Section, Table, Updated } from "../components/ds";
import { ago } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

const ANS = "http://localhost:8100";

export function Agents() {
  const who = useIdentity()?.subject;
  const agents = useResource(() => http<Json[]>("/api/v1/agents"), [who], 20_000);
  const ans = useResource(() => fetch(`${ANS}/api/v1/ans/agents`).then((r) => r.json() as Promise<Json[]>), [], 20_000);
  const trust = useResource(() => http<Json>("/api/v1/security/trust"), [who], 20_000);
  const [selected, setSelected] = useState<Json | null>(null);

  const ansBy = new Map((ans.data ?? []).map((a) => [a.did, a]));
  const trustBy = new Map(((trust.data?.agents ?? []) as Json[]).map((t) => [t.agent_did, t]));

  return (
    <>
      <PageHeader index="02" eyebrow="Agent registry" title="Every agent," emphasis="by its own identity."
                  actions={<Updated at={agents.updatedAt} onRefresh={agents.reload} />}>
        Agents are provisioned by an authorised administrator, hold their own Ed25519 keys and publish a
        DID Document. Registry status, discovery status and trust are three different facts, shown separately.
      </PageHeader>

      <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
        <Section title="Registered agents" hint="Select an agent for its Agent ID profile.">
          <Load r={agents} rows={8}>{(rows) => (
            <Table rows={rows} rowKey={(a) => a.id} onRow={setSelected} columns={[
              { key: "name", label: "Agent", render: (a) => (
                <div><div className="font-medium text-ink">{a.name}</div><Did value={a.did} /></div>) },
              { key: "type", label: "Type", render: (a) => <span className="text-ink-2">{a.agent_type}</span> },
              { key: "status", label: "Identity", render: (a) => <Badge>{a.status}</Badge> },
              { key: "ans", label: "Discovery", render: (a) => {
                const entry = ansBy.get(a.did);
                return entry ? <div><Badge>{entry.status}</Badge>
                  <div className="mt-0.5 text-[11px] text-muted">beat {ago(entry.last_seen)}</div></div>
                  : <span className="text-[12px] text-faint">not registered</span>;
              } },
              { key: "trust", label: "Trust", render: (a) => {
                const t = trustBy.get(a.did);
                return t ? <span><Badge>{t.level}</Badge> <span className="mono text-[11px] text-muted">{t.score}</span></span>
                  : <span className="text-[12px] text-muted">100 · no signals</span>;
              } },
              { key: "activity", label: "Last activity", render: (a) => (
                <span className="text-[12px] text-ink-2">{ago(a.last_activity_at)}</span>) },
            ]} />
          )}</Load>
        </Section>

        <Section title={selected ? selected.name : "Agent ID profile"}
                 hint={selected ? "Published in the DID Document (CSA Agent ID, §3.2)." : "Select an agent."}>
          {selected ? <AgentDetail agent={selected} /> : <p className="text-[13px] text-muted">Nothing selected.</p>}
        </Section>
      </div>
    </>
  );
}

function AgentDetail({ agent }: { agent: Json }) {
  const lineage = useResource(() => http<Json>(`/api/v1/agents/did/${agent.did}/lineage`), [agent.did]);
  const session = useResource(() => http<Json>(`/api/v1/security/sessions/${agent.did}`), [agent.did]);
  const creds = useResource(() => http<Json[]>(`/api/v1/agents/${agent.id}/credentials`), [agent.id]);
  const profile = agent.metadata?.profile ?? {};
  return (
    <div className="space-y-5">
      <Kv rows={[
        ["DID", <Did value={agent.did} full />],
        ["Controller", <Did value={agent.controller_did} full />],
        ["Owner", agent.owner ?? "—"],
        ["Endpoint", <span className="mono text-[12px]">{agent.endpoint ?? "none published"}</span>],
        ["Capabilities", <div className="flex flex-wrap gap-1">{(agent.capabilities ?? []).map((c: string) => <Badge key={c} tone="neutral">{c}</Badge>)}</div>],
        ["Signing key", <span className="mono text-[12px]">{agent.active_key?.algorithm ?? "Ed25519"} · {agent.active_key?.public_key_multibase?.slice(0, 18)}… (public half only)</span>],
        ["Global session", session.data ? <Badge>{session.data.state}</Badge> : "—"],
      ]} />
      <div>
        <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Model & software</h3>
        {profile.model ? (
          <Kv rows={[
            ["Model", profile.model.name ?? "—"],
            ["Runtime digest", <span className="mono text-[11px] break-all">{profile.model.runtimeDigest ?? "not reported"}</span>],
            ["SHA3-256", <span className="mono text-[11px] break-all text-brand">{profile.model.hash?.value}</span>],
            ["Software", profile.software?.version],
            ["Toolset", (profile.toolset ?? []).join(", ") || "—"],
            ["Created", profile.timestamps?.created ? new Date(profile.timestamps.created).toLocaleString() : "—"],
            ["Expires", profile.timestamps?.expires ?? "never (persistent)"],
          ]} />
        ) : <p className="text-[13px] text-muted">No Agent ID profile published for this agent.</p>}
      </div>
      <div>
        <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Credentials held</h3>
        <Load r={creds}>{(list) => list.length ? (
          <ul className="space-y-1.5 text-[12.5px]">
            {list.map((c) => (
              <li key={c.credential_id} className="flex flex-wrap items-center gap-2">
                <Badge>{c.status}</Badge>
                <span className="text-ink">{c.credential_type}</span>
                <span className="text-muted">from <Did value={c.issuer} /></span>
                <span className="ml-auto text-[11px] text-faint">expires {ago(c.expires_at)}</span>
              </li>
            ))}
          </ul>) : <p className="text-[13px] text-muted">None.</p>}</Load>
        <p className="mt-2 text-[11.5px] text-muted">Holding a valid credential is evidence for the PDP, never an authorization on its own.</p>
      </div>
      <div>
        <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Delegation lineage</h3>
        <Load r={lineage}>{(l) => (
          <div className="text-[13px]">
            {l.delegation && <p className="mb-2 text-ink-2">{l.delegation.kind} · depth {l.delegation.depth} · task “{l.delegation.task}”</p>}
            <p className="text-muted">Parents: {l.ancestors.length ? l.ancestors.map((a: Json) => a.did).join(" → ") : "none (persistent identity)"}</p>
            <p className="text-muted">Children: {l.children.length ? l.children.map((c: Json) => `${c.did} (${c.status})`).join(", ") : "none"}</p>
          </div>
        )}</Load>
      </div>
    </div>
  );
}
