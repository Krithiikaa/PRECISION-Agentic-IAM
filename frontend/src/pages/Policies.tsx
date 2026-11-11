import { useState } from "react";
import { http, type Json } from "../api/client";
import { Badge, Did, Kv, Load, Notice, PageHeader, Section, Segmented, Table, Updated } from "../components/ds";
import { ago, stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

type D = "ALL" | "ALLOW" | "DENY" | "HUMAN_APPROVAL_REQUIRED";

export function Policies() {
  const who = useIdentity()?.subject;
  const policies = useResource(() => http<Json>("/api/v1/policies"), [who], 30_000);
  const decisions = useResource(() => http<Json[]>("/api/v1/authorize/decisions?limit=200"), [who], 10_000);
  const [filter, setFilter] = useState<D>("ALL");
  const [selected, setSelected] = useState<Json | null>(null);

  return (
    <>
      <PageHeader index="05" eyebrow="Policies & authorization" title="Rego decides." emphasis="The AEM enforces."
                  actions={<Updated at={decisions.updatedAt} onRefresh={decisions.reload} />}>
        Every request is evaluated by OPA under deny-overrides and default-deny. The PIP gathers credentials, approvals,
        mandates, trust and session state; nothing a caller supplies can stand in for those facts.
      </PageHeader>

      <div className="space-y-6">
        <Section title="Policy inventory" hint="Declared in git (policy-as-code); live state from the engine.">
          <Load r={policies} rows={6}>{(p) => (
            <>
              <div className="mb-4 flex flex-wrap gap-2 text-[12.5px]">
                <Badge tone={p.engine.reachable ? "ok" : "bad"}>OPA {p.engine.reachable ? "reachable" : "UNREACHABLE"}</Badge>
                <Badge tone={p.manifest.ok ? "ok" : "bad"}>manifest {p.manifest.ok ? "valid" : "invalid"}</Badge>
                <span className="text-muted">{p.engine.modules.length} modules loaded</span>
              </div>
              <Table rows={p.policies as Json[]} rowKey={(x) => x.policy_id} columns={[
                { key: "id", label: "Policy", render: (x) => <div><div className="font-medium">{x.policy_id}</div><div className="mono text-[11px] text-muted">{x.module_id}</div></div> },
                { key: "v", label: "Version", render: (x) => <span className="mono text-[12px]">{x.version}</span> },
                { key: "status", label: "Declared", render: (x) => <Badge>{x.status}</Badge> },
                { key: "engine", label: "In engine", render: (x) => <Badge tone={x.in_engine ? "ok" : "bad"}>{x.in_engine ? "LOADED" : "ABSENT"}</Badge> },
                { key: "drift", label: "Drift", render: (x) => x.source_drift ? <Badge tone="warn">SOURCE CHANGED</Badge> : <span className="text-[12px] text-muted">none</span> },
                { key: "owner", label: "Owner", render: (x) => <span className="text-[12px] text-ink-2">{x.owner}</span> },
                { key: "scope", label: "Scope", render: (x) => <span className="text-[12px] text-muted">{x.scope}</span> },
              ]} />
              <h3 className="mb-2 mt-6 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Policy configuration data</h3>
              <ul className="space-y-1.5 text-[12.5px]">
                {(p.data as Json[]).map((d) => (
                  <li key={d.data_id}><span className="font-medium">{d.data_id}</span> <span className="mono text-[11px] text-muted">{d.version} · {d.path}</span> — <span className="text-muted">{d.description}</span></li>
                ))}
              </ul>
              <div className="mt-4"><Notice tone="info">Activating or deactivating a policy is held by the platform-security administrator principal only. No human role may change live policy from this console, by design.</Notice></div>
            </>
          )}</Load>
        </Section>

        <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
          <Section title="Decision log (PDP)" hint="Newest first. Select one for the explanation."
                   actions={<Segmented value={filter} onChange={setFilter} options={[
                     { value: "ALL", label: "All" }, { value: "ALLOW", label: "Allow" },
                     { value: "DENY", label: "Deny" }, { value: "HUMAN_APPROVAL_REQUIRED", label: "Human" }]} />}>
            <Load r={decisions} rows={8}>{(rows) => (
              <Table rows={rows.filter((d) => filter === "ALL" || d.decision === filter).slice(0, 100)} rowKey={(d) => d.request_id + d.decided_at}
                     onRow={setSelected} empty="No decisions match." columns={[
                { key: "decision", label: "Decision", render: (d) => <Badge>{d.decision}</Badge> },
                { key: "subject", label: "Subject", render: (d) => <Did value={d.subject} /> },
                { key: "what", label: "Action on resource", render: (d) => <span className="text-[12.5px]">{d.action} · <span className="text-muted">{d.resource.type}</span></span> },
                { key: "reason", label: "Reason", render: (d) => <span className="mono text-[11.5px] text-ink-2">{d.reason}</span> },
                { key: "t", label: "When", render: (d) => <span className="text-[12px] text-muted">{ago(d.decided_at)}</span> },
              ]} />
            )}</Load>
          </Section>

          <Section title="Why this decision" hint={selected?.request_id ?? "Select a decision."}>
            {selected ? (
              <div className="space-y-4">
                <Kv rows={[
                  ["Decision", <Badge>{selected.decision}</Badge>],
                  ["Reason", <span className="mono text-[12px]">{selected.reason}</span>],
                  ["Deciding policy", <span className="mono text-[12px]">{selected.policy ?? "default deny"}</span>],
                  ["Subject", <Did value={selected.subject} full />],
                  ["Action", selected.action],
                  ["Resource", `${selected.resource.type}${selected.resource.id ? ` / ${selected.resource.id}` : ""}`],
                  ["Purpose", selected.purpose],
                  ["Latency", `${selected.latency_ms} ms`],
                  ["Decided", stamp(selected.decided_at)],
                ]} />
                <div>
                  <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Evaluation stages</h3>
                  <ol className="space-y-1.5 text-[12.5px]">
                    {(selected.stages ?? []).map((s: Json, i: number) => (
                      <li key={i} className="flex gap-2"><span className={s.ok ? "text-ok" : "text-bad"}>{s.ok ? "✓" : "✗"}</span>
                        <span className="font-medium uppercase text-ink-2">{s.name}</span><span className="text-muted">{s.detail}</span>
                        <span className="ml-auto mono text-[11px] text-faint">{s.duration_ms} ms</span></li>
                    ))}
                  </ol>
                </div>
                <p className="text-[12px] text-muted">The PIP stage is where credentials, approvals, mandates, trust and session state are verified. Rego then decides on those verdicts, never on raw input.</p>
              </div>
            ) : <p className="text-[13px] text-muted">Nothing selected.</p>}
          </Section>
        </div>
      </div>
    </>
  );
}
