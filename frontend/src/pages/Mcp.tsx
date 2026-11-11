import { http, type Json } from "../api/client";
import { Badge, Did, Load, Notice, PageHeader, Section, Table, Updated } from "../components/ds";
import { ago } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

export function Mcp() {
  const who = useIdentity()?.subject;
  const r = useResource(() => http<Json>("/api/v1/console/mcp"), [who], 10_000);
  return (
    <>
      <PageHeader index="09" eyebrow="MCP security" title="A tool you can see" emphasis="is not a tool you may call."
                  actions={<Updated at={r.updatedAt} onRefresh={r.reload} />}>
        Agents authenticate to the MCP gateway with a signed client assertion from their own DID key; the token's
        <span className="mono"> azp</span> is the DID. Every tools/call is decided by the same PDP as the direct API.
      </PageHeader>
      <Load r={r} rows={8}>{(d) => (
        <div className="space-y-6">
          <Notice tone="info" title="Discovery ≠ permission">{d.note}. Resource: <span className="mono">{d.resource_uri}</span></Notice>
          <Section title="Protected tool catalogue" hint="Every tool is reachable only through the AEM.">
            <Table rows={d.tools as Json[]} rowKey={(t) => t.name} columns={[
              { key: "name", label: "Tool", render: (t) => <div><div className="mono text-[12.5px] text-ink">{t.name}</div><div className="text-[11.5px] text-muted">{t.description}</div></div> },
              { key: "res", label: "Resource · action", render: (t) => <span className="text-[12.5px]">{t.resource} · {t.action}</span> },
              { key: "cap", label: "Capability", render: (t) => <span className="text-[12px] text-ink-2">{t.required_capability}</span> },
              { key: "mcp", label: "Over MCP", render: (t) => <Badge tone={t.mcp_eligible ? "ok" : "neutral"}>{t.mcp_eligible ? "ELIGIBLE" : "NOT EXPOSED"}</Badge> },
            ]} />
          </Section>
          <div className="grid gap-6 xl:grid-cols-2">
            <Section title="Sessions" hint="Bound to the authenticated agent; revoked by the Session Authority on containment.">
              <Table rows={d.sessions as Json[]} rowKey={(s) => s.session_id} empty="No MCP sessions yet." columns={[
                { key: "agent", label: "Agent", render: (s) => <Did value={s.agent_did} /> },
                { key: "status", label: "Status", render: (s) => <Badge>{s.status}</Badge> },
                { key: "client", label: "Client", render: (s) => <span className="text-[12px] text-muted">{s.client ?? "—"} · {s.protocol_version}</span> },
                { key: "t", label: "Last activity", render: (s) => <span className="text-[12px] text-muted">{ago(s.last_activity_at ?? s.created_at)}</span> },
              ]} />
            </Section>
            <Section title="Tool invocations" hint="Each one an authorization decision.">
              <Table rows={d.invocations as Json[]} rowKey={(c) => c.request_id} empty="No tool calls yet." columns={[
                { key: "tool", label: "Tool", render: (c) => <span className="mono text-[12px]">{c.tool}</span> },
                { key: "agent", label: "Agent", render: (c) => <Did value={c.agent_did} /> },
                { key: "dec", label: "Decision", render: (c) => <span><Badge>{c.decision ?? c.status}</Badge><div className="mono text-[11px] text-muted">{c.reason}</div></span> },
                { key: "t", label: "When", render: (c) => <span className="text-[12px] text-muted">{ago(c.created_at)}</span> },
              ]} />
            </Section>
          </div>
        </div>
      )}</Load>
    </>
  );
}
