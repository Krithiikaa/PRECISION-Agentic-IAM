import { http, type Json } from "../api/client";
import { Badge, Did, Load, LiveDot, PageHeader, Section, Stat, Updated } from "../components/ds";
import { ago, sum } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity, type Route } from "../shell/Shell";

export function Overview({ go }: { go: (r: Route) => void }) {
  const who = useIdentity()?.subject;
  const r = useResource(() => http<Json>("/api/v1/console/overview"), [who], 15_000);
  const health = useResource(() => http<Json>("/api/v1/console/health"), [who], 30_000);

  return (
    <>
      <PageHeader index="01" eyebrow="Overview" title="The agent estate," emphasis="at a glance."
                  actions={<Updated at={r.updatedAt} onRefresh={r.reload} />}>
        Live counts from the IAM database and a probe of every dependency. Nothing here is cached or
        illustrative: if a service is down, it says so.
      </PageHeader>

      <Load r={r} rows={6}>{(d) => {
        const agents = d.agents.by_status as Record<string, number>;
        const decisions = d.authorization_24h.by_decision as Record<string, number>;
        const alerts = d.security.open_alerts_by_severity as Record<string, number>;
        const approvals = d.approvals.by_status as Record<string, number>;
        return (
          <div className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <Stat label="Registered agents" value={sum(agents)} tone="brand"
                    sub={<>{agents.ACTIVE ?? 0} active · {agents.SUSPENDED ?? 0} suspended · {agents.TERMINATED ?? 0} terminated · {d.agents.delegated} delegated</>} />
              <Stat label="Contained now" value={d.agents.contained} tone={d.agents.contained ? "bad" : "ok"}
                    sub={<>{d.security.open_incidents} open incident(s) · kill-switch lockouts in the SSS</>} />
              <Stat label="Decisions · 24h" value={sum(decisions)} tone="info"
                    sub={<>{decisions.ALLOW ?? 0} allow · {decisions.DENY ?? 0} deny · {decisions.HUMAN_APPROVAL_REQUIRED ?? 0} to human · mean {d.authorization_24h.mean_latency_ms ?? "—"} ms</>} />
              <Stat label="Open security alerts" value={sum(alerts)} tone={(alerts.CRITICAL || alerts.HIGH) ? "bad" : sum(alerts) ? "warn" : "ok"}
                    sub={Object.entries(alerts).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(" · ") || "none open"} />
            </div>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <Stat label="Credentials active" value={d.credentials.by_stored_status.ACTIVE ?? 0}
                    sub={<>{d.credentials.by_stored_status.REVOKED ?? 0} revoked · {d.credentials.active_but_lapsed} lapsed by time</>} />
              <Stat label="Pending approvals" value={approvals.PENDING ?? 0} tone={approvals.PENDING ? "warn" : "neutral"}
                    sub={<>{approvals.CONSUMED ?? 0} consumed · {approvals.REJECTED ?? 0} rejected</>} />
              <Stat label="Live JIT grants" value={d.jit.active}
                    sub="Each use is still re-decided by the PDP" />
              <Stat label="MCP sessions" value={d.mcp.active_sessions}
                    sub={<>{sum(d.mcp.invocations_24h)} tool calls · 24h · A2A {sum(d.a2a.by_status)} total</>} />
            </div>

            <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
              <Section title="Recent audit events" hint="Append-only trail; newest first."
                       actions={<button className="text-[12px] text-brand hover:underline" onClick={() => go("audit")}>Open audit →</button>}>
                <ul className="divide-y divide-line">
                  {(d.recent_audit as Json[]).map((e) => (
                    <li key={e.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-[13px]">
                      <span className="mono w-16 shrink-0 text-[11px] text-faint">#{e.seq}</span>
                      <span className="font-medium text-ink">{e.event_type}</span>
                      {e.decision && <Badge>{e.decision}</Badge>}
                      <Did value={e.agent_did} />
                      <span className="ml-auto text-[11.5px] text-muted">{ago(e.timestamp)}</span>
                    </li>
                  ))}
                </ul>
              </Section>

              <Section title="Service health" hint="Probed on request, never assumed."
                       actions={<button className="text-[12px] text-brand hover:underline" onClick={() => go("system")}>Details →</button>}>
                <Load r={health} rows={6}>{(h) => (
                  <ul className="space-y-2">
                    {(h.services as Json[]).map((s) => (
                      <li key={s.service} className="flex items-center gap-3 text-[13px]">
                        <LiveDot up={s.up} />
                        <span className="text-ink">{s.service}</span>
                        <span className="ml-auto mono text-[11px] text-faint">{s.latency_ms} ms</span>
                        <Badge tone={s.up ? "ok" : "bad"}>{s.up ? "UP" : "DOWN"}</Badge>
                      </li>
                    ))}
                  </ul>
                )}</Load>
              </Section>
            </div>

            <Section title="Loan workflows" hint={d.loan_workflows.note}
                     actions={<button className="text-[12px] text-brand hover:underline" onClick={() => go("workflow")}>Open workflow →</button>}>
              <div className="flex flex-wrap gap-2">
                {Object.keys(d.loan_workflows.by_status).length
                  ? Object.entries(d.loan_workflows.by_status as Record<string, number>).map(([k, v]) => (
                      <Badge key={k}>{k} · {v}</Badge>))
                  : <span className="text-[13px] text-muted">No workflows submitted since the API started.</span>}
              </div>
            </Section>
          </div>
        );
      }}</Load>
    </>
  );
}
