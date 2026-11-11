import { useState } from "react";
import { ApiError, http, security, type Json } from "../api/client";
import { Badge, Button, CheckList, Did, Disclosure, JsonBlock, Load, Notice, PageHeader, Section, Select, Table, TextArea, Updated } from "../components/ds";
import { ago, stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

export function Threats() {
  const who = useIdentity()?.subject;
  const trust = useResource(() => http<Json>("/api/v1/security/trust"), [who], 10_000);
  const alerts = useResource(() => http<Json[]>("/api/v1/security/alerts?limit=100"), [who], 8_000);
  const incidents = useResource(() => http<Json[]>("/api/v1/security/incidents"), [who], 8_000);
  const agents = useResource(() => http<Json[]>("/api/v1/agents"), [who]);

  const [target, setTarget] = useState("");
  const [why, setWhy] = useState("");
  const [revokeVcs, setRevokeVcs] = useState(false);
  const [impact, setImpact] = useState<Json | null>(null);
  const [outcome, setOutcome] = useState<{ tone: "ok" | "bad"; text: string; body?: Json } | null>(null);
  const [reviews, setReviews] = useState<Record<string, string>>({});
  // Server-confirmed results only. `contained` holds the POST response AND the
  // incident record read back from the server; nothing is assumed from a click.
  const [containing, setContaining] = useState(false);
  const [contained, setContained] = useState<{ report: Json; incident: Json | null } | null>(null);
  const [reinstating, setReinstating] = useState<Record<string, ReinstateState>>({});

  const contain = async () => {
    if (containing) return;
    setContaining(true); setOutcome(null); setContained(null);
    try {
      const report = await security.contain(target, why, revokeVcs);
      let incident: Json | null = null;
      try { incident = await security.incident(report.incident_id); } catch { incident = null; }
      setContained({ report, incident });
      setOutcome({ tone: "ok", text: `Server confirmed containment ${report.incident_id}.`, body: report });
      incidents.reload(); trust.reload(); agents.reload();
    } catch (e) {
      setOutcome({ tone: "bad", text: `Containment NOT performed: ${(e as Error).message}` });
    } finally { setContaining(false); }
  };

  const reinstate = async (incidentId: string) => {
    if (reinstating[incidentId]?.phase === "pending") return;
    setReinstating((m) => ({ ...m, [incidentId]: { phase: "pending" } }));
    try {
      const body = await security.reinstate(incidentId, reviews[incidentId] ?? "");
      setReinstating((m) => ({ ...m, [incidentId]: {
        phase: body.status === "REINSTATED" ? "reinstated" : "unknown", body,
        revalidation: body.revalidation ?? null } }));
    } catch (e) {
      const err = e instanceof ApiError ? e : null;
      setReinstating((m) => ({ ...m, [incidentId]: {
        phase: "refused", detail: err?.detail ?? (e as Error).message, status: err?.status,
        revalidation: (err?.body?.revalidation as Check[] | null | undefined) ?? null } }));
    } finally { incidents.reload(); trust.reload(); }
  };

  return (
    <>
      <PageHeader index="10" eyebrow="Threat monitoring" title="Detect, contain," emphasis="then review."
                  actions={<Updated at={alerts.updatedAt} onRefresh={alerts.reload} />}>
        A rule-based detector reads the audit trail; only events whose subject was authenticated can lower trust.
        Trust collapse contains the agent automatically. Reinstatement needs a written review by a different person.
      </PageHeader>

      <div className="space-y-6">
        <div className="grid gap-6 xl:grid-cols-[1fr_1.2fr]">
          <Section title="Trust scores" hint={trust.data ? `TRUSTED ${trust.data.bands.TRUSTED} · REDUCED ${trust.data.bands.REDUCED} · UNTRUSTED ${trust.data.bands.UNTRUSTED}` : undefined}>
            <Load r={trust}>{(t) => (
              <Table rows={t.agents as Json[]} rowKey={(a) => a.agent_did} empty={`All agents at 100: ${t.note}.`} columns={[
                { key: "agent", label: "Agent", render: (a) => <Did value={a.agent_did} /> },
                { key: "score", label: "Score", render: (a) => (
                  <div className="flex items-center gap-2"><div className="h-1.5 w-24 overflow-hidden rounded-full bg-sunken">
                    <div className={`h-full ${a.level === "TRUSTED" ? "bg-ok" : a.level === "REDUCED" ? "bg-warn" : "bg-bad"}`} style={{ width: `${a.score}%` }} />
                  </div><span className="mono text-[12px]">{a.score}</span></div>) },
                { key: "level", label: "Level", render: (a) => <Badge>{a.level}</Badge> },
                { key: "sig", label: "Signals", render: (a) => <span className="text-[12px] text-muted">{a.active_signals} active</span> },
              ]} />
            )}</Load>
          </Section>

          <Section title="Kill switch" hint="Locks one agent out across API, MCP and A2A; other agents are untouched.">
            <Load r={agents}>{(list) => (
              <div className="space-y-3">
                <div className="flex flex-wrap items-end gap-2">
                  <div className="min-w-64 flex-1">
                    <Select label="Agent" value={target} onChange={(v) => { setTarget(v); setImpact(null); }}>
                      <option value="">Choose an agent…</option>
                      {list.filter((a) => a.status !== "TERMINATED").map((a) => <option key={a.did} value={a.did}>{a.name} · {a.status}</option>)}
                    </Select>
                  </div>
                  <Button disabled={!target} onClick={async () => {
                    try { setImpact(await http<Json>(`/api/v1/security/impact/${target}`)); } catch (e) { setOutcome({ tone: "bad", text: (e as Error).message }); }
                  }}>Preview blast radius</Button>
                </div>
                {impact && (
                  <div className="grid grid-cols-2 gap-2 text-[12.5px] sm:grid-cols-4">
                    {[["Credentials", impact.reachable.active_credentials.length], ["Live mandates", impact.reachable.live_jit_grants.length],
                      ["MCP sessions", impact.reachable.live_mcp_sessions], ["Children", impact.reachable.delegated_children.length]].map(([k, v]) => (
                      <div key={k as string} className="rounded-lg border border-line bg-sunken px-3 py-2"><div className="text-muted">{k}</div><div className="display text-[22px]">{v}</div></div>
                    ))}
                  </div>
                )}
                <TextArea placeholder="Justification (required; recorded on the incident)" value={why} onChange={(e) => setWhy(e.target.value)} />
                <label className="flex items-center gap-2 text-[12.5px] text-ink-2">
                  <input type="checkbox" checked={revokeVcs} onChange={(e) => setRevokeVcs(e.target.checked)} />
                  Also revoke its credentials (irreversible)
                </label>
                <Button variant="danger" disabled={!target || why.trim().length < 10 || containing} onClick={contain}>
                  {containing ? "Containing…" : "Contain agent"}
                </Button>
              </div>
            )}</Load>
            {outcome && !contained && <div className="mt-3 animate-status-in" role="status"><Notice tone={outcome.tone}>{outcome.text}</Notice></div>}
            {contained && <div className="mt-3"><ContainmentResult report={contained.report} incident={contained.incident} /></div>}
          </Section>
        </div>

        <Section title="Incidents" hint="Containments and their post-incident reviews.">
          <Load r={incidents}>{(rows) => rows.length ? (
            <div className="space-y-3">
              {rows.map((inc) => (
                <div key={inc.incident_id} className="rounded-lg border border-line p-4">
                  <div className="flex flex-wrap items-center gap-2 text-[13px]">
                    <Badge>{inc.status}</Badge><Badge tone="neutral">{inc.trigger}</Badge>
                    <span className="mono text-[12px]">{inc.incident_id}</span><Did value={inc.agent_did} />
                    <span className="ml-auto text-[12px] text-muted">{inc.containment_ms?.toFixed?.(0)} ms · {ago(inc.contained_at)}</span>
                  </div>
                  <p className="mt-2 text-[13px] text-ink-2">{inc.justification}</p>
                  <p className="mt-1 text-[12px] text-muted">contained by {inc.opened_by}{inc.cascaded_to?.length ? ` · cascaded to ${inc.cascaded_to.join(", ")}` : ""}
                    {inc.reinstated_by ? ` · reinstated by ${inc.reinstated_by}: “${inc.review}”` : ""}</p>
                  <div className="mt-3">
                    <Disclosure title="Containment detail" meta="server record · audit evidence" testId={`incident-detail-${inc.incident_id}`}>
                      <ContainmentDetail incidentId={inc.incident_id} agentDid={inc.agent_did} />
                    </Disclosure>
                  </div>
                  {inc.status === "CONTAINED" && (
                    <div className="mt-3 flex flex-wrap items-start gap-2">
                      <div className="min-w-72 flex-1"><TextArea placeholder="Post-incident review (20+ characters). Must be a different person from the one who contained."
                        value={reviews[inc.incident_id] ?? ""} onChange={(e) => setReviews({ ...reviews, [inc.incident_id]: e.target.value })} /></div>
                      <Button disabled={reinstating[inc.incident_id]?.phase === "pending"} onClick={() => reinstate(inc.incident_id)}>
                        {reinstating[inc.incident_id]?.phase === "pending" ? "Revalidating…" : "Reinstate"}
                      </Button>
                    </div>
                  )}
                  {reinstating[inc.incident_id] && <ReinstateResult r={reinstating[inc.incident_id]} serverStatus={inc.status} />}
                </div>
              ))}
            </div>) : <Notice tone="ok">No incidents.</Notice>}</Load>
        </Section>

        <Section title="Anomaly alerts" hint="Unattributed alerts name a DID the caller only claimed; they never move trust.">
          <Load r={alerts} rows={6}>{(rows) => (
            <Table rows={rows} rowKey={(a) => a.alert_id} empty="No alerts." columns={[
              { key: "sev", label: "Severity", render: (a) => <Badge>{a.severity}</Badge> },
              { key: "rule", label: "Rule", render: (a) => <span className="mono text-[12px]">{a.rule}</span> },
              { key: "agent", label: "Agent", render: (a) => <Did value={a.agent_did} /> },
              { key: "sum", label: "Finding", render: (a) => <span className="text-[12.5px] text-ink-2">{a.summary}{!a.attributed && <span className="text-muted"> · unattributed</span>}</span> },
              { key: "st", label: "Status", render: (a) => <Badge>{a.status}</Badge> },
              { key: "t", label: "When", render: (a) => <span className="text-[12px] text-muted">{ago(a.created_at)}</span> },
            ]} />
          )}</Load>
          <p className="mt-4 text-[12px] text-muted">Rate-limit refusals (HTTP 429) are written to the API log with the limited identity, not to the audit trail:
            a database row per refused request would turn the limiter itself into an amplification vector.</p>
        </Section>
        {outcome?.body && <details className="text-[12px]"><summary className="cursor-pointer text-brand">Last action response</summary><JsonBlock value={outcome.body} /></details>}
      </div>
    </>
  );
}

type Check = { check: string; passed: boolean; detail?: string };
type ReinstateState = {
  phase: "pending" | "reinstated" | "refused" | "unknown";
  body?: Json; detail?: string; status?: number; revalidation?: Check[] | null;
};

/** What the SERVER returned for a containment, plus the incident it stored. */
function ContainmentResult({ report, incident }: { report: Json; incident: Json | null }) {
  const a = (report.actions ?? {}) as Json;
  const cancelled = a.approvals_cancelled as string[] | undefined;
  const push = report.sss_push as Json[] | undefined;
  return (
    <div className="rounded-lg border border-bad/25 bg-bad-bg/40 p-4 animate-status-in" data-testid="containment-result" role="status">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="bad">CONTAINED</Badge>
        <span className="text-[13px] font-medium text-ink">Server-confirmed · {report.incident_id}</span>
        <span className="ml-auto text-[12px] text-muted">{report.containment_ms} ms · {stamp(report.contained_at)}</span>
      </div>
      <dl className="mt-3 grid grid-cols-[140px_1fr] gap-x-3 gap-y-1.5 text-[12.5px]">
        <dt className="text-muted">Agent</dt><dd className="min-w-0"><Did value={report.agent_did} full /></dd>
        <dt className="text-muted">Reason</dt><dd className="min-w-0 break-words text-ink-2">{incident?.justification ?? <span className="text-faint">not returned</span>}</dd>
        <dt className="text-muted">Session</dt><dd><Badge>{a.session_state?.state}</Badge></dd>
        <dt className="text-muted">Identity</dt><dd className="text-ink-2">{a.identity}</dd>
        <dt className="text-muted">Approvals cancelled</dt>
        <dd data-testid="approvals-cancelled">{cancelled === undefined
          ? <span className="text-faint">not reported by the server</span>
          : cancelled.length
            ? <span><span className="font-medium">{cancelled.length}</span>{" "}{cancelled.map((id) => <span key={id} className="mono ml-1 rounded bg-surface px-1.5 py-0.5 text-[11.5px]">{id}</span>)}</span>
            : <span className="text-ink-2">0 — none pending or unspent</span>}</dd>
        <dt className="text-muted">JIT mandates revoked</dt><dd className="text-ink-2">{(a.jit_grants_revoked ?? []).length}</dd>
        <dt className="text-muted">MCP sessions revoked</dt><dd className="text-ink-2">{a.mcp_sessions_revoked ?? 0}</dd>
        <dt className="text-muted">ANS</dt><dd className="text-ink-2">{a.ans}</dd>
        <dt className="text-muted">Credentials revoked</dt><dd className="text-ink-2">{(a.credentials_revoked ?? []).length}</dd>
        <dt className="text-muted">Cascaded to</dt><dd className="text-ink-2">{(report.cascaded_to ?? []).length ? (report.cascaded_to as string[]).join(", ") : "none"}</dd>
        <dt className="text-muted">Other agents</dt><dd className="text-ink-2">{report.unaffected_active_agents} active, untouched</dd>
        <dt className="text-muted">Push to runtimes</dt><dd className="text-ink-2">{push?.[0] ? `${push[0].delivered ? "delivered" : "NOT delivered (the ledger still enforces)"} · ${push[0].subscribers ?? 0} subscriber(s)` : "—"}</dd>
      </dl>
    </div>
  );
}

/** The stored incident record and its audit evidence, read on demand. */
function ContainmentDetail({ incidentId, agentDid }: { incidentId: string; agentDid: string }) {
  const r = useResource(() => security.incident(incidentId), [incidentId]);
  const evidence = useResource(() => http<Json[]>(`/api/v1/audit?agent_did=${encodeURIComponent(agentDid)}&limit=300`), [incidentId]);
  return (
    <Load r={r} rows={4}>{(inc) => {
      const a = ((inc.containment ?? {}) as Json).actions as Json | undefined;
      const cancelled = a?.approvals_cancelled as string[] | undefined;
      const related = (evidence.data ?? []).filter((e) =>
        e.metadata?.incident_id === incidentId || String(e.reason ?? "").includes(incidentId));
      return (
        <div className="space-y-3 text-[12.5px]">
          <dl className="grid grid-cols-[140px_1fr] gap-x-3 gap-y-1.5">
            <dt className="text-muted">Contained</dt><dd className="text-ink-2">{stamp(inc.contained_at)} by {inc.opened_by} ({inc.trigger})</dd>
            <dt className="text-muted">Reason</dt><dd className="min-w-0 break-words text-ink-2">{inc.justification}</dd>
            <dt className="text-muted">Approvals cancelled</dt>
            <dd data-testid="detail-approvals-cancelled">{cancelled === undefined
              ? <span className="text-faint">not recorded (incident predates Phase 12)</span>
              : cancelled.length ? <>{cancelled.length}: {cancelled.map((id) => <span key={id} className="mono ml-1 text-[11.5px]">{id}</span>)}</>
              : "0"}</dd>
            <dt className="text-muted">Status</dt><dd><Badge>{inc.status}</Badge>{inc.reinstated_by && <span className="ml-2 text-muted">by {inc.reinstated_by} · {stamp(inc.reinstated_at)}</span>}</dd>
          </dl>
          <div>
            <div className="mb-1 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Audit evidence for this incident</div>
            {evidence.denied ? <p className="text-muted">Audit read requires AUDITOR or IAM_ADMIN.</p>
              : evidence.loading && !evidence.data ? <p className="text-muted">Loading…</p>
              : related.length ? (
                <ul className="space-y-1">{related.map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center gap-2 animate-step-in">
                    <span className="mono text-[11px] text-faint">#{e.seq}</span><span className="font-medium">{e.event_type}</span>
                    {e.decision && <Badge>{e.decision}</Badge>}
                    {e.metadata?.approval_id && <span className="mono text-[11px] text-ink-2">{e.metadata.approval_id}</span>}
                  </li>))}</ul>)
              : <p className="text-muted">No matching events among the agent's latest 300.</p>}
          </div>
        </div>
      );
    }}</Load>
  );
}

/** The SERVER's reinstatement outcome. A click is never shown as success. */
function ReinstateResult({ r, serverStatus }: { r: ReinstateState; serverStatus: string }) {
  if (r.phase === "pending") {
    return <div className="mt-3 animate-status-in" role="status"><Notice tone="info" title="Reinstatement requested">The server is revalidating trust; the incident stays CONTAINED until it answers.</Notice></div>;
  }
  const checks = r.revalidation ?? null;
  if (r.phase === "unknown") {
    return <div className="mt-3 animate-status-in" role="status"><Notice tone="warn" title="Not confirmed">The server answered without confirming reinstatement; the incident status shown above is authoritative.</Notice></div>;
  }
  if (r.phase === "reinstated") {
    return (
      <div className="mt-3 space-y-2 rounded-lg border border-ok/25 bg-ok-bg/40 p-4 animate-status-in" data-testid="reinstate-result" role="status">
        <div className="flex flex-wrap items-center gap-2"><Badge tone="ok">REINSTATED</Badge>
          <span className="text-[13px] font-medium">Server-confirmed · incident now {serverStatus}</span></div>
        {checks && <><div className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Trust revalidation</div><CheckList checks={checks} /></>}
        {(r.body?.still_required ?? []).length > 0 && <ul className="list-disc pl-5 text-[12px] text-muted">{(r.body!.still_required as string[]).map((x) => <li key={x}>{x}</li>)}</ul>}
      </div>
    );
  }
  return (
    <div className="mt-3 space-y-2 rounded-lg border border-bad/25 bg-bad-bg/40 p-4 animate-status-in" data-testid="reinstate-result" role="status">
      <div className="flex flex-wrap items-center gap-2"><Badge tone="bad">REFUSED</Badge>
        <span className="text-[13px] font-medium">{r.status ? `HTTP ${r.status}` : "No answer"} · incident remains {serverStatus}</span></div>
      <p className="text-[12.5px] text-ink-2">{r.detail}</p>
      {checks ? <><div className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Trust revalidation</div><CheckList checks={checks} /></>
              : <p className="text-[12px] text-muted">Refused before trust revalidation ran (state, review or separation-of-duties rule).</p>}
    </div>
  );
}
