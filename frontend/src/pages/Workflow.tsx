import { useRef, useState } from "react";
import { ApiError, http, workflows, type Json } from "../api/client";
import { Badge, Button, Did, Disclosure, Input, Load, Notice, PageHeader, Section, Table, Updated } from "../components/ds";
import { ago, inr, stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity, type Route } from "../shell/Shell";

const DOCS = ["IDENTITY_PROOF", "INCOME_PROOF", "ADDRESS_PROOF"];
const STEP_LABEL: Record<string, string> = {
  kyc: "KYC verification", risk_assessment: "Risk assessment", credit_analysis: "Credit analysis",
  document_verification: "Document verification", fraud_detection: "Fraud screening", decision: "Loan decision",
};

export function Workflow({ go }: { go: (r: Route) => void }) {
  const identity = useIdentity();
  const list = useResource(() => http<Json[]>("/api/v1/loan-workflows"), [identity?.subject], 3_000);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = list.data?.find((w) => w.workflow_id === selectedId) ?? null;

  return (
    <>
      <PageHeader index="★" eyebrow="Enterprise loan workflow" title="Six agents, one decision," emphasis="every step authorised."
                  actions={<Updated at={list.updatedAt} onRefresh={list.reload} />}>
        A loan officer submits; the coordinator agent claims the work with its own credential, discovers each specialist
        through the ANS and sends it a signed instruction. Every specialist calls the AEM with its OWN key; the PDP decides
        on its OWN credentials. Large loans pause for human approval.
      </PageHeader>

      <div className="space-y-6">
        <Submit onSubmitted={(id) => { setSelectedId(id); list.reload(); }} signedIn={!!identity} />
        <div className="grid gap-6 xl:grid-cols-[1fr_1.4fr]">
          <Section title="Workflows" hint="Polled every 3 s while you watch.">
            <Load r={list} rows={6}>{(rows) => (
              <Table rows={rows} rowKey={(w) => w.workflow_id} onRow={(w) => setSelectedId(w.workflow_id)} empty="No workflows yet: submit one above." columns={[
                { key: "id", label: "Workflow", render: (w) => <div><div className={`mono text-[12px] ${w.workflow_id === selectedId ? "text-brand" : ""}`}>{w.workflow_id}</div>
                  <div className="text-[11.5px] text-muted">{w.application?.customer_id}</div></div> },
                { key: "amt", label: "Amount", render: (w) => <span className="tabular-nums">{inr(w.application?.amount_inr)}</span> },
                { key: "status", label: "Status", render: (w) => <Badge>{w.status}</Badge> },
                { key: "t", label: "Updated", render: (w) => <span className="text-[12px] text-muted">{ago(w.updated_at)}</span> },
              ]} />
            )}</Load>
          </Section>
          <Section title={selected ? `Execution timeline · ${selected.workflow_id}` : "Execution timeline"}
                   hint={selected ? `Submitted by ${selected.submitted_by} · ${stamp(selected.submitted_at)}` : "Select a workflow."}>
            {selected ? <Timeline w={selected} go={go} /> : <p className="text-[13px] text-muted">Nothing selected.</p>}
          </Section>
        </div>
        <Notice tone="info" title="Integration limitations, stated">
          KYC registry, credit bureau, document store, fraud service, risk model and loan management system are SIMULATED
          adapters (every record carries <span className="mono">simulated: true</span>). Authentication, discovery,
          authorization, enforcement, approval and audit are real. This workflow's specialists reach the AEM directly; the
          MCP gateway and A2A channel are governed by the same PDP and shown on their own pages.
        </Notice>
      </div>
    </>
  );
}

/** A key for ONE logical submission. Generated when the officer submits a
 *  payload for the first time; reused, unchanged, for every retry of that
 *  same payload; discarded only once the server has confirmed the outcome. */
function newIdempotencyKey(): string {
  const c: Crypto = globalThis.crypto;
  if (typeof c.randomUUID === "function") return `console-${c.randomUUID()}`;
  const bytes = new Uint8Array(16);
  c.getRandomValues(bytes);
  return `console-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

type SubmitMsg = { tone: "ok" | "bad" | "info" | "warn"; title?: string; text: string };

function Submit({ onSubmitted, signedIn }: { onSubmitted: (id: string) => void; signedIn: boolean }) {
  const [form, setForm] = useState({ customer_id: "customer-007", applicant_name: "A. Demo Applicant",
                                     amount_inr: "400000", term_months: "36", declared_monthly_income_inr: "150000" });
  const [docs, setDocs] = useState<string[]>(DOCS);
  const [msg, setMsg] = useState<SubmitMsg | null>(null);
  const [busy, setBusy] = useState(false);
  // Synchronous guard: two clicks in the same tick both see `busy === false`.
  const inFlight = useRef(false);
  const pending = useRef<{ key: string; payload: string } | null>(null);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });

  const submit = async () => {
    if (inFlight.current) return;
    const body = {
      customer_id: form.customer_id, applicant_name: form.applicant_name, amount_inr: Number(form.amount_inr),
      term_months: Number(form.term_months), declared_monthly_income_inr: Number(form.declared_monthly_income_inr),
      documents: docs.map((t) => ({ type: t, content: `${t} (uploaded via console)` })) };
    const payload = JSON.stringify(body);
    // Same payload, not yet confirmed -> the SAME logical submission (retry).
    // Anything else -> a new one.
    const retry = pending.current?.payload === payload;
    if (!retry) pending.current = { key: newIdempotencyKey(), payload };
    const key = pending.current!.key;
    inFlight.current = true;
    setBusy(true);
    setMsg({ tone: "info", text: retry ? "Retrying with the same Idempotency-Key… not yet confirmed by the server."
                                       : "Sending… not yet confirmed by the server." });
    try {
      const w = await workflows.submit(body, key);
      pending.current = null;                       // outcome confirmed by the server
      if (w.idempotent_replay) {
        setMsg({ tone: "info", title: "Already received — nothing new was created",
                 text: `The server recognised this as the same submission as ${w.workflow_id} (status ${w.status}).` });
      } else {
        setMsg({ tone: "ok", text: `Submitted ${w.workflow_id}. The coordinator agent picks it up within seconds.` });
      }
      onSubmitted(w.workflow_id);
    } catch (e) {
      const status = e instanceof ApiError ? e.status : null;
      if (status === 409) {
        pending.current = null;
        setMsg({ tone: "bad", title: "Refused by the server (409)", text: (e as ApiError).detail });
      } else if (status !== null && status < 500 && status !== 429) {
        pending.current = null;                     // a definitive refusal: nothing was stored
        setMsg({ tone: "bad", title: `Refused (HTTP ${status})`, text: (e as ApiError).detail });
      } else {
        // Timeout, network failure, 429 or 5xx: the outcome is UNKNOWN. Keep
        // the key, so a retry cannot create a second application.
        setMsg({ tone: "warn", title: "Not confirmed",
                 text: `The server did not confirm this submission (${status ? `HTTP ${status}` : (e as Error).message}). ` +
                       "Submitting again resends the same Idempotency-Key, so the server cannot create a duplicate." });
      }
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  return (
    <Section title="Submit an application" hint="As a signed-in LOAN_OFFICER (the officer of record may not approve it later).">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Input label="Customer" value={form.customer_id} onChange={set("customer_id")} />
        <Input label="Applicant" value={form.applicant_name} onChange={set("applicant_name")} />
        <Input label="Amount (INR)" inputMode="numeric" value={form.amount_inr} onChange={set("amount_inr")} />
        <Input label="Term (months)" inputMode="numeric" value={form.term_months} onChange={set("term_months")} />
        <Input label="Monthly income (INR)" inputMode="numeric" value={form.declared_monthly_income_inr} onChange={set("declared_monthly_income_inr")} />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-4 text-[12.5px] text-ink-2">
        {DOCS.map((d) => (
          <label key={d} className="flex items-center gap-1.5"><input type="checkbox" checked={docs.includes(d)}
            onChange={(e) => setDocs(e.target.checked ? [...docs, d] : docs.filter((x) => x !== d))} />{d.replace("_", " ").toLowerCase()}</label>
        ))}
        <span className="text-[12px] text-muted">Try customer-666 (sanctions hit) · ₹25,00,000 (one approver) · ₹2,00,00,000 (two approvers)</span>
      </div>
      <div className="mt-4 flex items-center gap-3">
        <Button variant="primary" onClick={submit} disabled={busy}>{busy ? "Submitting…" : "Submit to the agents →"}</Button>
        {!signedIn && <span className="text-[12px] text-muted">Sign in first; the server will refuse an anonymous submission.</span>}
      </div>
      {pending.current && !busy && <p className="mt-2 text-[11.5px] text-muted">Unconfirmed submission pending · Idempotency-Key <span className="mono">{pending.current.key.slice(0, 22)}…</span></p>}
      {msg && <div key={msg.text} className="mt-3 animate-status-in" role="status"><Notice tone={msg.tone} title={msg.title}>{msg.text}</Notice></div>}
    </Section>
  );
}

function Timeline({ w, go }: { w: Json; go: (r: Route) => void }) {
  const [trace, setTrace] = useState<{ step: string; events: Json[] } | null>(null);
  const steps = (w.steps ?? []) as Json[];
  const loadTrace = async (s: Json) => {
    const requestId = s.step === "decision" ? (w.approval?.request_id ?? `${w.workflow_id}-decision`) : `${w.workflow_id}-${s.step}`;
    try { setTrace({ step: s.step, events: await http<Json[]>(`/api/v1/audit?request_id=${encodeURIComponent(requestId)}&limit=50`) }); }
    catch (e) { setTrace({ step: s.step, events: [{ event_type: (e as Error).message }] }); }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Badge>{w.status}</Badge>
        <span className="display text-[24px]">{inr(w.application?.amount_inr)}</span>
        <span className="text-[13px] text-muted">{w.application?.applicant_name} · {w.application?.term_months} months</span>
      </div>
      <Notice tone={w.status === "APPROVED" ? "ok" : w.status === "DECLINED" || w.status === "FAILED" ? "bad" : w.status === "AWAITING_APPROVAL" ? "warn" : "info"}
              title="Message to the customer">{w.customer_message}</Notice>
      {w.decision?.summary && <p className="text-[13px] text-ink-2"><span className="text-muted">Outcome:</span> {w.decision.summary}</p>}

      <ol className="relative space-y-3 border-l border-line pl-5">
        {!steps.length && <li className="text-[13px] text-muted">Waiting for the coordinator agent to claim this workflow…</li>}
        {steps.map((s) => (
          <li key={s.step} className="relative animate-rise">
            <span className={`absolute -left-[26px] top-1.5 h-2.5 w-2.5 rounded-full ring-4 ring-surface ${s.executed ? "bg-ok" : s.decision === "HUMAN_APPROVAL_REQUIRED" ? "bg-warn" : "bg-bad"}`} />
            <div className="rounded-lg border border-line px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-ink">{STEP_LABEL[s.step] ?? s.step}</span>
                <Badge>{s.decision ?? "—"}</Badge>
                <span className="mono text-[11px] text-muted">{s.tool}</span>
                <button className="ml-auto text-[12px] text-brand hover:underline" onClick={() => loadTrace(s)}>Authorization trace →</button>
              </div>
              <dl className="mt-2 grid grid-cols-[72px_1fr] gap-x-3 gap-y-1 text-[12.5px]">
                <dt className="text-muted">Agent</dt><dd className="min-w-0"><Did value={s.agent_did} /></dd>
                <dt className="text-muted">Capability</dt><dd className="mono min-w-0 break-all text-[12px] text-ink-2">{s.capability}</dd>
                <dt className="text-muted">Reason</dt><dd className="mono min-w-0 break-all text-[11.5px] text-ink-2">{s.reason ?? "—"}</dd>
                <dt className="text-muted">Policy</dt><dd className="mono min-w-0 break-all text-[11.5px] text-ink-2">{s.policy ?? "—"}</dd>
              </dl>
              {s.result && <div className="mt-2 flex flex-wrap gap-1.5">{Object.entries(s.result as Json).filter(([k]) => k !== "adapter").map(([k, v]) => (
                <span key={k} className="rounded-md bg-sunken px-2 py-0.5 text-[11.5px] text-ink-2">{k}: <span className="font-medium">{String(v)}</span></span>))}</div>}
              {s.started_at && s.finished_at && <div className="mt-1 text-[11px] text-faint">{Math.max(0, new Date(s.finished_at).getTime() - new Date(s.started_at).getTime())} ms</div>}
            </div>
          </li>
        ))}
      </ol>

      <Disclosure title="State history" meta={`persisted · ${w.attempts ?? 0} claim attempt(s)`} testId="workflow-transitions">
        <Transitions workflowId={w.workflow_id} version={w.version} />
      </Disclosure>

      {w.status === "AWAITING_APPROVAL" && (
        <Notice tone="warn" title="Human approval checkpoint">
          Policy requires {w.approval?.required_approvals ?? 1} approver(s) for this amount. The workflow resumes by itself once
          they decide. <button className="font-medium underline" onClick={() => go("approvals")}>Open approvals →</button>
        </Notice>
      )}
      {w.status === "FAILED" && <Notice tone="bad" title={`Failed at ${w.decision?.failed_step ?? "a step"}`}>
        The coordinator reports failure rather than guessing a result. A workflow left in progress is reclaimed automatically after two minutes.</Notice>}

      {trace && (
        <div>
          <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Trace · {STEP_LABEL[trace.step] ?? trace.step}</h3>
          {trace.events.length ? (
            <ul className="space-y-1 text-[12.5px]">
              {[...trace.events].reverse().map((e, i) => (
                <li key={i} className="flex flex-wrap items-center gap-2"><span className="mono text-[11px] text-faint">#{e.seq}</span>
                  <span className="font-medium">{e.event_type}</span>{e.decision && <Badge>{e.decision}</Badge>}
                  <span className="text-muted">{e.reason ?? ""}</span></li>
              ))}
            </ul>) : <p className="text-[13px] text-muted">No events under this correlation id (audit read requires AUDITOR or IAM_ADMIN).</p>}
        </div>
      )}
    </div>
  );
}

/** Phase 12: the workflow's PERSISTED transitions, read from the server. Every
 *  row is a database record written in the same transaction as the change and
 *  its audit event; nothing here is inferred from what the console did. */
function kindOf(t: Json): { label: string; tone: "warn" | "bad" | "info" | "ok" } | null {
  const reason = String(t.reason ?? "");
  if (reason.includes("lease expired")) return { label: "RECOVERY", tone: "warn" };
  if (reason.includes("recovered")) return { label: "RECOVERED", tone: "ok" };
  if (reason.includes("resumed")) return { label: "RESUMED", tone: "info" };
  if (t.to === "FAILED") return { label: "FAILURE", tone: "bad" };
  return null;
}

function Transitions({ workflowId, version }: { workflowId: string; version?: number }) {
  const r = useResource(() => workflows.transitions(workflowId), [workflowId, version]);
  return (
    <Load r={r} rows={4}>{(rows) => rows.length ? (
      <ol className="relative space-y-2.5 border-l border-line pl-5" data-testid="transition-list">
        {rows.map((t, i) => {
          const kind = kindOf(t);
          return (
            <li key={`${t.at}-${i}`} className="relative animate-step-in" style={{ animationDelay: `${Math.min(i, 12) * 45}ms` }}>
              <span className={`absolute -left-[25px] top-1.5 h-2 w-2 rounded-full ring-4 ring-surface ${kind?.tone === "bad" ? "bg-bad" : kind?.tone === "warn" ? "bg-warn" : "bg-brand"}`} />
              <div className="flex flex-wrap items-center gap-1.5 text-[12.5px]">
                {t.from ? <Badge>{t.from}</Badge> : <span className="text-muted">created</span>}
                <span className="text-faint" aria-label="to">→</span>
                <Badge>{t.to}</Badge>
                {kind && <Badge tone={kind.tone}>{kind.label}</Badge>}
                <span className="ml-auto text-[11.5px] text-muted">{stamp(t.at)}</span>
              </div>
              <div className="mt-1 grid grid-cols-[64px_1fr] gap-x-3 gap-y-0.5 text-[12px]">
                <span className="text-muted">Actor</span>
                <span className="min-w-0">{String(t.actor ?? "").startsWith("did:") ? <Did value={t.actor} /> : <span className="text-ink-2">{t.actor ?? "—"}</span>}</span>
                <span className="text-muted">Request</span><span className="mono min-w-0 break-all text-[11.5px] text-ink-2">{t.request_id ?? "—"}</span>
                {t.reason && <><span className="text-muted">Reason</span><span className="min-w-0 break-words text-ink-2">{t.reason}</span></>}
              </div>
            </li>
          );
        })}
      </ol>) : <p className="text-[13px] text-muted">No transitions recorded for this workflow.</p>}</Load>
  );
}
