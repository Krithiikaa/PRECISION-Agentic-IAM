import { useState } from "react";
import { http, type Json } from "../api/client";
import { Badge, Button, Did, JsonBlock, Kv, Load, Notice, PageHeader, Segmented, TextArea, Updated } from "../components/ds";
import { ago, inr, stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

export function Approvals() {
  const identity = useIdentity();
  const [view, setView] = useState<"PENDING" | "ALL">("PENDING");
  const r = useResource(() => http<Json[]>(`/api/v1/hitl/approvals${view === "PENDING" ? "?status=PENDING" : ""}`),
                        [identity?.subject, view], 8_000);
  const [open, setOpen] = useState<string | null>(null);

  return (
    <>
      <PageHeader index="07" eyebrow="Human approvals" title="A person decides" emphasis="what an agent may not."
                  actions={<Updated at={r.updatedAt} onRefresh={r.reload} />}>
        Escalations come from policy. A decision is signed by the approval authority and bound to the exact request,
        amount and officer of record. Maker-checker and dual control are enforced by the server; the buttons here only ask.
      </PageHeader>
      <div className="mb-4"><Segmented value={view} onChange={setView}
           options={[{ value: "PENDING", label: "Pending" }, { value: "ALL", label: "History" }]} /></div>
      <Load r={r} rows={6}>{(rows) => rows.length ? (
        <div className="space-y-4">
          {rows.slice(0, 40).map((a) => (
            <ApprovalCard key={a.approval_id} a={a} expanded={open === a.approval_id}
                          toggle={() => setOpen(open === a.approval_id ? null : a.approval_id)}
                          onDecided={r.reload} canDecide={!!identity} />
          ))}
        </div>
      ) : <Notice tone="ok">No {view === "PENDING" ? "pending " : ""}approvals.</Notice>}</Load>
    </>
  );
}

function ApprovalCard({ a, expanded, toggle, onDecided, canDecide }: {
  a: Json; expanded: boolean; toggle: () => void; onDecided: () => void; canDecide: boolean;
}) {
  const [note, setNote] = useState("");
  const [result, setResult] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);
  const p = a.presentation ?? {};
  const detail = p.resource?.detail ?? {};
  const amount = detail.amount_value ?? a.binding?.amount_inr;

  const decide = async (decision: "APPROVED" | "REJECTED") => {
    try {
      const out = await http<Json>(`/api/v1/hitl/approvals/${a.approval_id}/decide`, {
        method: "POST", body: JSON.stringify({ decision, note: note || null }) });
      setResult({ tone: "ok", text: `Recorded: ${out.status}. ${out.awaiting_approvals ? `${out.awaiting_approvals} more approver(s) needed.` : ""}` });
      onDecided();
    } catch (e) { setResult({ tone: "bad", text: (e as Error).message }); }
  };

  return (
    <article className="rounded-xl border border-line bg-surface shadow-card animate-rise">
      <button onClick={toggle} className="flex w-full flex-wrap items-center gap-3 px-5 py-4 text-left">
        <Badge>{a.status}</Badge>
        <span className="font-medium text-ink">{p.action?.label ?? a.action}</span>
        <span className="text-[13px] text-muted">{a.resource?.type} · {a.resource?.id}</span>
        {amount != null && <span className="display text-[20px] text-ink">{inr(amount)}</span>}
        <span className="text-[12px] text-muted">by <Did value={a.agent_did} /></span>
        <span className="ml-auto flex items-center gap-2 text-[12px] text-muted">
          {a.dual_control && <Badge tone="warn">DUAL CONTROL</Badge>}
          {a.approvals_recorded}/{a.required_approvals} approvals · {ago(a.requested_at)}
        </span>
      </button>
      {expanded && (
        <div className="grid gap-6 border-t border-line px-5 py-5 lg:grid-cols-2">
          <div className="space-y-4">
            {p.policy?.explanation && <Notice tone="warn" title={`Why a human: ${p.policy.reason}`}>{p.policy.explanation}</Notice>}
            <Kv rows={[
              ["Agent", <Did value={a.agent_did} full />],
              ["Verified capabilities", (p.agent?.verified_capabilities ?? []).join(", ") || "—"],
              ["Action", p.action?.description ?? a.action],
              ["Purpose", a.purpose],
              ["Applicant", detail.applicant ? `${detail.applicant} (${detail.customer_id})` : "—"],
              ["Officer of record", <span>{detail.submitted_by ?? "—"} <span className="text-[11.5px] text-muted">(may not approve: maker-checker)</span></span>],
              ["Deciding policy", <span className="mono text-[12px]">{p.policy?.policy}</span>],
              ["Request binding", <span className="mono text-[11px] break-all">{a.binding_sha256}</span>],
              ["Requested", stamp(a.requested_at)],
              ["Request expires", stamp(a.request_expires_at)],
            ]} />
          </div>
          <div className="space-y-4">
            <div>
              <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Sign-offs</h3>
              {(a.signoffs ?? []).length ? (
                <ul className="space-y-1.5 text-[13px]">
                  {a.signoffs.map((s: Json) => (
                    <li key={s.sequence} className="flex flex-wrap items-center gap-2"><Badge>{s.decision}</Badge>
                      <span className="font-medium">{s.username}</span>
                      <span className="text-[11.5px] text-muted">{(s.roles ?? []).filter((r: string) => /^[A-Z_]+$/.test(r)).join(", ")} · {s.provider}</span>
                      <span className="ml-auto text-[11px] text-faint">{ago(s.decided_at)}</span></li>
                  ))}
                </ul>) : <p className="text-[13px] text-muted">No sign-offs yet.</p>}
            </div>
            {a.artifact && (
              <details className="text-[12px]"><summary className="cursor-pointer text-brand">Signed approval artifact ({a.artifact_signed_by})</summary>
                <div className="mt-2"><JsonBlock value={a.artifact} /></div></details>
            )}
            {a.status === "PENDING" && (
              <div className="rounded-lg border border-line p-3">
                {!canDecide && <p className="mb-2 text-[12px] text-muted">Sign in as a loan or payment officer to decide.</p>}
                <TextArea placeholder="Note (optional, recorded with your decision)" value={note} onChange={(e) => setNote(e.target.value)} />
                <div className="mt-2 flex gap-2">
                  <Button variant="primary" onClick={() => decide("APPROVED")}>Approve</Button>
                  <Button variant="danger" onClick={() => decide("REJECTED")}>Reject</Button>
                </div>
              </div>
            )}
            {result && <Notice tone={result.tone}>{result.text}</Notice>}
          </div>
        </div>
      )}
    </article>
  );
}
