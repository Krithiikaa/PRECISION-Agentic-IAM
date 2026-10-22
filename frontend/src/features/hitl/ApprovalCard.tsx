import type { ApprovalRequest } from "../../types";

/**
 * ONE approval, shown in full.
 *
 * The rule this component exists to enforce: a human must never be asked to
 * approve "an agent wants access". They see which agent, what it wants to do,
 * to which record, for how much money, why policy stopped it, and when the
 * request dies. An approval nobody could have understood is not a meaningful
 * approval -- and the audit trail would carry a person's name against a
 * decision they had no way to make.
 *
 * Everything rendered here comes from the SERVER's `presentation` block, built
 * from the tool's own spec and the resource record. The requesting agent
 * cannot describe itself flatteringly to the person judging it.
 */

function Field({ label, value, emphasis = false }: {
  label: string;
  value: React.ReactNode;
  emphasis?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-wider text-slate-500">
        {label}
      </span>
      <span
        className={
          emphasis
            ? "text-sm font-semibold text-amber-200"
            : "mono text-xs text-slate-200"
        }
      >
        {value}
      </span>
    </div>
  );
}

function remaining(iso: string): string {
  const seconds = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (seconds <= 0) return "expired";
  if (seconds < 60) return `${seconds}s left`;
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s left`;
}

const STATUS_TONE: Record<string, string> = {
  PENDING: "bg-amber-500/15 text-amber-200 border-amber-500/30",
  APPROVED: "bg-emerald-500/15 text-emerald-200 border-emerald-500/30",
  REJECTED: "bg-rose-500/15 text-rose-200 border-rose-500/30",
  EXPIRED: "bg-slate-600/20 text-slate-400 border-slate-600/40",
  CANCELLED: "bg-slate-600/20 text-slate-400 border-slate-600/40",
  CONSUMED: "bg-sky-500/15 text-sky-200 border-sky-500/30",
};

export function ApprovalCard({
  approval, canDecide, busy, onDecide, note, onNote, alreadySigned = false,
}: {
  approval: ApprovalRequest;
  canDecide: boolean;
  busy: boolean;
  onDecide: (decision: "APPROVED" | "REJECTED") => void;
  note: string;
  onNote: (value: string) => void;
  /** Whether the signed-in human has already signed THIS approval. Display
   *  only -- the server refuses a second sign-off whatever this says. */
  alreadySigned?: boolean;
}) {
  const p = approval.presentation;
  const detail = (p?.resource?.detail ?? {}) as Record<string, unknown>;
  const pending = approval.status === "PENDING";
  const required = approval.required_approvals ?? 1;
  const recorded = approval.approvals_recorded ?? 0;
  const dual = required > 1;

  return (
    <article className="rounded border border-slate-800 bg-slate-900/50">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold tracking-wide text-slate-100">
            HUMAN APPROVAL {pending ? "REQUIRED" : "RECORD"}
          </span>
          <span
            className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${
              STATUS_TONE[approval.status] ?? STATUS_TONE.EXPIRED
            }`}
          >
            {approval.status}
          </span>
          {dual && (
            <span className="rounded border border-violet-500/40 bg-violet-500/10 px-1.5 py-0.5 text-[10px] font-medium text-violet-200">
              DUAL CONTROL · {recorded} of {required}
            </span>
          )}
        </div>
        <span className="mono text-[10px] text-slate-500">
          {approval.approval_id}
        </span>
      </header>

      <div className="grid gap-3 px-4 py-3 sm:grid-cols-2">
        <Field label="Agent" value={p?.agent?.name ?? approval.agent_did} />
        <Field label="DID" value={approval.agent_did} />
        <Field label="Action" value={p?.action?.label ?? approval.action} />
        <Field
          label="Resource"
          value={`${p?.resource?.label ?? approval.resource.type} ${approval.resource.id ?? ""}`}
        />
        {typeof detail.amount === "string" && (
          <Field label="Amount" value={detail.amount as string} emphasis />
        )}
        {typeof detail.applicant === "string" && (
          <Field label="Applicant" value={detail.applicant as string} />
        )}
        {typeof detail.submitted_by === "string" && (
          <Field label="Submitted by" value={detail.submitted_by as string} />
        )}
        {typeof detail.product === "string" && (
          <Field label="Product" value={detail.product as string} />
        )}
        {typeof detail.risk_band === "string" && (
          <Field label="Risk band" value={detail.risk_band as string} />
        )}
        <Field label="Purpose" value={approval.purpose} />
        <Field
          label="Attested capabilities"
          value={(p?.agent?.verified_capabilities ?? []).join(", ") || "none"}
        />
        <Field
          label="Requested"
          value={new Date(approval.requested_at).toLocaleTimeString()}
        />
        <Field
          label={pending ? "Request expires" : "Approval expires"}
          value={
            pending
              ? `${new Date(approval.request_expires_at).toLocaleTimeString()} (${remaining(approval.request_expires_at)})`
              : approval.expires_at
                ? `${new Date(approval.expires_at).toLocaleTimeString()} (${remaining(approval.expires_at)})`
                : "-"
          }
        />
      </div>

      {dual && (
        <p className="border-t border-slate-800 bg-violet-500/5 px-4 py-2.5 text-xs leading-relaxed text-violet-200">
          <span className="font-medium">Two different people must approve this. </span>
          {p?.approval?.explanation ??
            "Your decision alone does not release the action, and you cannot provide both approvals."}
          {approval.signoffs?.length > 0 && (
            <span className="mono ml-1 text-[10px] text-violet-300/80">
              (signed so far:{" "}
              {approval.signoffs.map((s) => s.username ?? s.subject).join(", ")})
            </span>
          )}
        </p>
      )}

      <p className="border-t border-slate-800 px-4 py-2.5 text-xs leading-relaxed text-slate-400">
        <span className="font-medium text-slate-300">Why you are being asked: </span>
        {p?.policy?.explanation ?? approval.reason}
        {p?.policy?.policy && (
          <span className="mono ml-1 text-[10px] text-slate-500">
            ({p.policy.policy})
          </span>
        )}
      </p>

      {approval.approver && (
        <p className="border-t border-slate-800 px-4 py-2 text-[11px] text-slate-400">
          {dual ? "Approved by " : "Decided by "}
          <span className="font-medium text-slate-200">
            {dual && approval.signoffs?.length
              ? approval.signoffs.map((s) => s.username ?? s.subject).join(" and ")
              : approval.approver.username}
          </span>{" "}
          ({approval.approver.roles.join(", ")})
          {approval.artifact_signed_by && (
            <>
              {" · artifact signed by "}
              <span className="mono text-[10px]">{approval.artifact_signed_by}</span>
            </>
          )}
        </p>
      )}

      {pending && (
        <div className="border-t border-slate-800 px-4 py-3">
          {canDecide ? (
            <>
              <input
                value={note}
                onChange={(e) => onNote(e.target.value)}
                placeholder="Note recorded with your decision (optional)"
                className="mb-2 w-full rounded border border-slate-700 bg-slate-950/60 px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-600"
              />
              <div className="flex gap-2">
                <button
                  disabled={busy}
                  onClick={() => onDecide("REJECTED")}
                  className="flex-1 rounded border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold text-rose-200 hover:bg-rose-500/20 disabled:opacity-40"
                >
                  REJECT
                </button>
                <button
                  disabled={busy}
                  onClick={() => onDecide("APPROVED")}
                  className="flex-1 rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-40"
                >
                  APPROVE
                </button>
              </div>
              {alreadySigned && (
                <p className="mt-2 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-[10px] leading-relaxed text-amber-200">
                  You have already signed this approval. A second sign-off from
                  the same person is refused by policy and by the database --
                  the buttons stay enabled so the refusal is visible rather than
                  hidden behind a disabled control.
                </p>
              )}
              <p className="mt-2 text-[10px] leading-relaxed text-slate-500">
                Approving records your decision as a signed, single-use artifact
                bound to this exact action -- including the amount shown above,
                so a figure that changes afterwards invalidates it. It does not
                perform the action: the agent must come back through the
                enforcement boundary, and the PDP is asked again.
                {dual && " This approval also needs a second, different person."}
              </p>
            </>
          ) : (
            <p className="text-[11px] text-slate-500">
              You are signed in, and your role does not approve this action.
              Deciding is refused by policy, not by this screen.
            </p>
          )}
        </div>
      )}
    </article>
  );
}
