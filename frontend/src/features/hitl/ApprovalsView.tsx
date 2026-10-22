import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client";
import type { HumanIdentity } from "../../auth/oidc";
import { useApprovalEvents } from "../../hooks/useEvents";
import type { ApprovalRequest } from "../../types";
import { ApprovalCard } from "./ApprovalCard";

/**
 * The approval queue: what agents are waiting on a person for.
 *
 * The queue itself is readable without signing in -- it shows what an agent
 * WANTS to do and no resource data. Opening one and deciding it require an
 * authenticated human, and the server decides whether their role permits it.
 *
 * This view never pre-judges permission. It offers the buttons to a signed-in
 * user whose token carries LOAN_OFFICER, and the server refuses anything else
 * on its own authority. A UI that hid the buttons would be guessing at policy;
 * one that enforced it would be a second implementation of it.
 *
 * HOW IT STAYS CURRENT (Phase 5.5, spec §12). It listens to the SSE stream the
 * console already has, and RE-READS THE QUEUE when an approval-lifecycle event
 * arrives. The event is a nudge, never data: it says "something changed, ask
 * the server again". A view that rendered an approval out of a broadcast would
 * be letting the event bus tell it what it is allowed to see.
 *
 * The poll is kept as a slow backstop rather than removed. SSE can drop, a
 * proxy can buffer it, and an approval queue that silently stops updating is a
 * worse failure than one that updates late -- so the push makes it fast and the
 * poll makes it certain. That is why the interval got longer instead of going
 * away: §12 says do not destabilise the flow for UI animation, and removing the
 * only guaranteed refresh path would have done exactly that.
 */

// Slow backstop. The SSE stream does the actual work; this only has to catch a
// stream that quietly died.
const BACKSTOP_POLL_MS = 20_000;
export function ApprovalsView({ identity }: { identity: HumanIdentity | null }) {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [showDecided, setShowDecided] = useState(false);

  const load = useCallback(async () => {
    try {
      setApprovals(await api.approvals());
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, BACKSTOP_POLL_MS);
    return () => clearInterval(timer);
  }, [load]);

  // Push. An approval opened, viewed, signed off, completed or consumed
  // anywhere in the system re-reads the queue here within one round trip.
  useApprovalEvents(load);

  const decide = async (
    approval: ApprovalRequest,
    decision: "APPROVED" | "REJECTED",
  ) => {
    setBusy(approval.approval_id);
    setError(null);
    try {
      // Opening the approval first is what makes the decision INFORMED, and it
      // is recorded as APPROVAL_VIEWED. The card already shows everything; this
      // makes "somebody read it" a fact in the audit trail rather than an
      // assumption.
      await api.approval(approval.approval_id);
      await api.decideApproval(approval.approval_id, decision,
                               notes[approval.approval_id]);
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const canDecide = Boolean(identity?.roles.includes("LOAN_OFFICER"));
  // Whether THIS person has already signed a given approval. Display only:
  // the server refuses a second sign-off from the same human whatever the UI
  // shows, and the button is left enabled so the refusal is visible rather
  // than hidden behind a disabled control.
  const alreadySigned = (approval: ApprovalRequest) =>
    Boolean(identity && (approval.signoffs ?? []).some(
      (signoff) => signoff.subject === identity.subject));
  const pending = approvals.filter((a) => a.status === "PENDING");
  const decided = approvals.filter((a) => a.status !== "PENDING");
  const shown = showDecided ? decided : pending;

  return (
    <section className="space-y-3">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Human approvals
          </h2>
          <p className="mt-0.5 text-[11px] text-slate-500">
            Actions policy referred to a person. Approving records a decision;
            it does not perform the action.
          </p>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setShowDecided(false)}
            className={`rounded px-2.5 py-1 text-[11px] ${
              !showDecided ? "bg-slate-700/70 text-slate-100" : "text-slate-500"
            }`}
          >
            Pending ({pending.length})
          </button>
          <button
            onClick={() => setShowDecided(true)}
            className={`rounded px-2.5 py-1 text-[11px] ${
              showDecided ? "bg-slate-700/70 text-slate-100" : "text-slate-500"
            }`}
          >
            Decided ({decided.length})
          </button>
        </div>
      </header>

      {!identity && pending.length > 0 && (
        <p className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[11px] text-amber-200">
          Sign in to decide. The queue is visible to anyone; the decision is not.
        </p>
      )}

      {identity && !canDecide && pending.length > 0 && (
        <p className="rounded border border-slate-700 bg-slate-800/40 px-3 py-2 text-[11px] text-slate-400">
          Signed in as{" "}
          <span className="text-slate-200">{identity.username}</span> (
          {identity.roles.join(", ") || "no roles"}). Loan decisions require
          LOAN_OFFICER. IAM administration and lending authority are separate on
          purpose.
        </p>
      )}

      {error && (
        <p className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-200">
          {error}
        </p>
      )}

      {shown.length === 0 && (
        <p className="rounded border border-slate-800 bg-slate-900/40 px-3 py-6 text-center text-xs text-slate-500">
          {showDecided
            ? "No decisions recorded yet."
            : "Nothing is waiting on a human."}
        </p>
      )}

      <div className="space-y-3">
        {shown.map((approval) => (
          <ApprovalCard
            key={approval.approval_id}
            approval={approval}
            canDecide={canDecide}
            busy={busy === approval.approval_id}
            note={notes[approval.approval_id] ?? ""}
            onNote={(value) =>
              setNotes((n) => ({ ...n, [approval.approval_id]: value }))
            }
            onDecide={(decision) => decide(approval, decision)}
            alreadySigned={alreadySigned(approval)}
          />
        ))}
      </div>
    </section>
  );
}
