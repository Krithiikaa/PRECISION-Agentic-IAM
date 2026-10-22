import { Panel } from "../../components/ui";

/**
 * The conceptual distinction the whole phase rests on.
 * Static explanatory diagram: it asserts nothing about live system state.
 */
export function IdentityVsCredential() {
  return (
    <Panel
      title="Identity vs credential vs authorization"
      subtitle="Which question does each layer answer?"
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          {
            layer: "DID + Ed25519",
            question: "Who is this agent?",
            answer: "A key pair the agent controls, published in a DID Document.",
            phase: "Phase 1",
            tone: "border-sky-600/40 bg-sky-600/10",
          },
          {
            layer: "Verifiable credential",
            question: "What has a trusted authority attested about it?",
            answer: "Signed claims from an issuer: capability, role, compliance.",
            phase: "Phase 2",
            tone: "border-emerald-600/40 bg-emerald-600/10",
          },
          {
            layer: "PDP",
            question: "Is this specific request allowed right now?",
            answer: "Policy over credentials plus live context.",
            phase: "Phase 4 — not built",
            tone: "border-slate-700 bg-slate-800/30",
          },
          {
            layer: "AEM",
            question: "How is a disallowed request stopped?",
            answer: "Enforcement at the tool and protocol boundary.",
            phase: "Phase 4 — not built",
            tone: "border-slate-700 bg-slate-800/30",
          },
        ].map((item) => (
          <div key={item.layer} className={`rounded border p-3 ${item.tone}`}>
            <p className="text-xs font-semibold text-slate-100">{item.layer}</p>
            <p className="mt-1.5 text-[11px] italic text-slate-300">“{item.question}”</p>
            <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">{item.answer}</p>
            <p className="mono mt-2 text-[10px] uppercase tracking-wide text-slate-500">
              {item.phase}
            </p>
          </div>
        ))}
      </div>
      <p className="mt-3 text-[11px] leading-relaxed text-slate-500">
        Holding a credential is <span className="text-slate-300">evidence</span>, not permission.
        A credential saying <span className="mono">capability: credit_analysis</span> means an
        issuer attested that capability — it does not mean the agent may read any particular
        record. That decision belongs to the policy layer, which does not exist yet.
      </p>
    </Panel>
  );
}
