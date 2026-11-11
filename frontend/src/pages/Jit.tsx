import { useState } from "react";
import { http, type Json } from "../api/client";
import { Badge, Button, Did, Input, Load, Notice, PageHeader, Section, Segmented, Table, Updated } from "../components/ds";
import { ago } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

export function Jit() {
  const who = useIdentity()?.subject;
  const [activeOnly, setActiveOnly] = useState<"active" | "all">("active");
  const grants = useResource(() => http<Json[]>(`/api/v1/jit?limit=200${activeOnly === "active" ? "&active_only=true" : ""}`),
                             [who, activeOnly], 10_000);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  const revoke = async (grantId: string) => {
    try {
      await http(`/api/v1/jit/${grantId}/revoke`, { method: "POST", body: JSON.stringify({ reason: reason || "revoked from the operations console" }) });
      setMessage({ tone: "ok", text: `${grantId} revoked.` }); grants.reload();
    } catch (e) { setMessage({ tone: "bad", text: (e as Error).message }); }
  };

  return (
    <>
      <PageHeader index="06" eyebrow="Just-in-time access" title="Temporary authority," emphasis="always re-decided."
                  actions={<Updated at={grants.updatedAt} onRefresh={grants.reload} />}>
        A mandate is signed by the JIT authority, bounded in time and in uses, and bound to one agent, action and resource.
        It never authorises by itself: each use is a fresh PDP decision in which the mandate is one more fact.
      </PageHeader>

      <Section title="Mandates" actions={<Segmented value={activeOnly} onChange={setActiveOnly}
               options={[{ value: "active", label: "Active" }, { value: "all", label: "All recent" }]} />}>
        <div className="mb-4 max-w-md"><Input placeholder="Revocation reason (recorded in the audit trail)" value={reason} onChange={(e) => setReason(e.target.value)} /></div>
        {message && <div className="mb-4"><Notice tone={message.tone}>{message.text}</Notice></div>}
        <Load r={grants} rows={6}>{(rows) => (
          <Table rows={rows} rowKey={(g) => g.grant_id} empty="No mandates." columns={[
            { key: "id", label: "Grant", render: (g) => <div><div className="mono text-[12px]">{g.grant_id}</div><div className="text-[11px] text-muted">signed {g.signed_by_kid?.split("#")[1]}</div></div> },
            { key: "agent", label: "Bound to", render: (g) => <Did value={g.agent_did} /> },
            { key: "scope", label: "Scope", render: (g) => <span className="text-[12.5px]">{g.action} · {g.resource_type}<div className="text-[11px] text-muted">{(g.resource_ids ?? []).join(", ") || "any id"} · {g.purpose}</div></span> },
            { key: "uses", label: "Uses", render: (g) => <span className="mono text-[12px]">{g.uses}/{g.max_uses}</span> },
            { key: "ttl", label: "Expires", render: (g) => <span className="text-[12px] text-muted">{ago(g.expires_at)}</span> },
            { key: "status", label: "Status", render: (g) => <Badge>{g.status}</Badge> },
            { key: "act", label: "", render: (g) => g.status === "ACTIVE" ? <Button variant="ghost" onClick={() => revoke(g.grant_id)}>Revoke</Button> : null },
          ]} />
        )}</Load>
      </Section>
    </>
  );
}
