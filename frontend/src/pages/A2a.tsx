import { useState } from "react";
import { http, type Json } from "../api/client";
import { Badge, Did, Kv, Load, PageHeader, Section, Table, Updated } from "../components/ds";
import { ago, inr, stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

export function A2a() {
  const who = useIdentity()?.subject;
  const r = useResource(() => http<Json[]>("/api/v1/a2a/transactions?limit=100"), [who], 10_000);
  const [selected, setSelected] = useState<Json | null>(null);

  return (
    <>
      <PageHeader index="08" eyebrow="Agent-to-agent transactions" title="Signed by the sender," emphasis="reconciled four times."
                  actions={<Updated at={r.updatedAt} onRefresh={r.reload} />}>
        Each instruction is an Ed25519-signed envelope bound to its receiver, freshness window and payload digest. The PDP
        authorises the SENDER; execution is claimed atomically, so a transaction runs exactly once.
      </PageHeader>
      <div className="grid gap-6 xl:grid-cols-[1.6fr_1fr]">
        <Section title="Ledger" hint="Newest first.">
          <Load r={r} rows={8}>{(rows) => (
            <Table rows={rows} rowKey={(t) => t.transaction_id} onRow={setSelected} empty="No transactions." columns={[
              { key: "id", label: "Transaction", render: (t) => <span className="mono text-[12px]">{t.transaction_id}</span> },
              { key: "path", label: "Sender → receiver", render: (t) => <span><Did value={t.sender_did} /> → <Did value={t.receiver_did} /></span> },
              { key: "amt", label: "Amount", render: (t) => <span className="tabular-nums">{inr(t.amount?.signed_inr)}</span> },
              { key: "rec", label: "Reconciled", render: (t) => <Badge tone={t.amount?.reconciled ? "ok" : t.status === "EXECUTED" ? "bad" : "neutral"}>{t.amount?.reconciled ? "YES" : "—"}</Badge> },
              { key: "status", label: "Status", render: (t) => <Badge>{t.status}</Badge> },
              { key: "t", label: "Issued", render: (t) => <span className="text-[12px] text-muted">{ago(t.issued_at)}</span> },
            ]} />
          )}</Load>
        </Section>
        <Section title="Transaction" hint={selected?.transaction_id ?? "Select a transaction."}>
          {selected ? (
            <Kv rows={[
              ["Status", <Badge>{selected.status}</Badge>],
              ["Reason", <span className="mono text-[12px]">{selected.reason}</span>],
              ["PDP decision", <span><Badge>{selected.decision ?? "—"}</Badge> <span className="mono text-[11px] text-muted">{selected.decision_reason}</span></span>],
              ["Policy", <span className="mono text-[12px]">{selected.policy ?? "—"}</span>],
              ["Action", `${selected.action} · ${selected.resource_type} / ${selected.resource_id}`],
              ["Purpose", selected.purpose],
              ["Signed amount", inr(selected.amount?.signed_inr)],
              ["Server record", inr(selected.amount?.server_inr)],
              ["Authorised", inr(selected.amount?.authorized_inr)],
              ["Executed", inr(selected.amount?.executed_inr)],
              ["Human approvals", selected.required_approvals ?? "not required"],
              ["Payload SHA-256", <span className="mono text-[11px] break-all">{selected.payload_sha256}</span>],
              ["Replay protection", "transaction id is unique; a reused id with different content is refused"],
              ["Issued", stamp(selected.issued_at)],
            ]} />
          ) : <p className="text-[13px] text-muted">Nothing selected.</p>}
        </Section>
      </div>
    </>
  );
}
