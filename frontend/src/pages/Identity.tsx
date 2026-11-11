import { useState } from "react";
import { http, type Json } from "../api/client";
import { Badge, Button, Did, Input, JsonBlock, Kv, Load, Notice, PageHeader, Section, Segmented, Table, Updated } from "../components/ds";
import { ago, stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

type Filter = "ALL" | "ACTIVE" | "REVOKED" | "EXPIRED";

export function Identity() {
  const who = useIdentity()?.subject;
  const creds = useResource(() => http<Json[]>("/api/v1/credentials"), [who], 30_000);
  const issuers = useResource(() => http<Json[]>("/api/v1/credentials/issuers"), [who]);
  const [filter, setFilter] = useState<Filter>("ACTIVE");
  const [subject, setSubject] = useState("");
  const [selected, setSelected] = useState<Json | null>(null);

  return (
    <>
      <PageHeader index="03" eyebrow="Identity & credentials" title="Who an agent is," emphasis="and what it can prove."
                  actions={<Updated at={creds.updatedAt} onRefresh={creds.reload} />}>
        DIDs bind each agent to an Ed25519 key; Verifiable Credentials are signed claims by an issuing authority.
        Only public key material is ever shown. A valid credential is evidence for the PDP, not permission.
      </PageHeader>

      <div className="space-y-6">
        <Section title="Issuing authorities" hint="Trust anchors the verifier resolves issuer keys from.">
          <Load r={issuers}>{(rows) => (
            <Table rows={rows} rowKey={(i) => i.did} columns={[
              { key: "name", label: "Issuer", render: (i) => <div><div className="font-medium">{i.name}</div><Did value={i.did} full /></div> },
              { key: "status", label: "Status", render: (i) => <Badge>{i.status}</Badge> },
              { key: "key", label: "Public key", render: (i) => <span className="mono text-[11.5px] text-ink-2">{(i.public_key_multibase ?? "").slice(0, 22)}…</span> },
              { key: "alg", label: "Algorithm", render: (i) => <span className="text-[12px] text-muted">{i.algorithm} · {i.verification_method?.split("#")[1]}</span> },
            ]} />
          )}</Load>
        </Section>

        <div className="grid gap-6 xl:grid-cols-[1.5fr_1fr]">
          <Section title="Credential inventory"
                   actions={<>
                     <Segmented value={filter} onChange={setFilter} options={[
                       { value: "ACTIVE", label: "Active" }, { value: "REVOKED", label: "Revoked" },
                       { value: "EXPIRED", label: "Expired" }, { value: "ALL", label: "All" }]} />
                   </>}>
            <div className="mb-4 max-w-sm"><Input placeholder="Filter by subject DID…" value={subject} onChange={(e) => setSubject(e.target.value)} /></div>
            <Load r={creds} rows={8}>{(rows) => {
              const shown = rows.filter((c) => (filter === "ALL" || c.status === filter)
                && (!subject || c.subject.includes(subject))).slice(0, 200);
              return (
                <Table rows={shown} rowKey={(c) => c.credential_id} onRow={setSelected} empty="No credentials match." columns={[
                  { key: "type", label: "Type", render: (c) => <div><div className="font-medium">{c.credential_type}</div>
                    <div className="text-[11.5px] text-muted">{c.claims?.capability ?? c.claims?.framework ?? c.claims?.role ?? c.claims?.spawnedBy ?? ""}</div></div> },
                  { key: "subject", label: "Subject", render: (c) => <Did value={c.subject} /> },
                  { key: "issuer", label: "Issuer", render: (c) => <Did value={c.issuer} /> },
                  { key: "status", label: "Status", render: (c) => <Badge>{c.status}</Badge> },
                  { key: "exp", label: "Expires", render: (c) => <span className="text-[12px] text-muted">{ago(c.expires_at)}</span> },
                ]} />
              );
            }}</Load>
          </Section>

          <Section title="Credential detail" hint={selected ? selected.credential_id : "Select a credential."}>
            {selected ? <CredentialDetail summary={selected} onChanged={creds.reload} /> : <p className="text-[13px] text-muted">Nothing selected.</p>}
          </Section>
        </div>
      </div>
    </>
  );
}

function CredentialDetail({ summary, onChanged }: { summary: Json; onChanged: () => void }) {
  const id = summary.credential_id;
  const detail = useResource(() => http<Json>(`/api/v1/credentials/${id}`), [id]);
  const history = useResource(() => http<Json[]>(`/api/v1/credentials/${id}/verifications`), [id]);
  const [verdict, setVerdict] = useState<Json | null>(null);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  const verify = async () => {
    const doc = detail.data?.credential;
    if (!doc) return;
    try {
      setVerdict(await http<Json>("/api/v1/credentials/verify", { method: "POST",
        body: JSON.stringify({ credential: doc, expected_subject: summary.subject }) }));
      history.reload();
    } catch (e) { setMessage({ tone: "bad", text: (e as Error).message }); }
  };
  const revoke = async () => {
    try {
      await http(`/api/v1/credentials/${id}/revoke`, { method: "POST", body: JSON.stringify({ reason }) });
      setMessage({ tone: "ok", text: "Revoked. Every verifier now rejects it." });
      onChanged(); detail.reload();
    } catch (e) { setMessage({ tone: "bad", text: (e as Error).message }); }
  };

  return (
    <div className="space-y-5">
      <Kv rows={[
        ["Type", summary.credential_type],
        ["Subject", <Did value={summary.subject} full />],
        ["Issuer", <Did value={summary.issuer} full />],
        ["Status", <Badge>{summary.status}</Badge>],
        ["Issued", stamp(summary.issued_at)],
        ["Expires", `${stamp(summary.expires_at)} (${ago(summary.expires_at)})`],
      ]} />
      <div>
        <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Claims</h3>
        <JsonBlock value={summary.claims} />
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={verify} disabled={!detail.data}>Verify signature & status now</Button>
      </div>
      {verdict && (
        <Notice tone={verdict.valid ? "ok" : "bad"} title={verdict.valid ? "Valid" : `Invalid · ${verdict.reason}`}>
          <ul className="mt-1 space-y-0.5">
            {(verdict.check_details ?? []).map((c: Json) => <li key={c.name}>{c.passed ? "✓" : "✗"} {c.name} — {c.detail}</li>)}
          </ul>
        </Notice>
      )}
      <div>
        <h3 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-muted">Verification history</h3>
        <Load r={history}>{(rows) => rows.length ? (
          <ul className="space-y-1 text-[12.5px]">
            {rows.slice(0, 12).map((v, i) => (
              <li key={i} className="flex flex-wrap gap-2"><Badge>{v.valid ? "VALID" : "INVALID"}</Badge>
                <span className="text-ink-2">{v.reason}</span><span className="text-muted">by {v.verifier}</span>
                <span className="ml-auto text-[11px] text-faint">{ago(v.timestamp)}</span></li>))}
          </ul>) : <p className="text-[13px] text-muted">Never verified.</p>}</Load>
      </div>
      {summary.status === "ACTIVE" && (
        <div className="rounded-lg border border-line p-3">
          <h3 className="mb-2 text-[12px] font-semibold text-ink">Revoke (IAM administrator)</h3>
          <Input placeholder="Reason, recorded in the audit trail" value={reason} onChange={(e) => setReason(e.target.value)} />
          <div className="mt-2"><Button variant="danger" disabled={reason.trim().length < 3} onClick={revoke}>Revoke credential</Button></div>
        </div>
      )}
      {message && <Notice tone={message.tone}>{message.text}</Notice>}
    </div>
  );
}
