import { useEffect, useRef, useState } from "react";
import { auditIntegrity, currentBearer, http, type Json } from "../api/client";
import { Badge, Button, Did, Disclosure, Input, JsonBlock, Load, Notice, PageHeader, Section, Skeleton, Table, Updated } from "../components/ds";
import { downloadCsv, downloadJson, stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

type Filters = { event_type: string; agent_did: string; decision: string; request_id: string };

export function Audit() {
  const who = useIdentity()?.subject;
  const [draft, setDraft] = useState<Filters>({ event_type: "", agent_did: "", decision: "", request_id: "" });
  const [filters, setFilters] = useState<Filters>(draft);
  const query = new URLSearchParams(Object.entries(filters).filter(([, v]) => v) as [string, string][]);
  query.set("limit", "300");
  const r = useResource(() => http<Json[]>(`/api/v1/audit?${query}`), [who, query.toString()]);
  const [selected, setSelected] = useState<Json | null>(null);

  return (
    <>
      <PageHeader index="11" eyebrow="Audit & compliance" title="Every decision," emphasis="in order, attributable."
                  actions={r.data?.length ? <>
                    <Button onClick={() => downloadCsv("precision-audit.csv", r.data!.map(({ metadata, ...rest }) => ({ ...rest, metadata })))}>Export CSV</Button>
                    <Button onClick={() => downloadJson("precision-audit.json", r.data)}>Export JSON</Button></> : undefined}>
        The audit trail is append-only with a monotonic sequence. A correlation (request) id ties together the PDP
        decision, the AEM interception, any human approval and the tool execution of one request.
      </PageHeader>

      <div className="space-y-6">
        <AuditIntegrity />
        <LiveStream />
        <Section title="Query the trail">
          <form className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5" onSubmit={(e) => { e.preventDefault(); setFilters(draft); }}>
            <Input label="Event type" placeholder="e.g. AEM_BLOCKED" value={draft.event_type} onChange={(e) => setDraft({ ...draft, event_type: e.target.value.trim() })} />
            <Input label="Agent DID" placeholder="did:poc:agent:…" value={draft.agent_did} onChange={(e) => setDraft({ ...draft, agent_did: e.target.value.trim() })} />
            <Input label="Decision" placeholder="ALLOW / DENY / …" value={draft.decision} onChange={(e) => setDraft({ ...draft, decision: e.target.value.trim() })} />
            <Input label="Correlation id" placeholder="request id" value={draft.request_id} onChange={(e) => setDraft({ ...draft, request_id: e.target.value.trim() })} />
            <div className="flex items-end gap-2"><Button type="submit" variant="primary">Search</Button>
              <Button onClick={() => { const empty = { event_type: "", agent_did: "", decision: "", request_id: "" }; setDraft(empty); setFilters(empty); }}>Clear</Button></div>
          </form>
        </Section>

        <div className="grid gap-6 xl:grid-cols-[1.6fr_1fr]">
          <Section title="Events" hint="Newest first; select one for its full record.">
            <Load r={r} rows={10}>{(rows) => (
              <Table rows={rows} rowKey={(e) => e.id} onRow={setSelected} empty="No events match." columns={[
                { key: "seq", label: "Seq", render: (e) => <span className="mono text-[11.5px] text-faint">{e.seq}</span> },
                { key: "t", label: "Time", render: (e) => <span className="text-[12px] text-muted">{stamp(e.timestamp)}</span> },
                { key: "type", label: "Event", render: (e) => <span className="font-medium">{e.event_type}</span> },
                { key: "actor", label: "Actor", render: (e) => <Did value={e.agent_did} /> },
                { key: "res", label: "Action · resource", render: (e) => <span className="text-[12px] text-ink-2">{[e.action, e.resource].filter(Boolean).join(" · ") || "—"}</span> },
                { key: "dec", label: "Outcome", render: (e) => e.decision ? <Badge>{e.decision}</Badge> : null },
                { key: "req", label: "Correlation", render: (e) => e.request_id ? (
                  <button className="mono text-[11px] text-brand hover:underline" onClick={(ev) => { ev.stopPropagation(); const f = { event_type: "", agent_did: "", decision: "", request_id: e.request_id }; setDraft(f); setFilters(f); }}>{e.request_id}</button>) : null },
              ]} />
            )}</Load>
          </Section>
          <Section title="Event record" hint={selected ? `#${selected.seq}` : "Select an event."}>
            {selected ? <JsonBlock value={selected} /> : <p className="text-[13px] text-muted">Nothing selected.</p>}
          </Section>
        </div>
      </div>
    </>
  );
}

/** Phase 12: the SERVER's integrity verdict over the hash chain, the write-time
 *  MACs and the signed checkpoints. The console never verifies anything itself
 *  and never widens the verdict: events before the chain's genesis are shown
 *  as OUTSIDE coverage, NOT verified, in a separate block. */
function AuditIntegrity() {
  const who = useIdentity()?.subject;
  const r = useResource(() => auditIntegrity.verify(), [who]);
  return (
    <Section title="Audit integrity"
             hint="Verified on the server: hash chain, per-event MACs and Ed25519-signed checkpoints."
             actions={<><Updated at={r.updatedAt} onRefresh={r.reload} />
               <Button onClick={r.reload} disabled={r.loading}>{r.loading ? "Verifying…" : "Verify now"}</Button></>}>
      {r.error && !r.denied && r.data ? (
        <Notice tone="warn" title="Verification unavailable">
          The last request failed ({r.error.message}). The result below is from {stamp(r.updatedAt?.toISOString())} and is not current.
        </Notice>) : null}
      <Load r={r} rows={4}>{(v) => <IntegrityReport v={v} />}</Load>
    </Section>
  );
}

function IntegrityReport({ v }: { v: Json }) {
  const ok = v.ok === true && v.status === "VERIFIED";
  const findings = (v.findings ?? []) as Json[];
  const legacy = Number(v.events_before_coverage ?? 0);
  return (
    <div className="space-y-4" data-testid="audit-integrity">
      <div key={v.verified_at} className="flex flex-wrap items-center gap-3 animate-status-in">
        <span className={`inline-flex h-9 w-9 items-center justify-center rounded-full text-[16px] ${ok ? "bg-ok-bg text-ok" : "bg-bad-bg text-bad"}`} aria-hidden>{ok ? "✓" : "!"}</span>
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={ok ? "ok" : "bad"}>{ok ? "VERIFIED" : "INTEGRITY VIOLATION"}</Badge>
            <span className="text-[13px] text-ink">{ok ? "No tampering detected inside chain coverage" : `${v.finding_count} finding(s) inside chain coverage`}</span>
          </div>
          <div className="mt-0.5 text-[12px] text-muted">Verified by the server at {stamp(v.verified_at)}</div>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-brand/25 bg-brand-50/40 px-4 py-3" data-testid="integrity-coverage">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={ok ? "ok" : "bad"}>{ok ? "VERIFIED" : "FINDINGS"}</Badge>
            <span className="text-[11px] font-medium uppercase tracking-[0.12em] text-brand">Inside integrity coverage · this result applies</span>
          </div>
          <div className="mt-1 text-[13px] text-ink">Events from sequence <span className="mono">#{v.covers_from_seq ?? "—"}</span> onward</div>
          <dl className="mt-2 grid grid-cols-[1fr_auto] gap-x-3 gap-y-1 text-[12.5px]">
            <dt className="text-muted">Chain entries checked</dt><dd className="tabular-nums">{Number(v.entries_checked ?? 0).toLocaleString()}</dd>
            <dt className="text-muted">Chain head</dt><dd className="mono text-[12px]">#{v.head_index ?? "—"}</dd>
            <dt className="text-muted">Per-event MACs</dt><dd>{v.mac_checked ? "checked" : <span className="text-warn">not checked</span>}</dd>
            <dt className="text-muted">Written in the last moments, not yet chained</dt><dd className="tabular-nums">{v.unsealed_within_grace ?? 0}</dd>
          </dl>
        </div>
        <div className="rounded-lg border border-dashed border-line-2 bg-sunken px-4 py-3" data-testid="legacy-coverage">
          <div className="flex items-center gap-2">
            <Badge tone="neutral">OUTSIDE INTEGRITY COVERAGE</Badge>
          </div>
          <div className="mt-1 display text-[26px] leading-none text-ink">{legacy.toLocaleString()}</div>
          <p className="mt-1.5 text-[12.5px] leading-relaxed text-ink-2">
            legacy events written before the chain's genesis (sequence below <span className="mono">#{v.covers_from_seq ?? "—"}</span>).
            They were never chained, so their integrity is <strong>not verified</strong>; the result on the left says nothing about them.
          </p>
        </div>
      </div>

      {findings.length > 0 ? (
        <Notice tone="bad" title={`Integrity violation · ${v.finding_count} finding(s)${v.alert_id ? ` · alert ${v.alert_id} raised` : ""}`}>
          <ul className="mt-1 space-y-1">
            {findings.slice(0, 50).map((f, i) => (
              <li key={i} className="flex flex-wrap items-baseline gap-2 animate-step-in" style={{ animationDelay: `${Math.min(i, 10) * 40}ms` }}>
                <span className="mono text-[12px] font-medium">{f.kind}</span>
                <span className="text-[12px]">{f.detail}</span>
                <span className="mono text-[11px] opacity-80">{f.chain_index != null ? `entry #${f.chain_index}` : ""}{f.event_seq != null ? ` · event seq #${f.event_seq}` : ""}</span>
              </li>
            ))}
          </ul>
          {v.finding_count > findings.length && <p className="mt-1 text-[12px]">Showing the first {findings.length}; see the CRITICAL alert or run scripts/verify_audit_chain.py for all.</p>}
        </Notice>
      ) : <p className="text-[12.5px] text-muted">No findings inside chain coverage.</p>}

      <Disclosure title="Signed checkpoints"
                  meta={`${v.checkpoints_verified ?? 0} verified · last at #${v.last_checkpoint_index ?? "—"} · ${v.entries_after_last_checkpoint ?? 0} entries after it`}
                  testId="integrity-checkpoints">
        <Checkpoints />
      </Disclosure>
      {v.scope_note && <p className="text-[12px] text-muted">{v.scope_note}</p>}
    </div>
  );
}

function Checkpoints() {
  const r = useResource(() => auditIntegrity.checkpoints(15), []);
  if (r.loading && !r.data) return <Skeleton rows={4} />;
  return (
    <Load r={r} rows={4}>{(c) => (
      <div className="space-y-3">
        <div className="text-[12px] text-muted">
          Trusted checkpoint key (from the server's keystore, not the database):{" "}
          {Object.entries((c.trusted_keys ?? {}) as Record<string, string>).map(([kid, key]) => (
            <span key={kid} className="mono break-all text-[11.5px] text-ink-2">{kid} · {key}</span>))}
        </div>
        <Table rows={(c.checkpoints ?? []) as Json[]} rowKey={(cp) => `${cp.chain_index}-${cp.signed_at}`}
               empty="No checkpoints have been signed yet." columns={[
          { key: "i", label: "Entry", render: (cp) => <span className="mono text-[12px]">#{cp.chain_index}</span> },
          { key: "t", label: "Signed", render: (cp) => <span className="text-[12px] text-muted">{stamp(cp.signed_at)}</span> },
          { key: "h", label: "Entry hash", render: (cp) => <span className="mono text-[11.5px] text-ink-2" title={cp.entry_hash}>{String(cp.entry_hash).slice(0, 20)}…</span> },
          { key: "k", label: "Key", render: (cp) => <span className="mono text-[11px] text-muted">{String(cp.kid).split("#").pop()}</span> },
        ]} />
        <p className="text-[12px] text-muted">Record a checkpoint (index and hash) outside this system to detect truncation of the chain together with its checkpoints.</p>
      </div>
    )}</Load>
  );
}

/** The live SSE stream, read with fetch() so the bearer token can be sent.
 *  (EventSource cannot send an Authorization header, which is why the old
 *  console's trace stopped working once Phase 10 made the stream audit_read.) */
function LiveStream() {
  const who = useIdentity()?.subject;
  const [events, setEvents] = useState<Json[]>([]);
  const [state, setState] = useState<"idle" | "live" | "denied" | "error">("idle");
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    const token = currentBearer();
    if (!token) { setState("denied"); return; }
    const ctrl = new AbortController();
    abort.current = ctrl;
    (async () => {
      try {
        const res = await fetch("/api/v1/events/stream?replay=20", { headers: { authorization: `Bearer ${token}` }, signal: ctrl.signal });
        if (res.status === 401 || res.status === 403) { setState("denied"); return; }
        if (!res.ok || !res.body) { setState("error"); return; }
        setState("live");
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const frames = buffer.split("\n\n");
          buffer = frames.pop() ?? "";
          for (const frame of frames) {
            const data = frame.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("");
            if (!data) continue;
            try { const ev = JSON.parse(data); setEvents((prev) => [ev, ...prev].slice(0, 40)); } catch { /* keep-alive */ }
          }
        }
      } catch { if (!ctrl.signal.aborted) setState("error"); }
    })();
    return () => ctrl.abort();
  }, [who]);

  return (
    <Section title="Live event stream" hint="Server-sent events from the audit trail, as they are written."
             actions={<Badge tone={state === "live" ? "ok" : state === "error" ? "bad" : "neutral"}>{state === "live" ? "LIVE" : state.toUpperCase()}</Badge>}>
      {state === "denied" ? <Notice tone="info">Sign in as an auditor or IAM administrator to follow the live stream.</Notice> : events.length ? (
        <ul className="max-h-56 space-y-1 overflow-y-auto text-[12.5px]">
          {events.map((e, i) => (
            <li key={`${e.seq ?? i}-${i}`} className="flex flex-wrap items-center gap-2 animate-rise">
              <span className="mono text-[11px] text-faint">{e.timestamp?.slice(11, 19)}</span>
              <span className="font-medium">{e.event_type}</span>{e.decision && <Badge>{e.decision}</Badge>}<Did value={e.agent_did} />
            </li>
          ))}
        </ul>) : <p className="text-[13px] text-muted">{state === "live" ? "Connected. Waiting for events…" : "Connecting…"}</p>}
    </Section>
  );
}
