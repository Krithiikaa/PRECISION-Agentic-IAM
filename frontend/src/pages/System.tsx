import { http, type Json } from "../api/client";
import { Badge, Load, LiveDot, Notice, PageHeader, Section, Updated } from "../components/ds";
import { stamp } from "../lib/format";
import { useResource } from "../lib/useResource";
import { useIdentity } from "../shell/Shell";

export function System() {
  const who = useIdentity()?.subject;
  const r = useResource(() => http<Json>("/api/v1/console/health"), [who], 15_000);
  return (
    <>
      <PageHeader index="12" eyebrow="System & integrations" title="Connected means" emphasis="probed just now."
                  actions={<Updated at={r.updatedAt} onRefresh={r.reload} />}>
        Each dependency is checked by the API on every request to this page: a query, a ping, an HTTP call. A service
        is shown as up only when that probe succeeded; failures show the error, not a reassuring default.
      </PageHeader>
      <Load r={r} rows={8}>{(h) => (
        <div className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {(h.services as Json[]).map((s) => (
              <div key={s.service} className="rounded-xl border border-line bg-surface p-5 shadow-card transition hover:shadow-lift animate-rise">
                <div className="flex items-center gap-2.5">
                  <LiveDot up={s.up} />
                  <h3 className="text-[14px] font-semibold text-ink">{s.service}</h3>
                  <span className="ml-auto"><Badge tone={s.up ? "ok" : "bad"}>{s.up ? "UP" : "DOWN"}</Badge></span>
                </div>
                <p className="mt-3 text-[12.5px] text-ink-2">{s.detail ?? s.error ?? "—"}</p>
                {s.error && s.detail && <p className="mt-1 text-[12px] text-bad">{s.error}</p>}
                <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11.5px] text-muted">
                  <span className="mono">{s.latency_ms} ms</span>
                  {s.url && <span className="mono">{s.url}</span>}
                  {s.issuer && <span className="mono">{s.issuer}</span>}
                  {s.model && <span>{s.model}</span>}
                  {s.resource_uri && <span className="mono">{s.resource_uri}</span>}
                  {s.active_sessions != null && <span>{s.active_sessions} active sessions</span>}
                  {s.by_status && <span>{Object.entries(s.by_status as Record<string, number>).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(" · ")}</span>}
                </div>
              </div>
            ))}
          </div>
          <Section title="Not deployed" hint="Stated, not hidden.">
            <ul className="list-disc space-y-1 pl-5 text-[13px] text-ink-2">
              {(h.not_present as string[]).map((x) => <li key={x}>{x}</li>)}
              <li>External banking systems (core banking, credit bureau, KYC provider, fraud service, document store): SIMULATED adapters, labelled on every record.</li>
            </ul>
          </Section>
          <Notice tone="info">Checked at {stamp(h.checked_at)}.</Notice>
        </div>
      )}</Load>
    </>
  );
}
