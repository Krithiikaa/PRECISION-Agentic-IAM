import { useState, type ReactNode } from "react";
import { ApiError } from "../api/client";
import type { ResourceState } from "../lib/useResource";

/* ------------------------------------------------------------------ page */
export function PageHeader({ index, eyebrow, title, emphasis, children, actions }: {
  index: string; eyebrow: string; title: string; emphasis?: string;
  children?: ReactNode; actions?: ReactNode;
}) {
  return (
    <header className="mb-7 flex flex-col gap-4 border-b border-line pb-6 md:flex-row md:items-end md:justify-between animate-rise">
      <div className="max-w-3xl">
        <div className="mb-2 flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.16em] text-muted">
          <span className="mono text-brand">{index}</span>
          <span className="h-px w-6 bg-line-2" />
          {eyebrow}
        </div>
        <h1 className="display text-[34px] leading-[1.05] text-ink md:text-[42px]">
          {title}{emphasis && <> <em className="text-brand">{emphasis}</em></>}
        </h1>
        {children && <p className="mt-3 max-w-2xl text-[13.5px] leading-relaxed text-muted">{children}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
    </header>
  );
}

export function Section({ title, hint, actions, children, className = "" }: {
  title: string; hint?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`min-w-0 rounded-xl border border-line bg-surface shadow-card animate-rise ${className}`}>
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-3.5">
        <div>
          <h2 className="text-[13px] font-semibold text-ink">{title}</h2>
          {hint && <p className="mt-0.5 text-[12px] text-muted">{hint}</p>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

export function Stat({ label, value, sub, tone = "neutral" }: {
  label: string; value: ReactNode; sub?: ReactNode; tone?: Tone;
}) {
  const accent = { ok: "bg-ok", warn: "bg-warn", bad: "bg-bad", info: "bg-info", neutral: "bg-line-2", brand: "bg-brand" }[tone];
  return (
    <div className="relative overflow-hidden rounded-xl border border-line bg-surface px-5 py-4 shadow-card transition hover:shadow-lift animate-rise">
      <span className={`absolute left-0 top-4 h-6 w-[3px] rounded-r ${accent}`} />
      <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-muted">{label}</div>
      <div className="display mt-1.5 text-[34px] leading-none text-ink">{value}</div>
      {sub && <div className="mt-2 text-[12px] text-muted">{sub}</div>}
    </div>
  );
}

/* ---------------------------------------------------------------- status */
export type Tone = "ok" | "warn" | "bad" | "info" | "neutral" | "brand";

const TONES: Record<Tone, string> = {
  ok: "bg-ok-bg text-ok border-ok/20",
  warn: "bg-warn-bg text-warn border-warn/20",
  bad: "bg-bad-bg text-bad border-bad/20",
  info: "bg-info-bg text-info border-info/20",
  neutral: "bg-sunken text-ink-2 border-line",
  brand: "bg-brand-50 text-brand border-brand/20",
};

const STATUS_TONE: Record<string, Tone> = {
  ACTIVE: "ok", ALLOW: "ok", APPROVED: "ok", VALID: "ok", EXECUTED: "ok", TRUSTED: "ok",
  SUCCEEDED: "ok", UP: "ok", CONSUMED: "info", COMPLETED: "ok", ACCEPTED: "ok",
  DENY: "bad", REVOKED: "bad", REJECTED: "bad", INVALID: "bad", FAILED: "bad", UNTRUSTED: "bad",
  TERMINATED: "neutral", CONTAINED: "bad", CRITICAL: "bad", HIGH: "bad", DOWN: "bad",
  TERMINATED_IMMEDIATE_SECURITY_LOCKOUT: "bad", DECLINED: "bad", REFUSED: "bad",
  HUMAN_APPROVAL_REQUIRED: "warn", PENDING: "warn", PENDING_APPROVAL: "warn",
  AWAITING_APPROVAL: "warn", SUSPENDED: "warn", EXPIRED: "warn", REDUCED: "warn",
  REDUCED_TRUST: "warn", MEDIUM: "warn", STALE: "warn", DEGRADED: "warn", EXHAUSTED: "neutral",
  IN_PROGRESS: "info", SUBMITTED: "info", RECEIVED: "info", AWAITING_EXECUTION: "info",
  OFFLINE: "neutral", LOW: "info", REINSTATED: "ok", RESOLVED: "neutral", OPEN: "warn",
  CANCELLED: "neutral", PROVISIONING: "info",
};

export function Badge({ children, tone }: { children: ReactNode; tone?: Tone }) {
  const t = tone ?? STATUS_TONE[String(children)] ?? "neutral";
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-[1px] text-[11px] font-medium ${TONES[t]}`}>
      {children}
    </span>
  );
}

export function LiveDot({ up }: { up: boolean }) {
  return (
    <span className={`inline-block h-2 w-2 rounded-full ${up ? "bg-ok animate-pulse-dot" : "bg-bad"}`}
          aria-label={up ? "up" : "down"} />
  );
}

/* ------------------------------------------------------------- identity */
export function Did({ value, full = false }: { value?: string | null; full?: boolean }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="text-faint">—</span>;
  const shown = full ? value : value.replace(/^did:poc:(agent|organization|administrator|service):/, "");
  return (
    <button
      type="button"
      title={`${value} (click to copy)`}
      onClick={() => { navigator.clipboard?.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
      className="mono max-w-full truncate rounded px-1 text-left text-[12px] text-ink-2 hover:bg-brand-50 hover:text-brand"
    >
      {copied ? "copied" : shown}
    </button>
  );
}

export function Kv({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-2 text-[13px]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 break-words text-ink">{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

/* ---------------------------------------------------------------- table */
export type Column<T> = { key: string; label: string; render: (row: T) => ReactNode; className?: string };

export function Table<T>({ rows, columns, rowKey, empty = "Nothing to show.", onRow }: {
  rows: T[]; columns: Column<T>[]; rowKey: (row: T) => string; empty?: string;
  onRow?: (row: T) => void;
}) {
  if (!rows.length) return <Empty>{empty}</Empty>;
  return (
    <div className="-mx-5 overflow-x-auto">
      <table className="w-full min-w-[640px] border-collapse text-[13px]">
        <thead>
          <tr className="border-b border-line text-left text-[11px] uppercase tracking-[0.1em] text-muted">
            {columns.map((c) => <th key={c.key} className={`px-5 pb-2 font-medium ${c.className ?? ""}`}>{c.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)} onClick={onRow ? () => onRow(row) : undefined}
                className={`border-b border-line/70 align-top transition last:border-0 ${onRow ? "cursor-pointer hover:bg-brand-50/50" : "hover:bg-sunken/60"}`}>
              {columns.map((c) => <td key={c.key} className={`px-5 py-2.5 ${c.className ?? ""}`}>{c.render(row)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* --------------------------------------------------------------- inputs */
export function Button({ children, onClick, variant = "secondary", disabled, type = "button", title }: {
  children: ReactNode; onClick?: () => void; variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean; type?: "button" | "submit"; title?: string;
}) {
  const v = {
    primary: "bg-brand text-white hover:bg-brand-700 border-brand",
    secondary: "bg-surface text-ink border-line-2 hover:border-brand hover:text-brand",
    danger: "bg-bad text-white border-bad hover:brightness-95",
    ghost: "border-transparent text-muted hover:text-brand",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled} title={title}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3.5 py-1.5 text-[13px] font-medium transition hover:shadow-card active:translate-y-px active:shadow-none disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:shadow-none ${v}`}>
      {children}
    </button>
  );
}

const fieldCls = "w-full rounded-lg border border-line-2 bg-surface px-3 py-2 text-[13px] text-ink placeholder:text-faint focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand-100";

export function Input(props: React.InputHTMLAttributes<HTMLInputElement> & { label?: string }) {
  const { label, ...rest } = props;
  return (
    <label className="block text-[12px] font-medium text-ink-2">
      {label && <span className="mb-1 block">{label}</span>}
      <input {...rest} className={fieldCls} />
    </label>
  );
}

export function Select({ label, value, onChange, children }: {
  label?: string; value: string; onChange: (v: string) => void; children: ReactNode;
}) {
  return (
    <label className="block text-[12px] font-medium text-ink-2">
      {label && <span className="mb-1 block">{label}</span>}
      <select value={value} onChange={(e) => onChange(e.target.value)} className={fieldCls}>{children}</select>
    </label>
  );
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label?: string }) {
  const { label, ...rest } = props;
  return (
    <label className="block text-[12px] font-medium text-ink-2">
      {label && <span className="mb-1 block">{label}</span>}
      <textarea {...rest} className={`${fieldCls} min-h-[72px]`} />
    </label>
  );
}

export function Segmented<V extends string>({ value, options, onChange }: {
  value: V; options: { value: V; label: string }[]; onChange: (v: V) => void;
}) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-sunken p-0.5 text-[12px]">
      {options.map((o) => (
        <button key={o.value} onClick={() => onChange(o.value)}
                className={`rounded-md px-3 py-1 transition ${value === o.value ? "bg-surface text-ink shadow-card" : "text-muted hover:text-ink"}`}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

/* --------------------------------------------------------------- states */
export function Empty({ children }: { children: ReactNode }) {
  return <p className="rounded-lg border border-dashed border-line-2 px-4 py-6 text-center text-[13px] text-muted">{children}</p>;
}

export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2.5" aria-busy="true">
      {Array.from({ length: rows }).map((_, i) => <div key={i} className="skeleton h-5" style={{ width: `${92 - i * 9}%` }} />)}
    </div>
  );
}

export function Notice({ tone = "info", title, children }: { tone?: Tone; title?: string; children: ReactNode }) {
  return (
    <div className={`rounded-lg border px-4 py-3 text-[13px] ${TONES[tone]}`}>
      {title && <div className="font-semibold">{title}</div>}
      <div className={title ? "mt-0.5 opacity-90" : ""}>{children}</div>
    </div>
  );
}

export function Denied({ status }: { status: 401 | 403 }) {
  return status === 401 ? (
    <Notice tone="info" title="Sign in required">
      This view reads protected data. Sign in with Keycloak (top right); the server decides what your role may see.
    </Notice>
  ) : (
    <Notice tone="warn" title="Your role may not read this">
      The server refused the request for your role. Access is decided by policy on the server, never by the console.
    </Notice>
  );
}

/** Render a resource's loading / denied / error / data states uniformly. */
export function Load<T>({ r, children, rows = 3 }: {
  r: ResourceState<T>; children: (data: T) => ReactNode; rows?: number;
}) {
  if (r.denied) return <Denied status={r.denied} />;
  if (r.loading && !r.data) return <Skeleton rows={rows} />;
  if (r.error && !r.data) {
    const status = r.error instanceof ApiError ? r.error.status : null;
    return (
      <Notice tone="bad" title={status ? `Request failed (HTTP ${status})` : "Service unreachable"}>
        {(r.error as ApiError).detail ?? r.error.message}
        <div className="mt-2"><Button variant="secondary" onClick={r.reload}>Retry</Button></div>
      </Notice>
    );
  }
  return <>{r.data != null && children(r.data)}</>;
}

export function JsonBlock({ value }: { value: unknown }) {
  return (
    <pre className="mono max-h-80 overflow-auto rounded-lg border border-line bg-sunken p-3 text-[11.5px] leading-relaxed text-ink-2">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Updated({ at, onRefresh }: { at: Date | null; onRefresh: () => void }) {
  return (
    <button onClick={onRefresh} className="text-[11.5px] text-muted hover:text-brand" title="Refresh now">
      {at ? `Updated ${at.toLocaleTimeString()}` : "Loading…"} ↻
    </button>
  );
}

/* ------------------------------------------------------------ Phase 12 */
/** An expandable panel. Content is mounted only once opened, so a closed
 *  panel never fetches; the height animates through CSS grid rows. */
export function Disclosure({ title, meta, children, defaultOpen = false, onOpen, testId }: {
  title: ReactNode; meta?: ReactNode; children: ReactNode; defaultOpen?: boolean;
  onOpen?: () => void; testId?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [mounted, setMounted] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-line" data-testid={testId}>
      <button type="button" aria-expanded={open}
              onClick={() => { const next = !open; setOpen(next); if (next) { setMounted(true); onOpen?.(); } }}
              className="flex w-full items-center gap-2 rounded-lg px-4 py-2.5 text-left text-[13px] font-medium text-ink transition hover:bg-brand-50/50">
        <span className="disclosure-chevron inline-block text-brand" aria-hidden>›</span>
        <span className="min-w-0 flex-1">{title}</span>
        {meta && <span className="shrink-0 text-[12px] font-normal text-muted">{meta}</span>}
      </button>
      <div className="disclosure-body" data-open={open}>
        <div><div className="border-t border-line px-4 py-3">{mounted ? children : null}</div></div>
      </div>
    </div>
  );
}

/** A server-reported list of checks: each one passed or failed, as returned. */
export function CheckList({ checks }: { checks: { check: string; passed: boolean; detail?: string }[] }) {
  return (
    <ul className="space-y-1.5 text-[12.5px]">
      {checks.map((c, i) => (
        <li key={c.check} className="flex flex-wrap items-baseline gap-2 animate-step-in" style={{ animationDelay: `${i * 60}ms` }}>
          <Badge tone={c.passed ? "ok" : "bad"}>{c.passed ? "PASSED" : "FAILED"}</Badge>
          <span className="mono text-[12px] text-ink">{c.check}</span>
          {c.detail && <span className="text-muted">{c.detail}</span>}
        </li>
      ))}
    </ul>
  );
}
