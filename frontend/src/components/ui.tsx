import type { ReactNode } from "react";

export function Panel({ title, subtitle, actions, children, className = "" }: {
  title?: string; subtitle?: string; actions?: ReactNode;
  children: ReactNode; className?: string;
}) {
  return (
    <section className={`rounded-lg border border-slate-800 bg-slate-900/40 ${className}`}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-slate-800 px-4 py-3">
          <div>
            {title && (
              <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">
                {title}
              </h2>
            )}
            {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

const STATUS_STYLES: Record<string, string> = {
  ACTIVE: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  VALID: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  REVOKED: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  INVALID: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  EXPIRED: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  SUSPENDED: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  TERMINATED: "bg-slate-600/20 text-slate-400 border-slate-600/40",
  UNKNOWN: "bg-slate-600/20 text-slate-400 border-slate-600/40",
};

export function StatusPill({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? "bg-slate-600/20 text-slate-300 border-slate-600/40";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium ${style}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}

export function Button({ children, onClick, variant = "default", disabled, title }: {
  children: ReactNode; onClick?: () => void;
  variant?: "default" | "danger" | "primary"; disabled?: boolean; title?: string;
}) {
  const styles = {
    default: "border-slate-700 bg-slate-800/60 text-slate-200 hover:bg-slate-700/60",
    primary: "border-sky-600/50 bg-sky-600/20 text-sky-200 hover:bg-sky-600/30",
    danger: "border-rose-600/50 bg-rose-600/15 text-rose-200 hover:bg-rose-600/25",
  }[variant];
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`rounded border px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide
        transition disabled:cursor-not-allowed disabled:opacity-40 ${styles}`}
    >
      {children}
    </button>
  );
}

export function Field({ label, value, mono = false, title }: {
  label: string; value: ReactNode; mono?: boolean; title?: string;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-[0.12em] text-slate-500">{label}</dt>
      <dd
        title={title}
        className={`mt-0.5 truncate text-xs text-slate-200 ${mono ? "mono" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-xs text-slate-500">{children}</p>;
}

export function Json({ value }: { value: unknown }) {
  return (
    <pre className="mono max-h-96 overflow-auto rounded border border-slate-800 bg-slate-950/70 p-3 text-[11px] leading-relaxed text-slate-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function Countdown({ seconds }: { seconds: number }) {
  const mm = String(Math.floor(Math.max(0, seconds) / 60)).padStart(2, "0");
  const ss = String(Math.max(0, seconds) % 60).padStart(2, "0");
  const tone = seconds <= 0 ? "text-rose-300"
    : seconds < 30 ? "text-amber-300" : "text-slate-300";
  return <span className={`mono ${tone}`}>{mm}:{ss}</span>;
}
