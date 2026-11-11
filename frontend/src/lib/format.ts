export function ago(iso?: string | null): string {
  if (!iso) return "—";
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return "—";
  const future = seconds < 0;
  const s = Math.abs(seconds);
  const v = s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m` : s < 86400
    ? `${Math.floor(s / 3600)}h` : `${Math.floor(s / 86400)}d`;
  return future ? `in ${v}` : `${v} ago`;
}

export function stamp(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit",
                                       minute: "2-digit", second: "2-digit" });
}

/** did:poc:agent:risk-001 -> risk-001 ; leaves non-DIDs alone. */
export function shortDid(did?: string | null): string {
  if (!did) return "—";
  const parts = did.split(":");
  return parts.length > 3 ? parts.slice(3).join(":") : did;
}

export function inr(amount?: number | null): string {
  if (amount == null) return "—";
  return "₹" + amount.toLocaleString("en-IN");
}

export function sum(obj?: Record<string, number> | null): number {
  return obj ? Object.values(obj).reduce((a, b) => a + b, 0) : 0;
}

export function downloadJson(name: string, value: unknown): void {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadCsv(name: string, rows: Record<string, unknown>[]): void {
  if (!rows.length) return;
  const cols = Array.from(new Set(rows.flatMap((r) => Object.keys(r))));
  const cell = (v: unknown) => {
    const s = v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}
