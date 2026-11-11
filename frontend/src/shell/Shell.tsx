import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setBearerToken } from "../api/client";
import { beginLogin, clearToken, completeLogin, logout, storedToken } from "../auth/oidc";
import type { HitlConfig, HumanIdentity } from "../auth/oidc";

/* -------------------------------------------------------------- routing */
export type Route =
  | "overview" | "workflow" | "agents" | "identity" | "ans" | "policies" | "jit"
  | "approvals" | "a2a" | "mcp" | "threats" | "audit" | "system";

const GROUPS: { label: string; items: { id: Route; label: string; icon: string }[] }[] = [
  { label: "Operate", items: [
    { id: "overview", label: "Overview", icon: "M3 12l9-8 9 8M5 10v10h14V10" },
    { id: "workflow", label: "Loan workflow", icon: "M4 6h10M4 12h16M4 18h7M17 4l3 2-3 2" },
    { id: "approvals", label: "Human approvals", icon: "M5 12l4 4 10-10" },
  ]},
  { label: "Identity", items: [
    { id: "agents", label: "Agent registry", icon: "M12 12a4 4 0 100-8 4 4 0 000 8zm-7 9a7 7 0 0114 0" },
    { id: "identity", label: "Identity & credentials", icon: "M4 6h16v12H4zM8 10h5M8 14h8" },
    { id: "ans", label: "Naming service", icon: "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18" },
  ]},
  { label: "Access", items: [
    { id: "policies", label: "Policies & decisions", icon: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z" },
    { id: "jit", label: "JIT access", icon: "M12 7v5l3 2M12 3a9 9 0 100 18 9 9 0 000-18z" },
    { id: "a2a", label: "A2A transactions", icon: "M7 7h11l-3-3M17 17H6l3 3" },
    { id: "mcp", label: "MCP security", icon: "M9 3v4M15 3v4M7 7h10v5a5 5 0 01-10 0zM12 17v4" },
  ]},
  { label: "Assure", items: [
    { id: "threats", label: "Threat monitoring", icon: "M12 3l9 16H3zM12 10v4M12 17h.01" },
    { id: "audit", label: "Audit & compliance", icon: "M7 3h8l4 4v14H7zM10 12h6M10 16h6" },
    { id: "system", label: "System & integrations", icon: "M4 6h16M4 12h16M4 18h16M7 6v0M7 12v0M7 18v0" },
  ]},
];

export function useRoute(): [Route, (r: Route) => void] {
  const read = () => (window.location.hash.replace(/^#\/?/, "").split("?")[0] || "overview") as Route;
  const [route, setRoute] = useState<Route>(read);
  useEffect(() => {
    const on = () => setRoute(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return [route, (r) => { window.location.hash = `/${r}`; }];
}

/* ------------------------------------------------------------- identity */
const IdentityContext = createContext<HumanIdentity | null>(null);
export const useIdentity = () => useContext(IdentityContext);

function Icon({ d }: { d: string }) {
  return (
    <svg viewBox="0 0 24 24" className="h-[17px] w-[17px] shrink-0" fill="none" stroke="currentColor"
         strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

function Mark() {
  return (
    <div className="flex items-center gap-2.5">
      <svg viewBox="0 0 28 28" className="h-7 w-7" aria-hidden="true">
        <rect width="28" height="28" rx="7" fill="#0d5537" />
        <path d="M9 20V8h6a4 4 0 010 8H9" fill="none" stroke="#ecf5ef" strokeWidth="2.2" strokeLinecap="round" />
        <circle cx="19.5" cy="19.5" r="1.8" fill="#9fd1b3" />
      </svg>
      <div className="leading-tight">
        <div className="text-[13px] font-semibold tracking-[0.2em] text-ink">PRECISION</div>
        <div className="text-[10.5px] text-muted">Agentic IAM · Operations</div>
      </div>
    </div>
  );
}

function SignIn({ identity, onIdentity }: {
  identity: HumanIdentity | null; onIdentity: (i: HumanIdentity | null) => void;
}) {
  const [config, setConfig] = useState<HitlConfig | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const loaded = await api.hitlConfig();
        if (cancelled) return;
        setConfig(loaded);
        const token = (await completeLogin(loaded)) ?? storedToken();
        if (!token) return;
        setBearerToken(token);
        try { onIdentity(await api.whoami()); }
        catch (e) { clearToken(); setBearerToken(null); onIdentity(null); setError((e as Error).message); }
      } catch (e) { if (!cancelled) setError((e as Error).message); }
    })();
    return () => { cancelled = true; };
  }, [onIdentity]);

  if (!config) {
    return <span className="text-[12px] text-muted">{error ? "Identity provider unavailable" : "Connecting…"}</span>;
  }
  if (!identity) {
    return (
      <div className="flex items-center gap-3">
        {error && <span className="text-[11px] text-bad" title={error}>Sign-in failed</span>}
        <button onClick={() => beginLogin(config)}
                className="rounded-lg bg-brand px-3.5 py-1.5 text-[13px] font-medium text-white transition hover:bg-brand-700">
          Sign in with Keycloak →
        </button>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-3">
      <div className="text-right leading-tight">
        <div className="text-[13px] font-medium text-ink">{identity.display_name ?? identity.username}</div>
        <div className="text-[11px] text-muted">
          {identity.roles.filter((r) => /^[A-Z_]+$/.test(r)).join(" · ") || "no roles"}
        </div>
      </div>
      <button onClick={() => { setBearerToken(null); onIdentity(null); logout(config); }}
              className="rounded-lg border border-line-2 px-2.5 py-1.5 text-[12px] text-muted transition hover:border-brand hover:text-brand">
        Sign out
      </button>
    </div>
  );
}

export function Shell({ route, go, children }: { route: Route; go: (r: Route) => void; children: ReactNode }) {
  const [identity, setIdentity] = useState<HumanIdentity | null>(null);
  const [open, setOpen] = useState(false);
  const current = GROUPS.flatMap((g) => g.items).find((i) => i.id === route);

  const nav = (
    <nav className="space-y-6" aria-label="Primary">
      {GROUPS.map((group) => (
        <div key={group.label}>
          <div className="mb-2 px-3 text-[10.5px] font-medium uppercase tracking-[0.18em] text-faint">{group.label}</div>
          <ul className="space-y-0.5">
            {group.items.map((item) => {
              const active = item.id === route;
              return (
                <li key={item.id}>
                  <button onClick={() => { go(item.id); setOpen(false); }}
                          aria-current={active ? "page" : undefined}
                          className={`group flex w-full items-center gap-2.5 rounded-lg px-3 py-[7px] text-[13px] transition ${
                            active ? "bg-brand-50 font-medium text-brand" : "text-ink-2 hover:bg-sunken hover:text-ink"}`}>
                    <Icon d={item.icon} />
                    {item.label}
                    {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-brand" />}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );

  return (
    <IdentityContext.Provider value={identity}>
      <div className="min-h-screen lg:grid lg:grid-cols-[248px_1fr]">
        <aside className="sticky top-0 hidden h-screen flex-col border-r border-line bg-surface/70 px-3 py-5 backdrop-blur lg:flex">
          <div className="mb-7 px-3"><Mark /></div>
          <div className="flex-1 overflow-y-auto">{nav}</div>
          <p className="mt-4 px-3 text-[10.5px] leading-relaxed text-faint">
            Every figure is read from the live IAM API. External banking systems are simulated adapters.
          </p>
        </aside>

        {open && (
          <div className="fixed inset-0 z-40 bg-ink/20 lg:hidden" onClick={() => setOpen(false)}>
            <aside className="h-full w-72 overflow-y-auto bg-surface px-3 py-5 shadow-lift" onClick={(e) => e.stopPropagation()}>
              <div className="mb-6 px-3"><Mark /></div>{nav}
            </aside>
          </div>
        )}

        <div className="min-w-0">
          <header className="sticky top-0 z-30 flex items-center justify-between gap-3 border-b border-line bg-canvas/85 px-4 py-3 backdrop-blur md:px-8">
            <div className="flex items-center gap-3">
              <button className="rounded-lg border border-line-2 p-1.5 lg:hidden" onClick={() => setOpen(true)} aria-label="Open navigation">
                <Icon d="M4 6h16M4 12h16M4 18h16" />
              </button>
              <div className="lg:hidden"><Mark /></div>
              <div className="hidden text-[12px] text-muted lg:block">
                Console <span className="mx-1.5 text-faint">/</span>
                <span className="text-ink">{current?.label}</span>
              </div>
            </div>
            <SignIn identity={identity} onIdentity={setIdentity} />
          </header>
          <main className="mx-auto max-w-[1280px] px-4 py-7 md:px-8 md:py-9">{children}</main>
        </div>
      </div>
    </IdentityContext.Provider>
  );
}
