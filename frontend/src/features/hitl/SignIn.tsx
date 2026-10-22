import { useEffect, useState } from "react";
import { api, setBearerToken } from "../../api/client";
import {
  beginLogin, clearToken, completeLogin, logout, storedToken,
} from "../../auth/oidc";
import type { HitlConfig, HumanIdentity } from "../../auth/oidc";

/**
 * The human sign-in control.
 *
 * Note what it displays and what it does not. It shows WHO you are and which
 * roles your token carries -- both read back from the server, which validated
 * the token against Keycloak's JWKS. It never says what you are permitted to
 * do, because that is the PDP's answer at the moment you act, not a claim a
 * header can make in advance.
 */
export function SignIn({
  identity, onIdentity,
}: {
  identity: HumanIdentity | null;
  onIdentity: (identity: HumanIdentity | null) => void;
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

        // Returning from Keycloak with a code. There is no session to resume:
        // Phase 5.5 moved the access token in memory, so a reload signs you
        // out. `storedToken()` covers a re-mount within the same page life.
        const token = (await completeLogin(loaded)) ?? storedToken();
        if (!token) return;
        setBearerToken(token);
        try {
          onIdentity(await api.whoami());
        } catch (e) {
          // The token may have expired while the page sat open. Clearing it is
          // the honest response: we are signed out.
          clearToken();
          setBearerToken(null);
          onIdentity(null);
          setError((e as Error).message);
        }
      } catch (e) {
        if (!cancelled) setError((e as Error).message);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [onIdentity]);

  if (!config) {
    return (
      <span className="text-[11px] text-slate-600">
        {error ? `identity provider unavailable` : "…"}
      </span>
    );
  }

  if (!identity) {
    return (
      <div className="flex items-center gap-2">
        {error && (
          <span className="text-[10px] text-rose-300" title={error}>
            sign-in failed
          </span>
        )}
        <button
          onClick={() => beginLogin(config)}
          className="rounded border border-sky-500/40 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-200 hover:bg-sky-500/20"
        >
          Sign in
        </button>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <div className="text-right">
        <div className="text-xs font-medium text-slate-200">
          {identity.display_name ?? identity.username}
        </div>
        <div className="mono text-[10px] text-slate-500">
          {identity.roles.join(" · ") || "no roles"}
        </div>
      </div>
      <button
        onClick={() => {
          setBearerToken(null);
          onIdentity(null);
          logout(config);
        }}
        className="rounded border border-slate-700 px-2.5 py-1.5 text-[11px] text-slate-400 hover:text-slate-200"
      >
        Sign out
      </button>
    </div>
  );
}
