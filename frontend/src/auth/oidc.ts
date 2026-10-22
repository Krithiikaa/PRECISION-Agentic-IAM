/**
 * OIDC login against the real Keycloak: Authorization Code + PKCE (S256).
 *
 * WHY PKCE AND NOT A CLIENT SECRET. The console is a browser application, so
 * anything it holds is public. A confidential client would mean shipping a
 * secret to every visitor and calling it confidential. PKCE binds the
 * authorization code to THIS browser's one-time verifier instead, so an
 * intercepted code is useless to anyone else.
 *
 * WHAT THIS FILE DOES NOT DO, deliberately:
 *
 *   * it does not decide anything. The token says who you are; every
 *     permission question is answered by the PDP at the point of action. The
 *     roles read here drive what the UI OFFERS, never what the server permits.
 *   * it does not mint a session. Server-side sessions are Phase 9's concern,
 *     and inventing one here would collide with it.
 *
 * TOKEN STORAGE (reviewed in Phase 5.5; see docs/HITL_SECURITY_MODEL.md).
 *
 * The access token is held in a MODULE-SCOPED VARIABLE. It is never written to
 * sessionStorage, never to localStorage, and never to a cookie this script can
 * read. Phase 5 kept it in sessionStorage; that was honestly labelled but
 * strictly worse, because a token at rest in web storage survives navigation
 * and can be read by any script that reaches the origin at any point in the
 * tab's life, not only while the page is running.
 *
 * WHAT THIS DOES BUY:
 *   - the token is gone on reload, on navigation away, and on tab close
 *   - it is not readable by a script that arrives after the fact, and there is
 *     no persisted copy to scrape from a shared or forensically imaged machine
 *   - no other tab, and no other page on the origin, can reach it
 *
 * WHAT IT DOES NOT BUY, stated plainly because overclaiming here is worse than
 * the gap itself:
 *   - IT IS NOT XSS PROTECTION. Script running in this page can read the
 *     variable, or simply call the API with the browser's ambient state. No
 *     browser-side storage choice fixes that. Only a backend-for-frontend
 *     holding the token server-side and issuing an httpOnly cookie does, and
 *     that means server-side sessions -- which is Phase 9's Session Authority.
 *     Building a second one here would collide with it.
 *
 * THE COST, accepted deliberately: a page refresh signs you out. For a console
 * whose only privileged action is approving a loan, being asked to
 * re-authenticate after a reload is the right side of that trade.
 *
 * localStorage was NOT considered as an alternative. It is strictly worse than
 * what Phase 5 had: it persists across tabs and across browser restarts.
 *
 * THE PKCE VERIFIER AND STATE still use sessionStorage, and must. They have to
 * survive a full-page navigation to Keycloak and back, which is exactly what an
 * in-memory value cannot do. They are single-use, short-lived, useless without
 * the matching authorization code, and are deleted the moment the callback is
 * handled -- and `state` is what makes the callback CSRF-resistant, so storing
 * it is the security measure, not a compromise of one.
 */

const STORAGE_VERIFIER = "agentic-iam.pkce_verifier";
const STORAGE_STATE = "agentic-iam.oidc_state";

// The access token. In memory only -- see the note above. Deliberately not
// exported: callers go through `storedToken()` / `clearToken()`.
let accessToken: string | null = null;

export type HitlConfig = {
  issuer: string;
  realm: string;
  client_id: string;
  audience: string;
  authorization_endpoint: string;
  token_endpoint: string;
  end_session_endpoint: string;
  roles: Record<string, string>;
};

export type HumanIdentity = {
  subject: string;
  issuer: string;
  username: string | null;
  display_name: string | null;
  roles: string[];
  provider: string;
  principal: string;
  status: string;
};

function base64url(buffer: ArrayBuffer | Uint8Array): string {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  view.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomString(bytes = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return base64url(buffer);
}

async function challengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return base64url(digest);
}

export function storedToken(): string | null {
  return accessToken;
}

export function clearToken(): void {
  accessToken = null;
}

/** Send the browser to Keycloak. The page navigates away. */
export async function beginLogin(config: HitlConfig): Promise<void> {
  const verifier = randomString();
  const state = randomString(16);
  sessionStorage.setItem(STORAGE_VERIFIER, verifier);
  sessionStorage.setItem(STORAGE_STATE, state);

  const params = new URLSearchParams({
    client_id: config.client_id,
    response_type: "code",
    scope: "openid profile email",
    redirect_uri: window.location.origin + window.location.pathname,
    state,
    code_challenge: await challengeFor(verifier),
    code_challenge_method: "S256",
  });
  window.location.assign(`${config.authorization_endpoint}?${params}`);
}

/**
 * Complete the login if we came back from Keycloak with a code.
 *
 * `state` is compared BEFORE the code is exchanged: a callback whose state
 * does not match the one this browser generated did not come from a login this
 * browser started, and exchanging its code would be CSRF.
 */
export async function completeLogin(config: HitlConfig): Promise<string | null> {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code) return null;

  const expected = sessionStorage.getItem(STORAGE_STATE);
  const verifier = sessionStorage.getItem(STORAGE_VERIFIER);
  sessionStorage.removeItem(STORAGE_STATE);
  sessionStorage.removeItem(STORAGE_VERIFIER);
  // Clear the code from the address bar either way, so a refresh cannot replay
  // it and it does not linger in browser history.
  window.history.replaceState({}, "", url.pathname);

  if (!expected || state !== expected || !verifier) {
    throw new Error(
      "The login response did not match this browser's request. Not exchanging the code.",
    );
  }

  const response = await fetch(config.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.client_id,
      code,
      redirect_uri: window.location.origin + url.pathname,
      code_verifier: verifier,
    }),
  });
  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status}`);
  }
  const body = await response.json();
  // In memory, and nowhere else. Note also what is NOT kept: the response may
  // carry a refresh token, and this deliberately does not read it. A refresh
  // token is a longer-lived credential than the one it renews, and holding one
  // in a browser would make the storage question strictly worse than it needs
  // to be for a console that re-authenticates on reload anyway.
  accessToken = body.access_token as string;
  return accessToken;
}

export function logout(config: HitlConfig): void {
  clearToken();
  const params = new URLSearchParams({
    client_id: config.client_id,
    post_logout_redirect_uri: window.location.origin + window.location.pathname,
  });
  window.location.assign(`${config.end_session_endpoint}?${params}`);
}
