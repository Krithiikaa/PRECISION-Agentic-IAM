# Frontend — Agentic Banking Control Center

A React + TypeScript + Tailwind console over the real backend. It is an
observability layer, never a source of truth: every value it shows came from an
API response or the event stream.

## What exists

- **Discovery** (Phase 3) — query the Agent Naming Service by capability and
  required credential. Every candidate, matched or filtered, shows the checks
  the backend ran and their reasons. "Ask coordinator" hands the job to the
  coordinator agent, which resolves the capability with its LLM and
  cross-checks the result against the identity authority.
- **Credentials** — trust roots, every credential with its live status, and a
  detail panel with claims, proof and raw JSON. `Verify` calls the real
  verifier and renders its eight checks with the backend's own reasons.
  `Simulate tampering` edits a signed claim without re-signing and shows the
  resulting `SIGNATURE_INVALID`. `Revoke` changes backend state.
- **Agents** — DID, key custody, capabilities, credentials held, and
  `Present & verify`, which asks the **agent process** for a holder-signed
  presentation and has the IAM API verify it.
- **Model** — what DID, credential, PDP and AEM each answer, and which of them
  exist yet.
- **Live trace** — `GET /api/v1/events/stream`, the real backend event bus.

## What does not exist yet

The loan application, the live agent topology graph, the Identity Lab screen,
the authorization explainer, the JIT countdown and the security-operations
views. Those belong to Phase 12 and to the phases whose backends do not exist.

## Rules this app follows

- It never synthesises an event. If the backend is idle, the trace is empty.
- It performs no cryptography. Every verdict shown is the backend's.
- Countdowns are display only; expiry is decided by the backend comparing
  timestamps.
- It never receives a private key, because no endpoint can return one.

## Run

```bash
npm install
npm run dev        # http://localhost:5173, proxies /api to localhost:8000
```

Set `VITE_API_TARGET` to point the proxy elsewhere (docker-compose sets it to
`http://iam-api:8000`).
