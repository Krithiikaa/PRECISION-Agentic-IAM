import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { Button, Countdown, Field, Json, Panel, StatusPill } from "../../components/ui";
import type { CredentialSummary, VerifiableCredential, VerificationReport } from "../../types";
import { VerificationResult } from "./VerificationFlow";

type Tab = "overview" | "proof" | "json";

/** Human label for a credential type. */
const TYPE_LABELS: Record<string, string> = {
  AgentCapabilityCredential: "Capability",
  ComplianceCredential: "Compliance",
  AgentRoleCredential: "Role",
};

export function CredentialDetail({ summary, onChanged }: {
  summary: CredentialSummary;
  onChanged: () => void;
}) {
  const [document, setDocument] = useState<VerifiableCredential | null>(null);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [tab, setTab] = useState<Tab>("overview");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(summary.seconds_remaining);

  useEffect(() => {
    setReport(null);
    setError(null);
    setTab("overview");
    setRemaining(summary.seconds_remaining);
    api.credential(summary.credential_id)
      .then((body) => setDocument(body.credential))
      .catch((e: Error) => setError(e.message));
  }, [summary.credential_id, summary.seconds_remaining]);

  // Display-only countdown. Expiry is decided by the backend comparing
  // timestamps; this ticker never influences a verification result.
  useEffect(() => {
    if (remaining <= 0) return;
    const timer = setInterval(() => setRemaining((r) => Math.max(0, r - 1)), 1000);
    return () => clearInterval(timer);
  }, [remaining]);

  async function run<T>(action: () => Promise<T>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const verify = () =>
    run(async () => {
      if (!document) return;
      setReport(await api.verify(document, document.credentialSubject.id));
    });

  const tamper = () =>
    run(async () => {
      if (!document) return;
      // Edit a signed claim WITHOUT re-signing, then ask the backend.
      const forged = structuredClone(document);
      forged.credentialSubject.capability = "payroll_access";
      setReport(await api.verify(forged, forged.credentialSubject.id));
    });

  const revoke = () =>
    run(async () => {
      await api.revoke(summary.credential_id, "REVOKED_FROM_CONTROL_CENTER");
      onChanged();
      if (document) setReport(await api.verify(document, document.credentialSubject.id));
    });

  const claims = document
    ? Object.entries(document.credentialSubject).filter(([key]) => key !== "id")
    : [];

  return (
    <Panel
      title={TYPE_LABELS[summary.credential_type] ?? summary.credential_type}
      subtitle={summary.credential_id}
      actions={<StatusPill status={summary.status} />}
    >
      {error && (
        <p className="mb-3 rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
          {error}
        </p>
      )}

      <div className="mb-3 flex flex-wrap gap-2">
        <Button variant="primary" onClick={verify} disabled={busy || !document}>
          Verify
        </Button>
        <Button
          onClick={tamper}
          disabled={busy || !document}
          title="Edits a signed claim without re-signing, then asks the real verifier"
        >
          Simulate tampering
        </Button>
        <Button
          variant="danger"
          onClick={revoke}
          disabled={busy || summary.status !== "ACTIVE"}
        >
          Revoke
        </Button>
        <div className="ml-auto flex gap-1">
          {(["overview", "proof", "json"] as Tab[]).map((name) => (
            <button
              key={name}
              onClick={() => setTab(name)}
              className={`rounded px-2 py-1 text-[11px] uppercase tracking-wide transition ${
                tab === name ? "bg-slate-700/70 text-slate-100" : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {name}
            </button>
          ))}
        </div>
      </div>

      {tab === "overview" && (
        <div className="space-y-4">
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <Field label="Issuer" value={summary.issuer} mono title={summary.issuer} />
            <Field
              label="Subject"
              value={document?.credentialSubject.id ?? "—"}
              mono
              title={document?.credentialSubject.id}
            />
            <Field label="Type" value={summary.credential_type} />
            <Field label="Issued" value={new Date(summary.issued_at).toLocaleTimeString()} />
            <Field label="Expires" value={new Date(summary.expires_at).toLocaleTimeString()} />
            <Field label="Time remaining" value={<Countdown seconds={remaining} />} />
          </dl>

          <div>
            <p className="mb-1.5 text-[10px] uppercase tracking-[0.12em] text-slate-500">
              Attested claims
            </p>
            <div className="space-y-1">
              {claims.map(([key, value]) => (
                <div key={key} className="flex gap-2 text-xs">
                  <span className="mono w-40 shrink-0 text-slate-500">{key}</span>
                  <span className="mono break-all text-slate-200">
                    {Array.isArray(value) ? value.join(", ") : String(value)}
                  </span>
                </div>
              ))}
            </div>
            {document?.type.includes("ComplianceCredential") && (
              <p className="mt-2 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-[10px] text-amber-200">
                DEMO / SYNTHETIC COMPLIANCE CREDENTIAL — this is fabricated POC data and is
                not a real SOX attestation of any kind.
              </p>
            )}
          </div>

          {report && (
            <div className="border-t border-slate-800 pt-3">
              <VerificationResult report={report} />
            </div>
          )}
        </div>
      )}

      {tab === "proof" && document && (
        <div className="space-y-3">
          <dl className="grid grid-cols-2 gap-3">
            <Field label="Proof type" value={document.proof.type} mono />
            <Field label="Cryptosuite" value={document.proof.cryptosuite} mono />
            <Field label="Proof purpose" value={document.proof.proofPurpose} mono />
            <Field label="Created" value={document.proof.created} mono />
          </dl>
          <Field
            label="Verification method (issuer key)"
            value={document.proof.verificationMethod}
            mono
          />
          <div>
            <p className="text-[10px] uppercase tracking-[0.12em] text-slate-500">
              Signature (base64, 64 bytes)
            </p>
            <p className="mono mt-1 break-all rounded border border-slate-800 bg-slate-950/70 p-2 text-[11px] text-slate-300">
              {document.proof.proofValue}
            </p>
          </div>
          <p className="text-[11px] text-slate-500">
            POC note: this is <span className="mono">{document.proof.type}</span> over
            JCS-canonical JSON — not the W3C <span className="mono">Ed25519Signature2020</span>{" "}
            suite, which canonicalises JSON-LD with URDNA2015.
          </p>
          {report && (
            <div className="border-t border-slate-800 pt-3">
              <VerificationResult report={report} />
            </div>
          )}
        </div>
      )}

      {tab === "json" && document && <Json value={document} />}
    </Panel>
  );
}
