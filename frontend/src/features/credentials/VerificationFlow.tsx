import type { CheckDetail, VerificationReport } from "../../types";

/**
 * Renders the verifier's answer, step by step.
 *
 * Every row here is a check the BACKEND actually ran, with the backend's own
 * detail string. The UI performs no verification of its own and has no
 * cryptography in it -- it could not fake a pass if it wanted to.
 */

const STEP_LABELS: Record<string, string> = {
  structure: "Credential structure",
  issuer: "Resolve issuer DID → public key",
  signature: "Verify Ed25519 issuer proof",
  subject: "Check subject binding",
  not_before: "Check issuance date",
  expiration: "Check expiry",
  status: "Check revocation status",
  claims: "Check required claims",
  holder: "Resolve holder DID",
  holder_proof: "Verify Ed25519 holder proof",
  challenge: "Check challenge",
  credentials: "Verify contained credentials",
};

export function CheckList({ checks }: { checks: CheckDetail[] }) {
  return (
    <ol className="space-y-1.5">
      {checks.map((check, index) => (
        <li key={check.name} className="flex items-start gap-2.5">
          <span className="mono mt-0.5 w-4 shrink-0 text-right text-[10px] text-slate-600">
            {index + 1}
          </span>
          <span
            className={`mt-0.5 shrink-0 text-xs ${check.passed ? "text-emerald-400" : "text-rose-400"}`}
            aria-hidden
          >
            {check.passed ? "✓" : "✕"}
          </span>
          <div className="min-w-0 flex-1">
            <p className={`text-xs ${check.passed ? "text-slate-300" : "text-rose-200"}`}>
              {STEP_LABELS[check.name] ?? check.name}
            </p>
            <p className="mono mt-0.5 break-words text-[10px] leading-relaxed text-slate-500">
              {check.detail}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function VerificationResult({ report }: { report: VerificationReport }) {
  return (
    <div className="space-y-3">
      <div
        className={`rounded border px-3 py-2 ${
          report.valid
            ? "border-emerald-500/30 bg-emerald-500/10"
            : "border-rose-500/30 bg-rose-500/10"
        }`}
      >
        <p className={`text-sm font-semibold ${report.valid ? "text-emerald-300" : "text-rose-300"}`}>
          {report.valid ? "✓ CREDENTIAL VALID" : "✕ CREDENTIAL INVALID"}
        </p>
        <p className="mono mt-0.5 text-[11px] text-slate-400">{report.reason}</p>
      </div>
      <CheckList checks={report.check_details} />
      <p className="mono text-[10px] text-slate-600">
        verified at {report.verified_at}
      </p>
    </div>
  );
}
