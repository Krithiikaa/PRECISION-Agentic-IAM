# Security policy

PRECISION is a proof of concept for agentic identity and access management.
It is **not production-ready** and has **not been independently reviewed**
(see `docs/PHASE_12_FINAL_REPORT.md`, "External dependencies").

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, using GitHub's
*Report a vulnerability* (private security advisory) on this repository. Do
not open a public issue, and do not include real personal or banking data —
this system holds synthetic data only.

Useful in a report: the affected component and file, the request or sequence
that triggers it, what you expected the control to do and what it did.

## What to expect

- Acknowledgement and triage by the repository maintainers.
- A fix with a regression test, and a note in the phase documentation naming
  the defect, as every fixed defect in this project has.

**Not yet established:** a named security owner, response-time commitments
and a coordinated-disclosure timeline. Those require an organisational owner
and are tracked as PARTIAL (R-240) in `docs/REQUIREMENTS_TRACEABILITY.md`.

## Scope

In scope: the IAM API, the ANS, agent runtimes, Rego policies, the
operations console and the scripts in this repository.

Out of scope: the simulated banking adapters' business logic (they are
labelled `simulated: true` and are not real checks), and denial-of-service
against a single development host.

## Secrets

`.env`, `backend/.keystore/` and `backend/.keystore-agents/` are gitignored
and must never be committed. The only published secret-shaped value is the
development `KEYSTORE_MASTER_KEY` default, which `ENV=production` refuses.
